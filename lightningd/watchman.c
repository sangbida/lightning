#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <db/exec.h>
#include <ccan/json_out/json_out.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/autodata.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <common/jsonrpc_io.h>
#include <common/timeout.h>
#include <lightningd/bitcoind.h>
#include <lightningd/broadcast.h>
#include <lightningd/channel.h>
#include <lightningd/feerate.h>
#include <lightningd/gossip_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <lightningd/onchain_control.h>
#include <lightningd/peer_control.h>
#include <ccan/io/io.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/plugin.h>
#include <lightningd/watchman.h>
#include <wallet/wallet.h>

/*
 * Watchman is the interface between lightningd and the bwatch plugin.
 * It manages a pending operation queue to ensure reliable delivery of
 * watch add/delete requests to bwatch, even across crashes.
 *
 * Architecture:
 * - Subsystems (channel, onchaind, wallet) call watchman_add/watchman_del
 * - Watchman queues operations and sends them to bwatch via RPC
 * - Operations stay in queue until bwatch acknowledges them
 * - On crash/restart, pending ops are replayed from datastore
 * - Bwatch handles duplicate operations idempotently
 */

/* A pending operation - just the raw JSON params to send to bwatch */
struct pending_op {
	const char *op_id;       /* "add:{owner}" or "del:{owner}" */
	const char *json_params; /* The JSON params to send to bwatch */
};


/*
 * Datastore persistence helpers
 * Pending operations are stored at ["watchman", "pending", op_id]
 */

/* Generate datastore key for a pending operation */
static const char **make_key(const tal_t *ctx, const char *op_id)
{
	const char **key = tal_arr(ctx, const char *, 3);
	key[0] = "watchman";
	key[1] = "pending";
	key[2] = op_id;
	return key;
}


/* Persist a pending operation to the datastore for crash recovery */
static void db_save(struct watchman *wm, const struct pending_op *op)
{
	const char **key = make_key(tmpctx, op->op_id);
	u8 *data = tal_dup_arr(tmpctx, u8, (u8 *)op->json_params,
			       strlen(op->json_params) + 1, 0);
	if (wallet_datastore_get(tmpctx, wm->ld->wallet, key, NULL))
		wallet_datastore_update(wm->ld->wallet, key, data);
	else
		wallet_datastore_create(wm->ld->wallet, key, data);
}

/* Remove a pending operation from the datastore */
static void db_remove(struct watchman *wm, const char *op_id)
{
	const char **key = make_key(tmpctx, op_id);
	wallet_datastore_remove(wm->ld->wallet, key);
}

static void save_tip(struct watchman *wm)
{
	struct db *db = wm->ld->wallet->db;
	db_set_intvar(db, "last_watchman_block_height", wm->last_processed_height);
	db_set_blobvar(db, "last_watchman_block_hash",
		       (const u8 *)&wm->last_processed_hash,
		       sizeof(wm->last_processed_hash));
}

static void load_tip(struct watchman *wm)
{
	struct db *db = wm->ld->wallet->db;
	const u8 *blob;

	wm->last_processed_height = db_get_intvar(db, "last_watchman_block_height", 0);

	blob = db_get_blobvar(tmpctx, db, "last_watchman_block_hash");
	if (blob && tal_bytelen(blob) == sizeof(struct bitcoin_blkid))
		memcpy(&wm->last_processed_hash, blob, sizeof(wm->last_processed_hash));
}

/* Load all pending operations from datastore on startup */
static void load_pending_ops(struct watchman *wm)
{
	const char **startkey = tal_arr(tmpctx, const char *, 2);
	const char **key;
	const u8 *data;
	u64 generation;
	struct db_stmt *stmt;

	startkey[0] = "watchman";
	startkey[1] = "pending";

	for (stmt = wallet_datastore_first(tmpctx, wm->ld->wallet, startkey,
					   &key, &data, &generation);
	     stmt;
	     stmt = wallet_datastore_next(tmpctx, startkey, stmt,
					  &key, &data, &generation)) {
		if (tal_count(key) != 3)
			continue;

		struct pending_op *op = tal(wm, struct pending_op);
		op->op_id = tal_strdup(op, key[2]);
		op->json_params = tal_strdup(op, (const char *)data);
		tal_arr_expand(&wm->pending_ops, op);

		log_debug(wm->ld->log, "Loaded pending op: %s", op->op_id);
	}
}

static void watchman_on_plugin_ready(struct lightningd *ld, struct plugin *plugin);

struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld)
{
	struct watchman *wm = talz(ctx, struct watchman);

	wm->ld = ld;
	wm->pending_ops = tal_arr(wm, struct pending_op *, 0);

	load_pending_ops(wm);
	/* Load persisted tip (height + hash) from the SQL vars table. */
	load_tip(wm);

	log_info(ld->log, "Watchman: height=%u, %zu pending ops",
		 wm->last_processed_height, tal_count(wm->pending_ops));

	/* Replay pending ops exactly when bwatch transitions to INIT_COMPLETE. */
	ld->plugins->on_plugin_ready = watchman_on_plugin_ready;

	return wm;
}

/* Per-request context for bwatch_ack_response. Carries the bare op_id so the
 * callback never needs to parse the JSON-RPC response id. */
struct bwatch_ack_arg {
	struct watchman *wm;
	const char *op_id;	/* bare "add:owner", "del:owner", "addutxo:owner" */
};

/* Single response callback for bwatch operations (handles both success and error).
 * notify_cb is never called for RPC replies, so we only need response_cb. */
static void bwatch_ack_response(const char *buffer,
				const jsmntok_t *toks,
				const jsmntok_t *idtok UNUSED,
				struct bwatch_ack_arg *arg)
{
	const jsmntok_t *err = json_get_member(buffer, toks, "error");

	if (err) {
		log_unusual(arg->wm->ld->log, "bwatch operation %s failed: %.*s",
			    arg->op_id, json_tok_full_len(err), json_tok_full(buffer, err));
	} else {
		log_debug(arg->wm->ld->log, "Acknowledged pending op: %s", arg->op_id);
	}

	watchman_ack(arg->wm->ld, arg->op_id);
}

/* op_id is "add:owner", "del:owner", or "addutxo:owner"; return the owner suffix. */
static const char *owner_from_op_id(const char *op_id)
{
	const char *colon = strchr(op_id, ':');
	return colon ? colon + 1 : "";
}

/* Send an RPC request to the bwatch plugin.
 * op_id must include owner as suffix after colon: "add:owner", "del:owner", "addutxo:owner". */
static void send_to_bwatch(struct watchman *wm, const char *method,
			   const char *op_id, const char *json_params)
{
	struct plugin *bwatch;
	struct jsonrpc_request *req;
	const char *owner;
	size_t len;

	/* Find bwatch plugin by the command it registers */
	bwatch = find_plugin_for_command(wm->ld, method);
	if (!bwatch) {
		log_broken(wm->ld->log, "bwatch plugin not found, cannot send %s", method);
		return;
	}

	if (bwatch->plugin_state != INIT_COMPLETE) {
		log_debug(wm->ld->log, "bwatch plugin not ready (state %d), queuing %s %s",
			  bwatch->plugin_state, method, op_id);
		return;
	}

	struct bwatch_ack_arg *arg = tal(tmpctx, struct bwatch_ack_arg);
	arg->wm = wm;
	arg->op_id = tal_strdup(arg, op_id);

	req = jsonrpc_request_start(wm, method, op_id, bwatch->log,
				     NULL, bwatch_ack_response, arg);

	/* Parent arg to req so it's freed when the request is freed,
	 * regardless of whether the callback fires. */
	tal_steal(req, arg);

	owner = owner_from_op_id(op_id);
	if (!streq(owner, ""))
		json_add_string(req->stream, "owner", owner);

	/* json_params is a JSON object string like {"type":"...","scriptpubkey":"...","start_block":N}.
	 * Append the rest (skip outer braces) so we get type, scriptpubkey, start_block, etc. */
	len = strlen(json_params);
	if (len >= 2 && json_params[0] == '{' && json_params[len-1] == '}') {
		json_stream_append(req->stream, ",", 1);
		json_stream_append(req->stream, json_params + 1, len - 2);
	} else {
		json_stream_append(req->stream, ",", 1);
		json_stream_append(req->stream, json_params, len);
	}

	jsonrpc_request_end(req);
	plugin_request_send(bwatch, req);
}

/* Queue an operation, persist it for crash recovery, and send to bwatch. */
static void enqueue_op(struct watchman *wm, const char *method,
		       const char *op_id, const char *json_params)
{
	struct pending_op *op = tal(wm, struct pending_op);
	op->op_id = tal_strdup(op, op_id);
	op->json_params = tal_strdup(op, json_params);
	tal_arr_expand(&wm->pending_ops, op);
	db_save(wm, op);
	send_to_bwatch(wm, method, op_id, json_params);
}

/**
 * watchman_add - Queue an add watch operation
 *
 * Simply queues the operation and sends to bwatch.
 * Bwatch handles duplicate adds idempotently.
 */
void watchman_add(struct lightningd *ld, const char *owner, const char *json_params)
{
	struct watchman *wm = ld->watchman;
	char *op_id = tal_fmt(tmpctx, "add:%s", owner);

	/* Remove any existing add for this owner to avoid UNIQUE constraint
	 * when BIP32 and BIP86 both register the same key (e.g. wallet/p2wpkh/0) */
	watchman_ack(ld, op_id);

	enqueue_op(wm, "addwatch", op_id, json_params);
}

/**
 * watchman_del - Queue a delete watch operation
 *
 * Simply queues the operation and sends to bwatch.
 * Bwatch handles duplicate deletes idempotently.
 * Cancels any pending add for this owner.
 */
void watchman_del(struct lightningd *ld, const char *owner, const char *json_params)
{
	struct watchman *wm = ld->watchman;
	char *op_id = tal_fmt(tmpctx, "del:%s", owner);

	/* Cancel any pending add for this owner; we're replacing it with a del */
	watchman_ack(ld, tal_fmt(tmpctx, "add:%s", owner));

	enqueue_op(wm, "delwatch", op_id, json_params);
}

/**
 * watchman_ack - Acknowledge a completed watch operation
 *
 * Called when bwatch confirms it has processed an add/del/addutxo operation.
 * Removes the operation from the pending queue and datastore.
 * op_id must be the bare stored id (e.g. "add:wallet/p2wpkh/0"), not the
 * full JSON-RPC response id.
 */
void watchman_ack(struct lightningd *ld, const char *op_id)
{
	struct watchman *wm = ld->watchman;

	for (size_t i = 0; i < tal_count(wm->pending_ops); i++) {
		if (streq(wm->pending_ops[i]->op_id, op_id)) {
			db_remove(wm, op_id);
			tal_free(wm->pending_ops[i]);
			tal_arr_remove(&wm->pending_ops, i);
			return;
		}
	}
}

/**
 * watchman_replay_pending - Resend all pending operations to bwatch
 *
 * Called on startup after bwatch is ready, to ensure any operations
 * that were pending before a crash are sent to bwatch.
 */
void watchman_replay_pending(struct lightningd *ld)
{
	struct watchman *wm = ld->watchman;

	for (size_t i = 0; i < tal_count(wm->pending_ops); i++) {
		struct pending_op *op = wm->pending_ops[i];
		const char *method;
		if (strstarts(op->op_id, "add:"))
			method = "addwatch";
		else if (strstarts(op->op_id, "del:"))
			method = "delwatch";
		else if (strstarts(op->op_id, "addutxo:"))
			method = "addutxo";
		else {
			log_broken(wm->ld->log, "Unknown pending op type: %s", op->op_id);
			continue;
		}
		send_to_bwatch(wm, method, op->op_id, op->json_params);
	}
}

/* Called by plugin machinery when any plugin hits INIT_COMPLETE.
 * We use this to trigger pending-op replay the moment bwatch is truly ready. */
static void watchman_on_plugin_ready(struct lightningd *ld, struct plugin *plugin)
{
	if (!ld->watchman)
		return;
	/* Check if this is bwatch by seeing if it owns the "addwatch" method. */
	if (find_plugin_for_command(ld, "addwatch") != plugin)
		return;
	log_debug(ld->log, "bwatch reached INIT_COMPLETE, replaying pending ops");
	watchman_replay_pending(ld);
}

u32 get_block_height(struct lightningd *ld)
{
	struct watchman *wm = ld->watchman;
	if (!wm)
		return 0;
	return wm->last_processed_height;
}

/* Context for sync lookupwatch RPC */
struct lookupwatch_ctx {
	struct lightningd *ld;
	const char *owner;  /* result, tal(ld) */
};

static void lookupwatch_cb(const char *buf, const jsmntok_t *toks,
			  const jsmntok_t *idtok UNUSED,
			  struct lookupwatch_ctx *ctx)
{
	const jsmntok_t *result_tok = json_get_member(buf, toks, "result");
	if (result_tok) {
		bool found;
		const jsmntok_t *found_tok = json_get_member(buf, result_tok, "found");
		if (found_tok && json_to_bool(buf, found_tok, &found) && found) {
			const jsmntok_t *owners_tok = json_get_member(buf, result_tok, "owners");
			if (owners_tok && owners_tok->type == JSMN_ARRAY && owners_tok->size > 0) {
				const jsmntok_t *owner_tok = owners_tok + 1;
				const char *owner = json_strdup(tmpctx, buf, owner_tok);
				if (owner && strstarts(owner, "wallet/"))
					ctx->owner = tal_strdup(ctx->ld, owner);
			}
		}
	}
	io_break(ctx->ld);
}

const char *watchman_lookup_scriptpubkey(struct lightningd *ld,
					 const u8 *script,
					 size_t script_len)
{
	struct plugin *bwatch;
	struct jsonrpc_request *req;
	struct lookupwatch_ctx ctx = { .ld = ld, .owner = NULL };

	bwatch = find_plugin_for_command(ld, "lookupwatch");
	if (!bwatch || bwatch->plugin_state != INIT_COMPLETE)
		return NULL;

	req = jsonrpc_request_start(tmpctx, "lookupwatch", NULL,
				   bwatch->log, NULL, lookupwatch_cb, &ctx);
	json_add_hex(req->stream, "scriptpubkey", script, script_len);
	jsonrpc_request_end(req);
	plugin_request_send(bwatch, req);

	io_loop_with_timers(ld);
	return ctx.owner;
}

void watchman_watch_scriptpubkey(struct lightningd *ld,
				 const char *owner,
				 const u8 *scriptpubkey,
				 size_t script_len,
				 u32 start_block)
{
	watchman_add(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"scriptpubkey\""
			     ",\"scriptpubkey\":\"%s\""
			     ",\"start_block\":%u}",
			     tal_hexstr(tmpctx, scriptpubkey, script_len),
			     start_block));
}

void watchman_watch_outpoint(struct lightningd *ld,
			     const char *owner,
			     const struct bitcoin_outpoint *outpoint,
			     u32 start_block)
{
	watchman_add(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"outpoint\""
			     ",\"outpoint\":\"%s:%u\""
			     ",\"start_block\":%u}",
			     fmt_bitcoin_txid(tmpctx, &outpoint->txid),
			     outpoint->n,
			     start_block));
}

void watchman_unwatch_outpoint(struct lightningd *ld,
			       const char *owner,
			       const struct bitcoin_outpoint *outpoint)
{
	watchman_del(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"outpoint\""
			     ",\"outpoint\":\"%s:%u\"}",
			     fmt_bitcoin_txid(tmpctx, &outpoint->txid),
			     outpoint->n));
}

void watchman_watch_txid(struct lightningd *ld,
			 const char *owner,
			 const struct bitcoin_txid *txid,
			 u32 start_block)
{
	watchman_add(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"txid\""
			     ",\"txid\":\"%s\""
			     ",\"start_block\":%u}",
			     fmt_bitcoin_txid(tmpctx, txid),
			     start_block));
}

void watchman_unwatch_txid(struct lightningd *ld,
			   const char *owner,
			   const struct bitcoin_txid *txid)
{
	watchman_del(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"txid\""
			     ",\"txid\":\"%s\"}",
			     fmt_bitcoin_txid(tmpctx, txid)));
}

void watchman_watch_scid(struct lightningd *ld,
			 const char *owner,
			 const struct short_channel_id *scid,
			 u32 start_block)
{
	watchman_add(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"scid\""
			     ",\"scid\":\"%s\""
			     ",\"start_block\":%u}",
			     fmt_short_channel_id(tmpctx, *scid),
			     start_block));
}

void watchman_unwatch_scid(struct lightningd *ld,
			   const char *owner,
			   const struct short_channel_id *scid)
{
	watchman_del(ld, owner,
		     tal_fmt(tmpctx,
			     "{\"type\":\"scid\""
			     ",\"scid\":\"%s\"}",
			     fmt_short_channel_id(tmpctx, *scid)));
}

struct gettransaction_call {
	struct lightningd *ld;
	void (*cb)(struct bitcoin_tx *tx, u32 blockheight, void *arg);
	void *arg;
};

static void gettransaction_cb(const char *buf, const jsmntok_t *toks,
			      const jsmntok_t *idtok UNUSED,
			      struct gettransaction_call *call)
{
	const jsmntok_t *result_tok, *rawtx_tok;
	u8 *rawtx;
	const u8 *p;
	size_t len;
	u32 blockheight;
	struct bitcoin_tx *tx;

	result_tok = json_get_member(buf, toks, "result");
	if (!result_tok) {
		log_unusual(call->ld->log, "bwatch gettransaction failed");
		tal_free(call);
		return;
	}

	rawtx_tok = json_get_member(buf, result_tok, "rawtx");
	if (!rawtx_tok
	    || !(rawtx = json_tok_bin_from_hex(tmpctx, buf, rawtx_tok))) {
		log_unusual(call->ld->log, "bwatch gettransaction: bad rawtx");
		tal_free(call);
		return;
	}

	if (!json_scan(tmpctx, buf, result_tok, "{blockheight:%}",
		       JSON_SCAN(json_to_u32, &blockheight))) {
		log_unusual(call->ld->log,
			    "bwatch gettransaction: missing blockheight");
		tal_free(call);
		return;
	}

	p = rawtx;
	len = tal_bytelen(rawtx);
	tx = pull_bitcoin_tx(tmpctx, &p, &len);
	if (!tx) {
		log_unusual(call->ld->log,
			    "bwatch gettransaction: failed to parse rawtx");
		tal_free(call);
		return;
	}

	call->cb(tx, blockheight, call->arg);
	tal_free(call);
}

void watchman_get_transaction(struct lightningd *ld,
			      const struct bitcoin_txid *txid,
			      void (*cb)(struct bitcoin_tx *tx,
					 u32 blockheight,
					 void *arg),
			      void *arg)
{
	struct plugin *bwatch;
	struct jsonrpc_request *req;
	struct gettransaction_call *call;

	bwatch = find_plugin_for_command(ld, "gettransaction");
	if (!bwatch) {
		log_unusual(ld->log, "bwatch plugin not found, cannot get transaction");
		return;
	}
	if (bwatch->plugin_state != INIT_COMPLETE) {
		log_unusual(ld->log, "bwatch not ready, cannot get transaction");
		return;
	}

	call = tal(ld, struct gettransaction_call);
	call->ld = ld;
	call->cb = cb;
	call->arg = arg;

	req = jsonrpc_request_start(call, "gettransaction",
				    "gettransaction", bwatch->log,
				    NULL, gettransaction_cb, call);
	json_add_txid(req->stream, "txid", txid);
	jsonrpc_request_end(req);
	plugin_request_send(bwatch, req);
}

void watchman_add_utxo(struct lightningd *ld,
		       const struct bitcoin_outpoint *outpoint,
		       u32 blockheight, u32 txindex,
		       const u8 *script, size_t script_len,
		       struct amount_sat sat,
		       const char *owner)
{
	struct watchman *wm = ld->watchman;
	struct json_stream *js;
	size_t len;
	char *json_params;

	if (!wm)
		return;

	const char *op_id = tal_fmt(tmpctx, "addutxo:%s", owner);

	js = new_json_stream(tmpctx, NULL, NULL);
	json_object_start(js, NULL);
	json_add_outpoint(js, "outpoint", outpoint);
	json_add_u32(js, "blockheight", blockheight);
	json_add_u32(js, "txindex", txindex);
	json_add_hex(js, "scriptpubkey", script, script_len);
	json_add_u64(js, "satoshis", sat.satoshis);
	json_object_end(js);

	json_params = tal_strndup(tmpctx, json_out_contents(js->jout, &len), len);

	enqueue_op(wm, "addutxo", op_id, json_params);
}

/* Dispatch table - add new watch types here */
static void wallet_utxo_spent_watch_revert(struct lightningd *ld UNUSED,
					   const char *suffix UNUSED,
					   u32 blockheight UNUSED) {}
static void wallet_watch_p2wpkh_revert(struct lightningd *ld UNUSED,
				       const char *suffix UNUSED,
				       u32 blockheight UNUSED) {}
static void wallet_watch_p2tr_revert(struct lightningd *ld UNUSED,
				     const char *suffix UNUSED,
				     u32 blockheight UNUSED) {}
static void wallet_watch_p2sh_p2wpkh_revert(struct lightningd *ld UNUSED,
					    const char *suffix UNUSED,
					    u32 blockheight UNUSED) {}
static void channel_funding_watch_revert(struct lightningd *ld UNUSED,
					 const char *suffix UNUSED,
					 u32 blockheight UNUSED) {}
static void channel_funding_spent_watch_revert(struct lightningd *ld UNUSED,
					       const char *suffix UNUSED,
					       u32 blockheight UNUSED) {}
static void channel_wrong_funding_spent_watch_revert(struct lightningd *ld UNUSED,
						     const char *suffix UNUSED,
						     u32 blockheight UNUSED) {}
static void channel_rogue_inflight_watch_revert(struct lightningd *ld UNUSED,
						const char *suffix UNUSED,
						u32 blockheight UNUSED) {}
static void onchaind_tx_watch_revert(struct lightningd *ld UNUSED,
				     const char *suffix UNUSED,
				     u32 blockheight UNUSED) {}
static void onchaind_output_watch_revert(struct lightningd *ld UNUSED,
					 const char *suffix UNUSED,
					 u32 blockheight UNUSED) {}
static void gossip_scid_watch_revert(struct lightningd *ld UNUSED,
				     const char *suffix UNUSED,
				     u32 blockheight UNUSED) {}

static const struct watch_dispatch {
	const char *prefix;
	watch_found_fn handler;
	watch_revert_fn revert;
} watch_handlers[] = {
	/* wallet/utxo/<txid>:<outnum>: WATCH_OUTPOINT, fires when a wallet UTXO is spent */
	{ "wallet/utxo/",         wallet_utxo_spent_watch_found, wallet_utxo_spent_watch_revert },
	/* wallet/p2wpkh/<keyidx>: WATCH_SCRIPTPUBKEY, fires when a p2wpkh wallet address receives funds */
	{ "wallet/p2wpkh/",       wallet_watch_p2wpkh, wallet_watch_p2wpkh_revert },
	/* wallet/p2tr/<keyidx>: WATCH_SCRIPTPUBKEY, fires when a p2tr wallet address receives funds */
	{ "wallet/p2tr/",         wallet_watch_p2tr, wallet_watch_p2tr_revert },
	/* wallet/p2sh_p2wpkh/<keyidx>: WATCH_SCRIPTPUBKEY, fires when a p2sh-wrapped p2wpkh address receives funds */
	{ "wallet/p2sh_p2wpkh/",  wallet_watch_p2sh_p2wpkh, wallet_watch_p2sh_p2wpkh_revert },
	/* channel/funding/<dbid>: WATCH_SCRIPTPUBKEY, fires when funding tx confirmed */
	{ "channel/funding/",               channel_funding_watch_found, channel_funding_watch_revert },
	/* channel/funding_spent/<dbid>: WATCH_OUTPOINT, fires when funding outpoint spent */
	{ "channel/funding_spent/",         channel_funding_spent_watch_found, channel_funding_spent_watch_revert },
	/* channel/wrong_funding_spent/<dbid>: WATCH_OUTPOINT, fires when shutdown_wrong_funding outpoint spent */
	{ "channel/wrong_funding_spent/",   channel_wrong_funding_spent_watch_found, channel_wrong_funding_spent_watch_revert },
	/* channel/rogue_inflight/<dbid>: WATCH_TXID, fires when a non-primary inflight tx confirms */
	{ "channel/rogue_inflight/",        channel_rogue_inflight_watch_found, channel_rogue_inflight_watch_revert },
	/* onchaind/txid/<dbid>: WATCH_TXID, fires when any onchaind-tracked tx confirms */
	{ "onchaind/txid/",                   onchaind_tx_watch_found, onchaind_tx_watch_revert },
	/* onchaind/outpoint/<dbid>: WATCH_OUTPOINT, fires when any onchaind output is spent */
	{ "onchaind/outpoint/",               onchaind_output_watch_found, onchaind_output_watch_revert },
	/* gossip/<scid>: WATCH_SCID, fires when a channel announcement UTXO is confirmed */
	{ "gossip/",                          gossip_scid_watch_found, gossip_scid_watch_revert },
};

/**
 * dispatch_watch_found - Find and call the appropriate handler for an owner
 *
 * Matches the owner string against registered prefixes and dispatches to the
 * appropriate handler, passing the raw suffix (the part after the prefix).
 * Each handler is responsible for parsing its own identifier from the suffix.
 */
static void dispatch_watch_found(struct lightningd *ld,
				 const char *owner,
				 const struct bitcoin_tx *tx,
				 size_t outnum,
				 u32 blockheight,
				 u32 txindex)
{
	for (size_t i = 0; i < ARRAY_SIZE(watch_handlers); i++) {
		if (strstarts(owner, watch_handlers[i].prefix)) {
			const char *suffix = owner + strlen(watch_handlers[i].prefix);
			watch_handlers[i].handler(ld, suffix, tx, outnum,
						  blockheight, txindex);
			return;
		}
	}

	log_debug(ld->log, "No handler for watch owner: %s", owner);
}

static void dispatch_watch_revert(struct lightningd *ld,
				  const char *owner,
				  u32 blockheight)
{
	for (size_t i = 0; i < ARRAY_SIZE(watch_handlers); i++) {
		if (strstarts(owner, watch_handlers[i].prefix)) {
			const char *suffix = owner + strlen(watch_handlers[i].prefix);
			watch_handlers[i].revert(ld, suffix, blockheight);
			return;
		}
	}

	log_debug(ld->log, "No revert handler for watch owner: %s", owner);
}

static struct command_result *param_bitcoin_tx(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct bitcoin_tx **tx)
{
	*tx = bitcoin_tx_from_hex(cmd, buffer + tok->start, tok->end - tok->start);
	if (!*tx)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Expected a hex-encoded transaction");
	return NULL;
}

static struct command_result *param_bitcoin_blkid_cmd(struct command *cmd,
						      const char *name,
						      const char *buffer,
						      const jsmntok_t *tok,
						      struct bitcoin_blkid **blkid)
{
	*blkid = tal(cmd, struct bitcoin_blkid);
	if (!json_to_bitcoin_blkid(buffer, tok, *blkid))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Expected a blockhash");
	return NULL;
}

/**
 * json_watch_found - RPC handler for watch_found notifications from bwatch
 *
 * Called by bwatch when a watched transaction appears in a block.
 * The notification includes the tx, blockheight, txindex, list of owners, and
 * optionally outnum (for scriptpubkey watches) or innum (for outpoint watches).
 *
 * Dispatches to subsystem handlers based on owner prefix.
 */
static struct command_result *json_watch_found(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	const char **owners;
	u32 *blockheight, *txindex, *index;
	struct bitcoin_tx *tx;

	if (!param_check(cmd, buffer, params,
		   p_req("tx", param_bitcoin_tx, &tx),
		   p_req("blockheight", param_number, &blockheight),
		   p_req("txindex", param_number, &txindex),
		   p_req("owners", param_string_array, &owners),
		   p_opt("index", param_number, &index),
		   NULL))
		return command_param_failed();

	assert(wm);
	if (command_check_only(cmd))
		return command_check_done(cmd);

	log_info(cmd->ld->log, "watch_found at block %u", *blockheight);

	for (size_t i = 0; i < tal_count(owners); i++)
		dispatch_watch_found(cmd->ld, owners[i], tx,
				     index ? *index : 0,
				     *blockheight, *txindex);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

static struct command_result *json_watch_revert(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	const char *owner;
	u32 *blockheight;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("blockheight", param_number, &blockheight),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	dispatch_watch_revert(cmd->ld, owner, *blockheight);
	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

/**
 * json_revert_block_processed - RPC handler called by bwatch when it rolls
 * back a block during a reorg. Updates and persists watchman's tip so that
 * on restart the height/hash reflect the rolled-back state rather than the
 * disconnected block.
 */
static struct command_result *json_revert_block_processed(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *obj UNNEEDED,
							  const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	u32 *blockheight;
	struct bitcoin_blkid *blockhash;

	if (!param_check(cmd, buffer, params,
			 p_req("blockheight", param_number, &blockheight),
			 p_req("blockhash", param_bitcoin_blkid_cmd, &blockhash),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!wm)
		return command_fail(cmd, LIGHTNINGD, "Watchman not initialized");

	log_debug(wm->ld->log, "revert_block_processed: %u -> %u",
		  wm->last_processed_height, *blockheight);
	wm->last_processed_height = *blockheight;
	wm->last_processed_hash = *blockhash;
	save_tip(wm);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

/**
 * json_block_processed - RPC handler for block_processed notifications from bwatch
 *
 * Called by bwatch after it finishes processing all watches in a block.
 * We track this height to know where bwatch is in the chain, which helps
 * during startup/reorg scenarios.
 */
static struct command_result *json_block_processed(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	u32 *blockheight;
	struct bitcoin_blkid *blockhash;

	if (!param_check(cmd, buffer, params,
			 p_req("blockheight", param_number, &blockheight),
			 p_req("blockhash", param_bitcoin_blkid_cmd, &blockhash),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!wm)
		return command_fail(cmd, LIGHTNINGD, "Watchman not initialized");

	if (*blockheight != wm->last_processed_height) {
		log_debug(wm->ld->log, "block_processed: %u -> %u",
			  wm->last_processed_height, *blockheight);
		wm->last_processed_height = *blockheight;
		wm->last_processed_hash = *blockhash;
		save_tip(wm);
	}

	channel_block_processed(wm->ld, *blockheight);
	notify_new_block(wm->ld);
	rebroadcast_txs(wm->ld);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	if (wm->last_processed_height > 0)
		json_add_string(response, "blockhash",
				fmt_bitcoin_blkid(response, &wm->last_processed_hash));
	return command_success(cmd, response);
}

/**
 * json_getwatchmanheight - RPC handler to return watchman's last processed height
 *
 * Called by bwatch on startup to determine what height to rescan from.
 */
static struct command_result *json_getwatchmanheight(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	struct json_stream *response;
	u32 height;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	height = wm ? wm->last_processed_height : 0;
	log_debug(cmd->ld->log, "getwatchmanheight: returning height=%u (wm=%s)",
		  height, wm ? "ok" : "NULL");
	response = json_stream_success(cmd);
	json_add_u32(response, "height", height);
	if (wm && wm->last_processed_height > 0)
		json_add_string(response, "blockhash",
				fmt_bitcoin_blkid(response, &wm->last_processed_hash));
	return command_success(cmd, response);
}

static const struct json_command watch_found_command = {
	"watch_found",
	json_watch_found,
};
AUTODATA(json_command, &watch_found_command);

static const struct json_command watch_revert_command = {
	"watch_revert",
	json_watch_revert,
};
AUTODATA(json_command, &watch_revert_command);

static const struct json_command block_processed_command = {
	"block_processed",
	json_block_processed,
};
AUTODATA(json_command, &block_processed_command);

static const struct json_command revert_block_processed_command = {
	"revert_block_processed",
	json_revert_block_processed,
};
AUTODATA(json_command, &revert_block_processed_command);

static const struct json_command getwatchmanheight_command = {
	"getwatchmanheight",
	json_getwatchmanheight,
};
AUTODATA(json_command, &getwatchmanheight_command);

/**
 * json_chaininfo - RPC handler for chaininfo from bwatch
 *
 * Called by bwatch on startup to inform watchman about the chain name,
 * IBD status, and sync state. Validates we're on the right network and
 * sets bitcoind->synced accordingly.
 */
static struct command_result *json_chaininfo(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	const char *chain;
	u32 *headercount, *blockcount;
	bool *ibd;

	if (!param_check(cmd, buffer, params,
			 p_req("chain", param_string, &chain),
			 p_req("headercount", param_number, &headercount),
			 p_req("blockcount", param_number, &blockcount),
			 p_req("ibd", param_bool, &ibd),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!streq(chain, chainparams->bip70_name))
		fatal("Wrong network! Our Bitcoin backend is running on '%s',"
		      " but we expect '%s'.", chain, chainparams->bip70_name);

	if (*ibd) {
		log_unusual(cmd->ld->log,
			    "Waiting for initial block download"
			    " (this can take a while!)");
		cmd->ld->bitcoind->synced = false;
	} else if (*headercount != *blockcount) {
		log_unusual(cmd->ld->log,
			    "Waiting for bitcoind to catch up"
			    " (%u blocks of %u)",
			    *blockcount, *headercount);
		cmd->ld->bitcoind->synced = false;
	} else {
		cmd->ld->bitcoind->synced = true;
	}

	struct json_stream *response = json_stream_success(cmd);
	json_add_string(response, "chain", chain);
	json_add_bool(response, "synced", cmd->ld->bitcoind->synced);
	return command_success(cmd, response);
}

static const struct json_command chaininfo_command = {
	"chaininfo",
	json_chaininfo,
};
AUTODATA(json_command, &chaininfo_command);

/* --- Height, sync, and lifecycle functions (ex-chaintopology) --- */