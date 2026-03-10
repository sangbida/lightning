#include "config.h"
#include "bwatch.h"
#include "bwatch_interface.h"
#include "bwatch_store.h"
#include <bitcoin/tx.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <plugins/bwatch/bwatch_wiregen.h>
#include <plugins/libplugin.h>

/*
 * ============================================================================
 * SENDING WATCH_FOUND NOTIFICATIONS	
 * ============================================================================
 */

/* Callback for watch_found RPC.
 * watch_found notifications are sent on an aux command so they cannot
 * interfere with the poll command lifetime. */
static struct command_result *watch_found_done(struct command *cmd,
					       const char *method UNUSED,
					       const char *buf UNUSED,
					       const jsmntok_t *result UNUSED,
					       void *arg UNUSED)
{
	return aux_command_done(cmd);
}

/* Send watch_found notification to lightningd
 * @txindex: position of tx in the block (0 = coinbase)
 * @outnum: for scriptpubkey watches, which output matched
 * @innum: for outpoint watches, which input matched
 */
void bwatch_send_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 index)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "watch_found",
				    watch_found_done, watch_found_done, NULL);
	json_add_tx(req->js, "tx", tx);
	json_add_u32(req->js, "blockheight", blockheight);
	json_add_u32(req->js, "txindex", txindex);
	if (index != UINT32_MAX)
		json_add_u32(req->js, "index", index);

	/* Add owners array */
	json_array_start(req->js, "owners");
	for (size_t i = 0; i < tal_count(w->owners); i++)
		json_add_string(req->js, NULL, w->owners[i]);
	json_array_end(req->js);

	send_outreq(req);
}

void bwatch_send_blockdepth_found(struct command *cmd,
				  const struct watch *w,
				  u32 depth,
				  u32 blockheight)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "watch_found",
				    watch_found_done, watch_found_done, NULL);
	json_add_u32(req->js, "blockheight", blockheight);
	json_add_u32(req->js, "depth", depth);

	json_array_start(req->js, "owners");
	for (size_t i = 0; i < tal_count(w->owners); i++)
		json_add_string(req->js, NULL, w->owners[i]);
	json_array_end(req->js);

	send_outreq(req);
}

void bwatch_send_watch_revert(struct command *cmd,
			      const char *owner,
			      u32 blockheight)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "watch_revert",
				    watch_found_done, watch_found_done, NULL);
	json_add_string(req->js, "owner", owner);
	json_add_u32(req->js, "blockheight", blockheight);
	send_outreq(req);
}

/*
 * ============================================================================
 * SENDING BLOCK_PROCESSED NOTIFICATION
 * ============================================================================
 */

/* Callback for block_processed acknowledgement from watchman.
 * Starts the next poll now that watchman's height is confirmed updated. */
static struct command_result *block_processed_ack(struct command *cmd,
					  const char *method UNUSED,
					  const char *buf,
					  const jsmntok_t *result,
					  void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	u32 acked_height;
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{blockheight:%}",
			JSON_SCAN(json_to_number, &acked_height));
	if (err)
		plugin_err(cmd->plugin, "block_processed ack '%.*s': %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result), err);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Received block_processed ack for height %u", acked_height);

	/* Watchman height is now confirmed updated — safe to poll for next block */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0),
					  bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Non-fatal error: watchman may not be ready; still reschedule poll */
static struct command_result *block_processed_err(struct command *cmd,
					  const char *method UNUSED,
					  const char *buf,
					  const jsmntok_t *result,
					  void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	plugin_log(cmd->plugin, LOG_DBG,
		   "block_processed RPC failed (watchman not ready?): %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));

	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0),
					  bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Send block_processed to watchman with just the blockheight.
 * Fee estimates are now polled independently by lightningd every 30s.
 * The next poll is started from block_processed_ack, ensuring watchman's
 * height is updated before we log "No block change". */
struct command_result *bwatch_send_block_processed(struct command *cmd)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "block_processed",
				    block_processed_ack, block_processed_err, NULL);
	json_add_u32(req->js, "blockheight", bwatch->current_height);
	json_add_string(req->js, "blockhash",
			fmt_bitcoin_blkid(tmpctx, &bwatch->current_blockhash));
	return send_outreq(req);
}

/* Notify watchman that a block was rolled back so it can update and persist
 * its tip. Fire-and-forget via aux_command — the poll timer doesn't depend
 * on the ack. Crash safety: if we crash before the ack, watchman's stale
 * height will be higher than bwatch's on restart, retriggering rollback. */
void bwatch_send_revert_block_processed(struct command *cmd, u32 new_height,
					const struct bitcoin_blkid *new_hash)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "revert_block_processed",
				    watch_found_done, watch_found_done, NULL);
	json_add_u32(req->js, "blockheight", new_height);
	json_add_string(req->js, "blockhash",
			fmt_bitcoin_blkid(tmpctx, new_hash));
	send_outreq(req);
}

/* --- chaininfo: send chain name, IBD status to watchman on init --- */

static struct command_result *chaininfo_ack(struct command *cmd,
					   const char *method UNUSED,
					   const char *buf UNUSED,
					   const jsmntok_t *result UNUSED,
					   void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0), bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

static struct command_result *chaininfo_err(struct command *cmd,
					   const char *method UNUSED,
					   const char *buf,
					   const jsmntok_t *result,
					   void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	plugin_log(cmd->plugin, LOG_DBG,
		   "chaininfo RPC failed: %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0), bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

static struct command_result *chaininfo_getchaininfo_done(struct command *cmd,
							 const char *method UNUSED,
							 const char *buf,
							 const jsmntok_t *result,
							 void *unused UNUSED)
{
	struct out_req *req;
	const char *chain;
	u32 headercount, blockcount;
	bool ibd;
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{chain:%,headercount:%,blockcount:%,ibd:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &chain),
			JSON_SCAN(json_to_number, &headercount),
			JSON_SCAN(json_to_number, &blockcount),
			JSON_SCAN(json_to_bool, &ibd));
	if (err) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "getchaininfo parse failed: %s", err);
		return timer_complete(cmd);
	}

	req = jsonrpc_request_start(cmd, "chaininfo",
				    chaininfo_ack, chaininfo_err, NULL);
	json_add_string(req->js, "chain", chain);
	json_add_u32(req->js, "headercount", headercount);
	json_add_u32(req->js, "blockcount", blockcount);
	json_add_bool(req->js, "ibd", ibd);
	return send_outreq(req);
}

static struct command_result *chaininfo_getchaininfo_failed(struct command *cmd,
							   const char *method UNUSED,
							   const char *buf UNUSED,
							   const jsmntok_t *result UNUSED,
							   void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "getchaininfo failed during chaininfo init");
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0), bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

struct command_result *bwatch_send_chaininfo(struct command *cmd, void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "getchaininfo",
				    chaininfo_getchaininfo_done,
				    chaininfo_getchaininfo_failed,
				    NULL);
	json_add_u32(req->js, "last_height", bwatch->current_height);
	return send_outreq(req);
}

/*
 * ============================================================================
 * RPC COMMAND HANDLERS
 * ============================================================================
 */

/* Common helper: add a watch and trigger rescan if behind current height. */
static struct command_result *add_watch_and_maybe_rescan(struct command *cmd,
							 struct bwatch *bwatch,
							 struct watch *w,
							 u32 scan_start)
{
	if (w && bwatch->current_height > 0 && scan_start <= bwatch->current_height) {
		bwatch_start_rescan(cmd, w, scan_start, bwatch->current_height);
		return command_still_pending(cmd);
	}
	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

struct command_result *json_bwatch_add_scriptpubkey(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	u8 *scriptpubkey;
	u32 *start_block;
	struct watch *w;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("scriptpubkey", param_bin_from_hex, &scriptpubkey),
			 p_req("start_block", param_u32, &start_block),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	w = bwatch_add_watch(cmd, bwatch, WATCH_SCRIPTPUBKEY,
			     NULL, scriptpubkey, NULL, NULL,
			     *start_block, owner);
	return add_watch_and_maybe_rescan(cmd, bwatch, w, *start_block);
}

struct command_result *json_bwatch_add_outpoint(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	struct bitcoin_outpoint *outpoint;
	u32 *start_block;
	struct watch *w;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("outpoint", param_outpoint, &outpoint),
			 p_req("start_block", param_u32, &start_block),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	w = bwatch_add_watch(cmd, bwatch, WATCH_OUTPOINT,
			     outpoint, NULL, NULL, NULL,
			     *start_block, owner);
	return add_watch_and_maybe_rescan(cmd, bwatch, w, *start_block);
}

struct command_result *json_bwatch_add_scid(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	struct short_channel_id *scid;
	u32 *start_block;
	struct watch *w;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("scid", param_short_channel_id, &scid),
			 p_req("start_block", param_u32, &start_block),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	w = bwatch_add_watch(cmd, bwatch, WATCH_SCID,
			     NULL, NULL, scid, NULL,
			     *start_block, owner);
	return add_watch_and_maybe_rescan(cmd, bwatch, w, *start_block);
}

struct command_result *json_bwatch_add_blockdepth(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	u32 *start_block;
	struct watch *w;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("start_block", param_u32, &start_block),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	w = bwatch_add_watch(cmd, bwatch, WATCH_BLOCKDEPTH,
			     NULL, NULL, NULL, start_block,
			     *start_block, owner);
	return add_watch_and_maybe_rescan(cmd, bwatch, w, *start_block);
}

struct command_result *json_bwatch_del_scriptpubkey(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	u8 *scriptpubkey;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("scriptpubkey", param_bin_from_hex, &scriptpubkey),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	bwatch_del_watch(cmd, bwatch, WATCH_SCRIPTPUBKEY,
			 NULL, scriptpubkey, NULL, NULL, owner);
	return command_success(cmd, json_out_obj(cmd, "removed", "true"));
}

struct command_result *json_bwatch_del_outpoint(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	struct bitcoin_outpoint *outpoint;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("outpoint", param_outpoint, &outpoint),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	bwatch_del_watch(cmd, bwatch, WATCH_OUTPOINT,
			 outpoint, NULL, NULL, NULL, owner);
	return command_success(cmd, json_out_obj(cmd, "removed", "true"));
}

struct command_result *json_bwatch_del_scid(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	struct short_channel_id *scid;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("scid", param_short_channel_id, &scid),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	bwatch_del_watch(cmd, bwatch, WATCH_SCID,
			 NULL, NULL, scid, NULL, owner);
	return command_success(cmd, json_out_obj(cmd, "removed", "true"));
}

struct command_result *json_bwatch_del_blockdepth(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	u32 *start_block;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("start_block", param_u32, &start_block),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	bwatch_del_watch(cmd, bwatch, WATCH_BLOCKDEPTH,
			 NULL, NULL, NULL, start_block, owner);
	return command_success(cmd, json_out_obj(cmd, "removed", "true"));
}


/* Helper to output common watch fields */
static void json_out_watch_common(struct json_out *jout,
				  enum watch_type type,
				  u32 start_block,
				  wirestring **owners)
{
	json_out_addstr(jout, "type", bwatch_get_watch_type_name(type));
	json_out_add(jout, "start_block", false, "%u", start_block);
	json_out_start(jout, "owners", '[');
	for (size_t i = 0; i < tal_count(owners); i++)
		json_out_addstr(jout, NULL, owners[i]);
	json_out_end(jout, ']');
}

/* RPC command: listwatch */
struct command_result *json_bwatch_list(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct json_out *jout;
	struct watch *w;
	struct scriptpubkey_watches_iter sit;
	struct outpoint_watches_iter oit;
	struct scid_watches_iter scit;
	struct blockdepth_watches_iter bdit;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	jout = json_out_new(cmd);
	json_out_start(jout, NULL, '{');
	json_out_start(jout, "watches", '[');

	w = scriptpubkey_watches_first(bwatch->scriptpubkey_watches, &sit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "scriptpubkey",
				tal_hexstr(tmpctx, w->key.scriptpubkey.script, w->key.scriptpubkey.len));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = scriptpubkey_watches_next(bwatch->scriptpubkey_watches, &sit);
	}

	w = outpoint_watches_first(bwatch->outpoint_watches, &oit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "outpoint", fmt_bitcoin_outpoint(tmpctx, &w->key.outpoint));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = outpoint_watches_next(bwatch->outpoint_watches, &oit);
	}

	w = scid_watches_first(bwatch->scid_watches, &scit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_add(jout, "blockheight", false, "%u", short_channel_id_blocknum(w->key.scid));
		json_out_add(jout, "txindex", false, "%u", short_channel_id_txnum(w->key.scid));
		json_out_add(jout, "outnum", false, "%u", short_channel_id_outnum(w->key.scid));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = scid_watches_next(bwatch->scid_watches, &scit);
	}

	w = blockdepth_watches_first(bwatch->blockdepth_watches, &bdit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_add(jout, "blockdepth", false, "%u", w->start_block);
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = blockdepth_watches_next(bwatch->blockdepth_watches, &bdit);
	}

	json_out_end(jout, ']');
	json_out_end(jout, '}');
	return command_success(cmd, jout);
}


/*
 * ============================================================================
 * WATCHMAN SYNCHRONIZATION
 * ============================================================================
 */

/* Called when getwatchmanheight fails (watchman not ready, method missing, etc.).
 * Retry until watchman is up — bwatch must not start polling before watchman is ready,
 * otherwise block_processed notifications will arrive before watchman can handle them. */
static struct command_result *getwatchmanheight_failed(struct command *cmd,
						       const char *method UNUSED,
						       const char *buf UNUSED,
						       const jsmntok_t *result UNUSED,
						       void *unused UNUSED)
{
	plugin_log(cmd->plugin, LOG_DBG,
		   "getwatchmanheight failed (watchman not ready?), retrying in 500ms");
	global_timer(cmd->plugin, time_from_msec(500), bwatch_sync_with_watchman, NULL);
	return timer_complete(cmd);
}

/* Handle getwatchmanheight response - sync with watchman's last processed height */
static struct command_result *getwatchmanheight_done(struct command *cmd,
						     const char *method UNUSED,
						     const char *buf,
						     const jsmntok_t *result,
						     void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	u32 watchman_height;
	const jsmntok_t *height_tok;

	/* Parse the response */
	height_tok = json_get_member(buf, result, "height");
	if (!height_tok || !json_to_u32(buf, height_tok, &watchman_height)) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Could not parse getwatchmanheight response, starting poll from height %u",
			   bwatch->current_height);
		watchman_height = bwatch->current_height;
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "Watchman reports height %u, bwatch has height %u",
		   watchman_height, bwatch->current_height);

	/* Roll back to watchman's height if we're ahead */
	if (bwatch->current_height > watchman_height) {
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Rolling back from %u to watchman height %u",
			   bwatch->current_height, watchman_height);
		while (bwatch->current_height > watchman_height)
			bwatch_remove_tip(cmd, bwatch);
	}

	plugin_log(cmd->plugin, LOG_INFORM,
		   "bwatch initialized at height %u with %zu blocks, polling every %u ms",
		   bwatch->current_height, tal_count(bwatch->block_history),
		   bwatch->poll_interval_ms);

	/* Send chaininfo to set bitcoind->synced; poll timer starts after chaininfo completes */
	return bwatch_send_chaininfo(cmd, NULL);
}

/* Timer callback to sync with watchman before starting normal polling */
struct command_result *bwatch_sync_with_watchman(struct command *cmd, void *unused UNUSED)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getwatchmanheight",
						    getwatchmanheight_done,
						    getwatchmanheight_failed,
						    NULL);
	return send_outreq(req);
}
