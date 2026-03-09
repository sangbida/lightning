#ifndef LIGHTNING_LIGHTNINGD_WATCHMAN_H
#define LIGHTNING_LIGHTNINGD_WATCHMAN_H

#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/tal/str/str.h>
#include <lightningd/feerate.h>

struct lightningd;
struct bitcoin_tx;
struct pending_op;

#define FEE_HISTORY_NUM 3

struct watchman {
	struct lightningd *ld;
	u32 last_processed_height;
	struct bitcoin_blkid last_processed_hash;
	struct pending_op **pending_ops;

	/* Feerate estimation state (updated per-block via block_processed) */
	u32 feerate_floor;
	struct feerate_est *feerates[FEE_HISTORY_NUM];
	struct feerate_est *smoothed_feerates;
};

/**
 * watch_found_fn - Handler for watch_found notifications
 * @ld: lightningd instance
 * @suffix: the owner string after the prefix (e.g. "42" for wallet/p2wpkh/42,
 *          or "100x1x0" for gossip/100x1x0); the handler is responsible for
 *          parsing whatever identifier it stored in that suffix
 * @tx: the transaction that matched
 * @outnum: which output matched (for scriptpubkey watches) or input for outpoint watches
 * @blockheight: the block height where tx was found
 * @txindex: position of tx in block (0 = coinbase)
 *
 * Called when bwatch detects a watched item in a block.
 */
typedef void (*watch_found_fn)(struct lightningd *ld,
			       const char *suffix,
			       const struct bitcoin_tx *tx,
			       size_t outnum,
			       u32 blockheight,
			       u32 txindex);

typedef void (*watch_revert_fn)(struct lightningd *ld,
				const char *suffix,
				u32 blockheight);

/**
 * watchman_new - Create and initialize a new watchman instance
 * @ctx: tal context to allocate from
 * @ld: lightningd instance
 *
 * Returns a new watchman instance, loading pending operations from datastore.
 */
struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld);

/**
 * watchman_add - Add a watch via raw JSON params
 * @ld: lightningd instance
 * @owner: the owner identifier (e.g., "wallet/p2wpkh/42")
 * @json_params: the raw JSON params string to send to bwatch
 *
 * Adds a watch to the pending queue and sends it to bwatch.
 * If a conflicting delete is pending, it will be canceled.
 */
void watchman_add(struct lightningd *ld,
		  const char *owner,
		  const char *json_params);

/**
 * watchman_del - Remove a watch via raw JSON params
 * @ld: lightningd instance
 * @owner: the owner identifier
 * @json_params: the raw JSON params string to send to bwatch
 *
 * Removes a watch by adding a delete operation to the pending queue.
 * If a conflicting add is pending, it will be canceled instead.
 */
void watchman_del(struct lightningd *ld,
		  const char *owner,
		  const char *json_params);

/**
 * watchman_ack - Acknowledge a completed watch operation
 * @ld: lightningd instance
 * @op_id: the operation ID that was acknowledged
 *
 * Called when bwatch acknowledges a watch operation.
 */
void watchman_ack(struct lightningd *ld, const char *op_id);

/**
 * watchman_replay_pending - Replay all pending operations
 * @ld: lightningd instance
 *
 * Resends all pending watch operations to bwatch.
 * Call this when bwatch is ready (e.g., on startup).
 */
void watchman_replay_pending(struct lightningd *ld);

/* Typed watch helpers — prefer these over calling watchman_add/del directly. */

/** Register a WATCH_SCRIPTPUBKEY — fires channel_funding_watch_found when seen. */
void watchman_watch_scriptpubkey(struct lightningd *ld,
				 const char *owner,
				 const u8 *scriptpubkey,
				 size_t script_len,
				 u32 start_block);

/** Register a WATCH_OUTPOINT — fires when the outpoint is spent. */
void watchman_watch_outpoint(struct lightningd *ld,
			     const char *owner,
			     const struct bitcoin_outpoint *outpoint,
			     u32 start_block);

/** Remove a WATCH_OUTPOINT (e.g. during splice before re-adding for new outpoint). */
void watchman_unwatch_outpoint(struct lightningd *ld,
			       const char *owner,
			       const struct bitcoin_outpoint *outpoint);

/** Register a WATCH_TXID — fires when a tx with that txid is confirmed.
 *  outnum and innum will both be UINT32_MAX in the handler. */
void watchman_watch_txid(struct lightningd *ld,
			 const char *owner,
			 const struct bitcoin_txid *txid,
			 u32 start_block);

/** Remove a WATCH_TXID. */
void watchman_unwatch_txid(struct lightningd *ld,
			   const char *owner,
			   const struct bitcoin_txid *txid);

/** Register a WATCH_SCID — fires when bwatch finds the output (for gossip get_txout). */
void watchman_watch_scid(struct lightningd *ld,
			 const char *owner,
			 const struct short_channel_id *scid,
			 u32 start_block);

/** Remove a WATCH_SCID. */
void watchman_unwatch_scid(struct lightningd *ld,
			   const char *owner,
			   const struct short_channel_id *scid);

/* Get highest block number (from bwatch). */
u32 get_block_height(struct lightningd *ld);

/*
 * Owner string constructors.
 *
 * Always use these instead of raw tal_fmt() to build owner strings.
 * Using a single constructor for both watchman_add and watchman_del
 * guarantees the strings are identical and the del can never silently fail
 * due to a format mismatch (e.g. %u vs PRIu64).
 */

/* wallet/ owners */
static inline const char *owner_wallet_p2wpkh(const tal_t *ctx, u64 keyidx)
{ return tal_fmt(ctx, "wallet/p2wpkh/%"PRIu64, keyidx); }

static inline const char *owner_wallet_p2tr(const tal_t *ctx, u64 keyidx)
{ return tal_fmt(ctx, "wallet/p2tr/%"PRIu64, keyidx); }

static inline const char *owner_wallet_p2sh_p2wpkh(const tal_t *ctx, u64 keyidx)
{ return tal_fmt(ctx, "wallet/p2sh_p2wpkh/%"PRIu64, keyidx); }

static inline const char *owner_wallet_utxo(const tal_t *ctx,
					     const struct bitcoin_outpoint *op)
{ return tal_fmt(ctx, "wallet/utxo/%s", fmt_bitcoin_outpoint(ctx, op)); }

/* channel/ owners */
static inline const char *owner_channel_funding(const tal_t *ctx, u64 dbid)
{ return tal_fmt(ctx, "channel/funding/%"PRIu64, dbid); }

static inline const char *owner_channel_funding_spent(const tal_t *ctx, u64 dbid)
{ return tal_fmt(ctx, "channel/funding_spent/%"PRIu64, dbid); }

static inline const char *owner_channel_wrong_funding_spent(const tal_t *ctx, u64 dbid)
{ return tal_fmt(ctx, "channel/wrong_funding_spent/%"PRIu64, dbid); }

static inline const char *owner_channel_rogue_inflight(const tal_t *ctx, u64 dbid)
{ return tal_fmt(ctx, "channel/rogue_inflight/%"PRIu64, dbid); }

/* onchaind/ owners */
static inline const char *owner_onchaind_txid(const tal_t *ctx, u64 dbid)
{ return tal_fmt(ctx, "onchaind/txid/%"PRIu64, dbid); }

static inline const char *owner_onchaind_outpoint(const tal_t *ctx, u64 dbid)
{ return tal_fmt(ctx, "onchaind/outpoint/%"PRIu64, dbid); }

/* gossip/ owners */
static inline const char *owner_gossip_scid(const tal_t *ctx,
					     struct short_channel_id scid)
{ return tal_fmt(ctx, "gossip/%s", fmt_short_channel_id(ctx, scid)); }

#endif /* LIGHTNING_LIGHTNINGD_WATCHMAN_H */
