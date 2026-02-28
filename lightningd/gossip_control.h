#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <lightningd/watchman.h>

struct bitcoin_tx;
struct channel;
struct lightningd;

void gossip_init(struct lightningd *ld, int connectd_fd);

void gossipd_notify_spends(struct lightningd *ld,
			   u32 blockheight,
			   const struct short_channel_id *scids);

void gossip_notify_new_block(struct lightningd *ld);

/**
 * gossip_notify_blockheight - Notify gossipd of a specific block height
 *
 * Used when bwatch processes a block; the authoritative height comes from
 * bwatch's block_processed, not chaintopology.
 */
void gossip_notify_blockheight(struct lightningd *ld, u32 blockheight);

/**
 * gossip_scid_watch_found - bwatch handler for gossip/ owner prefix.
 * Handles both SCID confirmation (get_txout_reply) and funding spend
 * (gossipd_notify_spends) based on whether blockheight matches the SCID.
 */
void gossip_scid_watch_found(struct lightningd *ld,
			     const char *suffix,
			     const struct bitcoin_tx *tx,
			     size_t outnum,
			     u32 blockheight,
			     u32 txindex);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H */
