#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <lightningd/lightningd.h>

struct channel;
struct bitcoin_tx;

void onchaind_funding_spent(struct channel *channel,
			    const struct bitcoin_tx *tx,
			    u32 blockheight);

void onchaind_restart_closed_channels(struct lightningd *ld);

/** bwatch handler: "onchaind/txid/<dbid>" — txid confirmed, send depth to onchaind. */
void onchaind_tx_watch_found(struct lightningd *ld,
			     const char *suffix,
			     const struct bitcoin_tx *tx,
			     size_t outnum,
			     u32 blockheight,
			     u32 txindex);

/** bwatch handler: "onchaind/outpoint/<dbid>" — output spent, notify onchaind. */
void onchaind_output_watch_found(struct lightningd *ld,
				 const char *suffix,
				 const struct bitcoin_tx *tx,
				 size_t innum,
				 u32 blockheight,
				 u32 txindex);

/** Send current confirmation depths for all onchaind-tracked txs (per block). */
void onchaind_send_depth_updates(struct channel *channel, u32 blockheight);

/** bwatch depth handler: "onchaind/csv/<dbid>" — fires each block with CSV-locked output depth. */
void onchaind_csv_depth_found(struct lightningd *ld,
			      const char *suffix,
			      u32 depth,
			      u32 blockheight);

/** bwatch revert handler: "onchaind/csv/<dbid>" — confirming block reorged away. */
void onchaind_csv_depth_revert(struct lightningd *ld,
			       const char *suffix,
			       u32 blockheight);

/** bwatch depth handler: "onchaind/htlc_depth/<dbid>" — fires each block with HTLC output depth. */
void onchaind_htlc_depth_found(struct lightningd *ld,
			       const char *suffix,
			       u32 depth,
			       u32 blockheight);

/** bwatch revert handler: "onchaind/htlc_depth/<dbid>" — confirming block reorged away. */
void onchaind_htlc_depth_revert(struct lightningd *ld,
				const char *suffix,
				u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
