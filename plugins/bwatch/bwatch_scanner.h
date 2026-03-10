#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H

#include "config.h"
#include "bwatch.h"

/* Process all transactions in a block against watches */
void bwatch_process_block_txs(struct command *cmd,
			      struct bwatch *bwatch,
			      const struct bitcoin_block *block,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      const struct watch *w);

/* Check scid watches for a block (async - spawns getutxout requests) */
void bwatch_check_scid_watches(struct command *cmd,
			       struct bwatch *bwatch,
			       const struct bitcoin_block *block,
			       u32 blockheight,
			       const struct watch *w);

/* Fire depth notifications for all blockdepth watches at new_height.
 * Call after every new block and after every reorg tip removal. */
void bwatch_check_blockdepth_watches(struct command *cmd,
				     struct bwatch *bwatch,
				     u32 new_height);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H */
