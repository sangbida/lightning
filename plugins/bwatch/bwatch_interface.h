#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H

#include "config.h"
#include "bwatch.h"

/* Send watch_found notification to lightningd */
void bwatch_send_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 index);

/* Send blockdepth depth notification to lightningd (no tx, just depth + height) */
void bwatch_send_blockdepth_found(struct command *cmd,
				  const struct watch *w,
				  u32 depth,
				  u32 blockheight);

void bwatch_send_watch_revert(struct command *cmd,
			      const char *owner,
			      u32 blockheight);


/* Send block_processed notification to watchman (fetches feerates first) */

/* Send chaininfo (chain name, IBD status, sync) to watchman; timer callback */
struct command_result *bwatch_send_chaininfo(struct command *cmd, void *unused UNUSED);

/* Send block_processed to watchman; starts next poll from ack callback */
struct command_result *bwatch_send_block_processed(struct command *cmd);

/* Notify watchman that a block was rolled back; updates its persisted tip */
void bwatch_send_revert_block_processed(struct command *cmd, u32 new_height,
					const struct bitcoin_blkid *new_hash);

/* Sync with watchman height on startup */
struct command_result *bwatch_sync_with_watchman(struct command *cmd, void *unused);

/* RPC command handlers (called by plugin_main) */
struct command_result *json_bwatch_add_scriptpubkey(struct command *cmd, const char *buffer, const jsmntok_t *params);
struct command_result *json_bwatch_add_outpoint(struct command *cmd, const char *buffer, const jsmntok_t *params);
struct command_result *json_bwatch_add_scid(struct command *cmd, const char *buffer, const jsmntok_t *params);
struct command_result *json_bwatch_add_blockdepth(struct command *cmd, const char *buffer, const jsmntok_t *params);

struct command_result *json_bwatch_del_scriptpubkey(struct command *cmd, const char *buffer, const jsmntok_t *params);
struct command_result *json_bwatch_del_outpoint(struct command *cmd, const char *buffer, const jsmntok_t *params);
struct command_result *json_bwatch_del_scid(struct command *cmd, const char *buffer, const jsmntok_t *params);
struct command_result *json_bwatch_del_blockdepth(struct command *cmd, const char *buffer, const jsmntok_t *params);

struct command_result *json_bwatch_list(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params);


#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H */
