#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_H

#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/* Forward declare hash table types (defined in bwatch_store.h) */
struct scriptpubkey_watches;
struct outpoint_watches;
struct scid_watches;
struct blockdepth_watches;

/* Watch type enumeration */
enum watch_type {
	WATCH_SCRIPTPUBKEY,
	WATCH_OUTPOINT,
	WATCH_SCID,
	WATCH_BLOCKDEPTH,
};

/* Scriptpubkey wrapper for easier handling */
struct scriptpubkey {
	const u8 *script;
	size_t len;
};

/* Watch structure */
struct watch {
	enum watch_type type;
	u32 start_block;  /* Block height to start watching from */
	wirestring **owners;  /* tal_arr of owner identifiers */
	union {
		struct scriptpubkey scriptpubkey;
		struct bitcoin_outpoint outpoint;
		struct short_channel_id scid;
	} key;
};

/* Main bwatch state */
struct bwatch {
	struct plugin *plugin;
	u32 current_height;
	struct bitcoin_blkid current_blockhash;
	struct block_record_wire **block_history;	/* Oldest first, most recent last */

	/* Watch hash tables (opaque pointers, defined in bwatch_store.h) */
	struct scriptpubkey_watches *scriptpubkey_watches;
	struct outpoint_watches *outpoint_watches;
	struct scid_watches *scid_watches;
	struct blockdepth_watches *blockdepth_watches;

	/* Polling */
	u32 poll_interval_ms;  
	struct plugin_timer *poll_timer;
	
	bool initial_fees_sent;	/* one-shot startup estimate before first block */
	u32 tip_height;		/* latest chain tip from getchaininfo; fee estimates
				 * are suppressed for catch-up blocks below this */
};

/* Rescan state for catching up on historical blocks */
struct rescan_state {
	const struct watch *watch;	/* NULL = rescan all watches, non-NULL = single watch */
	u32 current_block;		/* Next block to fetch */
	u32 target_block;		/* Stop after this block */
};

/* Helper to get bwatch from plugin */
struct bwatch *bwatch_of(struct plugin *plugin);

/* Forward declaration for rescan (implemented in bwatch.c, called from bwatch_interface.c) */
void bwatch_start_rescan(struct command *cmd,
			 const struct watch *w,
			 u32 start_block,
			 u32 target_block);

/* Forward declarations for block processing (exposed for bwatch_interface.c) */
struct command_result *bwatch_poll_chain(struct command *cmd, void *unused);
void bwatch_remove_tip(struct command *cmd, struct bwatch *bwatch);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_H */
