#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/features.h>
#include <common/htlc_tx.h>
#include <common/json_command.h>
#include <common/timeout.h>
#include <lightningd/bitcoind.h>
#include <lightningd/channel_control.h>
#include <lightningd/feerate.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/notification.h>
#include <lightningd/watchman.h>
#include <math.h>


static u32 interp_feerate(const struct feerate_est *rates, u32 blockcount)
{
	const struct feerate_est *before = NULL, *after = NULL;

	const size_t num_feerates = tal_count(rates);
	for (size_t i = 0; i < num_feerates; i++) {
		if (rates[i].blockcount <= blockcount) {
			before = &rates[i];
		} else if (rates[i].blockcount > blockcount && !after) {
			after = &rates[i];
		}
	}
	if (!before && !after)
		return 0;
	if (!before && after)
		return after->rate;
	if (before && !after)
		return before->rate;

	if (before->rate < after->rate)
		return before->rate;

	return before->rate
		- ((u64)(blockcount - before->blockcount)
		   * (before->rate - after->rate)
		   / (after->blockcount - before->blockcount));
}

u32 feerate_for_deadline(struct lightningd *ld, u32 blockcount)
{
	struct watchman *wm = ld->watchman;
	u32 rate = interp_feerate(wm->feerates[0], blockcount);

	if (rate && rate < wm->feerate_floor)
		rate = wm->feerate_floor;
	return rate;
}

u32 smoothed_feerate_for_deadline(struct lightningd *ld, u32 blockcount)
{
	return interp_feerate(ld->watchman->smoothed_feerates, blockcount);
}

u32 feerate_for_target(struct lightningd *ld, u64 deadline)
{
	u64 blocks, blockheight;

	blockheight = get_block_height(ld);

	if (blockheight > deadline)
		return feerate_for_deadline(ld, 1);

	blocks = deadline - blockheight;

	if (blocks > 200)
		return FEERATE_FLOOR;
	if (blocks > 100)
		return get_feerate_floor(ld);

	return feerate_for_deadline(ld, blocks);
}

static void smooth_one_feerate(struct lightningd *ld,
			       struct feerate_est *rate)
{
	/* Feerates arrive once per block (~600s); smoothing weight reflects that. */
	double alpha = 1 - pow(0.1, 600.0 / 120);
	u32 old_feerate, feerate_smooth;

	old_feerate = smoothed_feerate_for_deadline(ld, rate->blockcount);
	assert(old_feerate);

	feerate_smooth = rate->rate * alpha + old_feerate * (1 - alpha);

	if (abs((int)rate->rate - (int)feerate_smooth) > (0.1 * rate->rate))
		rate->rate = feerate_smooth;

	if (rate->rate < get_feerate_floor(ld))
		rate->rate = get_feerate_floor(ld);

	if (rate->rate != feerate_smooth)
		log_debug(ld->log,
			  "Feerate estimate for %u blocks set to %u (was %u)",
			  rate->blockcount, rate->rate, feerate_smooth);
}

static bool feerates_differ(const struct feerate_est *a,
			    const struct feerate_est *b)
{
	const size_t num_feerates = tal_count(a);
	if (num_feerates != tal_count(b))
		return true;
	for (size_t i = 0; i < num_feerates; i++) {
		if (a[i].blockcount != b[i].blockcount)
			return true;
		if (a[i].rate != b[i].rate)
			return true;
	}
	return false;
}

static bool different_blockcounts(struct lightningd *ld,
				  const struct feerate_est *old,
				  const struct feerate_est *new)
{
	const size_t num_feerates = tal_count(old);
	if (num_feerates != tal_count(new)) {
		log_unusual(ld->log, "Presented with %zu feerates this time (was %zu!)",
			    tal_count(new), num_feerates);
		return true;
	}
	for (size_t i = 0; i < num_feerates; i++) {
		if (old[i].blockcount != new[i].blockcount) {
			log_unusual(ld->log, "Presented with feerates"
				    " for blockcount %u, previously %u",
				    new[i].blockcount, old[i].blockcount);
			return true;
		}
	}
	return false;
}

void update_feerates(struct lightningd *ld,
		     u32 feerate_floor,
		     const struct feerate_est *rates TAKES)
{
	struct watchman *wm = ld->watchman;
	struct feerate_est *new_smoothed;
	bool changed;

	wm->feerate_floor = feerate_floor;

	if (tal_count(rates) == 0)
		return;

	if (wm->feerates[0] && different_blockcounts(ld, wm->feerates[0], rates)) {
		for (size_t i = 0; i < ARRAY_SIZE(wm->feerates); i++)
			wm->feerates[i] = tal_free(wm->feerates[i]);
		wm->smoothed_feerates = tal_free(wm->smoothed_feerates);
	}

	tal_free(wm->feerates[FEE_HISTORY_NUM-1]);
	memmove(wm->feerates + 1, wm->feerates,
		sizeof(wm->feerates[0]) * (FEE_HISTORY_NUM-1));
	wm->feerates[0] = tal_dup_talarr(wm, struct feerate_est, rates);
	changed = feerates_differ(wm->feerates[0], wm->feerates[1]);

	new_smoothed = tal_dup_talarr(wm, struct feerate_est, wm->feerates[0]);

	if (tal_count(wm->smoothed_feerates) != 0) {
		const size_t num_new = tal_count(new_smoothed);
		for (size_t i = 0; i < num_new; i++)
			smooth_one_feerate(ld, &new_smoothed[i]);
	}
	changed |= feerates_differ(wm->smoothed_feerates, new_smoothed);
	tal_free(wm->smoothed_feerates);
	wm->smoothed_feerates = new_smoothed;

	if (changed)
		notify_feerate_change(ld);
}

/*
 * Fee polling: lightningd polls bitcoind for fee estimates every 30 seconds,
 * mirroring what chaintopology used to do. bwatch no longer calls estimatefees;
 * it only reports blockheight via block_processed.
 */
struct fee_poll {
	struct lightningd *ld;
	struct oneshot *timer;
};

/* Forward declaration */
static void start_fee_estimate(struct fee_poll *fp);

static void schedule_fee_estimate(struct fee_poll *fp);

static void update_feerates_and_reschedule(struct lightningd *ld,
					   u32 feerate_floor,
					   const struct feerate_est *rates,
					   struct fee_poll *fp)
{
	update_feerates(ld, feerate_floor, rates);
	schedule_fee_estimate(fp);
}

static void start_fee_estimate(struct fee_poll *fp)
{
	fp->timer = NULL;
	bitcoind_estimate_fees(fp, fp->ld->bitcoind,
			       update_feerates_and_reschedule, fp);
}

static void schedule_fee_estimate(struct fee_poll *fp)
{
	fp->timer = new_reltimer(fp->ld->timers, fp,
				 time_from_sec(30),
				 start_fee_estimate, fp);
}

/* Called once bwatch/bitcoind are live; kicks off the 30-second fee poll loop */
void start_fee_polling(struct lightningd *ld)
{
	struct fee_poll *fp = tal(ld, struct fee_poll);
	fp->ld = ld;
	fp->timer = NULL;
	ld->fee_poll = fp;
	/* Do an immediate estimate, then repeat every 30s */
	start_fee_estimate(fp);
}

struct rate_conversion {
	u32 blockcount;
};

static struct rate_conversion conversions[] = {
	[FEERATE_OPENING] = { 12 },
	[FEERATE_MUTUAL_CLOSE] = { 100 },
	[FEERATE_UNILATERAL_CLOSE] = { 6 },
	[FEERATE_DELAYED_TO_US] = { 12 },
	[FEERATE_HTLC_RESOLUTION] = { 6 },
	[FEERATE_PENALTY] = { 12 },
};

u32 opening_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_OPENING];
	return feerate_for_deadline(ld, conversions[FEERATE_OPENING].blockcount);
}

u32 mutual_close_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_MUTUAL_CLOSE];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_MUTUAL_CLOSE].blockcount);
}

u32 unilateral_feerate(struct lightningd *ld, bool option_anchors)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_UNILATERAL_CLOSE];

	if (option_anchors) {
		u32 feerate = feerate_for_deadline(ld, 100);
		if (!feerate)
			return 0;
		if (feerate < 1250)
			return 1250;
		return feerate;
	}

	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_UNILATERAL_CLOSE].blockcount)
		* ld->config.commit_fee_percent / 100;
}

u32 delayed_to_us_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_DELAYED_TO_US];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_DELAYED_TO_US].blockcount);
}

u32 htlc_resolution_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_HTLC_RESOLUTION];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_HTLC_RESOLUTION].blockcount);
}

u32 penalty_feerate(struct lightningd *ld)
{
	if (ld->force_feerates)
		return ld->force_feerates[FEERATE_PENALTY];
	return smoothed_feerate_for_deadline(ld,
					     conversions[FEERATE_PENALTY].blockcount);
}

u32 get_feerate_floor(struct lightningd *ld)
{
	return ld->watchman->feerate_floor;
}

u32 default_locktime(struct lightningd *ld)
{
	u32 locktime, current_height = get_block_height(ld);

	locktime = current_height;

	if (locktime > 100 && pseudorand(10) == 0)
		locktime -= pseudorand(100);

	return locktime;
}

static struct command_result *json_feerates(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct lightningd *ld = cmd->ld;
	struct json_stream *response;
	enum feerate_style *style;
	u32 rate;

	if (!param(cmd, buffer, params,
		   p_req("style", param_feerate_style, &style),
		   NULL))
		return command_param_failed();

	struct watchman *wm = ld->watchman;
	const size_t num_feerates = tal_count(wm->feerates[0]);

	response = json_stream_success(cmd);
	if (!num_feerates)
		json_add_string(response, "warning_missing_feerates",
				"Some fee estimates unavailable: bitcoind startup?");

	json_object_start(response, feerate_style_name(*style));
	rate = opening_feerate(ld);
	if (rate)
		json_add_num(response, "opening", feerate_to_style(rate, *style));
	rate = mutual_close_feerate(ld);
	if (rate)
		json_add_num(response, "mutual_close",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(ld, false);
	if (rate)
		json_add_num(response, "unilateral_close",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(ld, true);
	if (rate)
		json_add_num(response, "unilateral_anchor_close",
			     feerate_to_style(rate, *style));
	rate = penalty_feerate(ld);
	if (rate)
		json_add_num(response, "penalty",
			     feerate_to_style(rate, *style));

	json_add_u64(response, "min_acceptable",
		     feerate_to_style(feerate_min(ld, NULL), *style));
	json_add_u64(response, "max_acceptable",
		     feerate_to_style(feerate_max(ld, NULL), *style));
	json_add_u64(response, "floor",
		     feerate_to_style(get_feerate_floor(ld), *style));

	json_array_start(response, "estimates");
	assert(tal_count(wm->smoothed_feerates) == num_feerates);
	for (size_t i = 0; i < num_feerates; i++) {
		json_object_start(response, NULL);
		json_add_num(response, "blockcount",
			     wm->feerates[0][i].blockcount);
		json_add_u64(response, "feerate",
			     feerate_to_style(wm->feerates[0][i].rate, *style));
		json_add_u64(response, "smoothed_feerate",
			     feerate_to_style(wm->smoothed_feerates[i].rate,
					      *style));
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);

	if (num_feerates) {
		bool anchor_outputs
			= feature_offered(ld->our_features->bits[INIT_FEATURE],
					  OPT_ANCHOR_OUTPUTS_DEPRECATED)
			|| feature_offered(ld->our_features->bits[INIT_FEATURE],
					   OPT_ANCHORS_ZERO_FEE_HTLC_TX);

		json_object_start(response, "onchain_fee_estimates");
		json_add_num(response, "opening_channel_satoshis",
			     opening_feerate(ld) * 702 / 1000);
		json_add_u64(response, "mutual_close_satoshis",
			     mutual_close_feerate(ld) * 673 / 1000);
		if (anchor_outputs)
			json_add_u64(response, "unilateral_close_satoshis",
				     unilateral_feerate(ld, true) * 1112 / 1000);
		else
			json_add_u64(response, "unilateral_close_satoshis",
				     unilateral_feerate(ld, false) * 598 / 1000);
		json_add_u64(response, "unilateral_close_nonanchor_satoshis",
			     unilateral_feerate(ld, false) * 598 / 1000);

		json_add_u64(response, "htlc_timeout_satoshis",
			     htlc_timeout_fee(htlc_resolution_feerate(ld),
					      false, false).satoshis /* Raw: estimate */);
		json_add_u64(response, "htlc_success_satoshis",
			     htlc_success_fee(htlc_resolution_feerate(ld),
					      false, false).satoshis /* Raw: estimate */);
		json_object_end(response);
	}

	return command_success(cmd, response);
}

static const struct json_command feerates_command = {
	"feerates",
	json_feerates,
};
AUTODATA(json_command, &feerates_command);

static struct command_result *json_parse_feerate(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	u32 *feerate;

	if (!param(cmd, buffer, params,
		   p_req("feerate", param_feerate, &feerate),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_add_num(response, feerate_style_name(FEERATE_PER_KSIPA),
		     feerate_to_style(*feerate, FEERATE_PER_KSIPA));
	return command_success(cmd, response);
}

static const struct json_command parse_feerate_command = {
	"parsefeerate",
	json_parse_feerate,
};
AUTODATA(json_command, &parse_feerate_command);

u32 feerate_min(struct lightningd *ld, bool *unknown)
{
	struct watchman *wm = ld->watchman;
	u32 min;

	if (unknown)
		*unknown = false;

	min = 0xFFFFFFFF;
	for (size_t i = 0; i < ARRAY_SIZE(wm->feerates); i++) {
		const size_t num_feerates = tal_count(wm->feerates[i]);
		for (size_t j = 0; j < num_feerates; j++) {
			if (wm->feerates[i][j].rate < min)
				min = wm->feerates[i][j].rate;
		}
	}
	if (min == 0xFFFFFFFF) {
		if (unknown)
			*unknown = true;
		min = 0;
	}

	min /= 2;

	if (min < get_feerate_floor(ld))
		return get_feerate_floor(ld);
	return min;
}

u32 feerate_max(struct lightningd *ld, bool *unknown)
{
	struct watchman *wm = ld->watchman;
	u32 max = 0;

	if (unknown)
		*unknown = false;

	for (size_t i = 0; i < ARRAY_SIZE(wm->feerates); i++) {
		const size_t num_feerates = tal_count(wm->feerates[i]);
		for (size_t j = 0; j < num_feerates; j++) {
			if (wm->feerates[i][j].rate > max)
				max = wm->feerates[i][j].rate;
		}
	}
	if (!max) {
		if (unknown)
			*unknown = true;
		return UINT_MAX;
	}
	return max * ld->config.max_fee_multiplier;
}


const char *feerate_name(enum feerate feerate)
{
	switch (feerate) {
	case FEERATE_OPENING: return "opening";
	case FEERATE_MUTUAL_CLOSE: return "mutual_close";
	case FEERATE_UNILATERAL_CLOSE: return "unilateral_close";
	case FEERATE_DELAYED_TO_US: return "delayed_to_us";
	case FEERATE_HTLC_RESOLUTION: return "htlc_resolution";
	case FEERATE_PENALTY: return "penalty";
	case FEERATE_MIN: return "min_acceptable";
	case FEERATE_MAX: return "max_acceptable";
	}
	abort();
}

struct command_result *param_feerate_style(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum feerate_style **style)
{
	*style = tal(cmd, enum feerate_style);
	if (json_tok_streq(buffer, tok,
			   feerate_style_name(FEERATE_PER_KSIPA))) {
		**style = FEERATE_PER_KSIPA;
		return NULL;
	} else if (json_tok_streq(buffer, tok,
				  feerate_style_name(FEERATE_PER_KBYTE))) {
		**style = FEERATE_PER_KBYTE;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be '%s' or '%s', not '%.*s'",
			    name,
			    feerate_style_name(FEERATE_PER_KSIPA),
			    feerate_style_name(FEERATE_PER_KBYTE),
			    json_tok_full_len(tok), json_tok_full(buffer, tok));
}

static struct command_result *param_feerate_unchecked(struct command *cmd,
						      const char *name,
						      const char *buffer,
						      const jsmntok_t *tok,
						      u32 **feerate)
{
	*feerate = tal(cmd, u32);

	if (json_tok_streq(buffer, tok, "opening")) {
		**feerate = opening_feerate(cmd->ld);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "mutual_close")) {
		**feerate = mutual_close_feerate(cmd->ld);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "penalty")) {
		**feerate = penalty_feerate(cmd->ld);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "unilateral_close")) {
		**feerate = unilateral_feerate(cmd->ld, false);
		return NULL;
	}
	if (json_tok_streq(buffer, tok, "unilateral_anchor_close")) {
		**feerate = unilateral_feerate(cmd->ld, true);
		return NULL;
	}

	if (json_tok_streq(buffer, tok, "slow")) {
		**feerate = feerate_for_deadline(cmd->ld, 100);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "normal")) {
		**feerate = feerate_for_deadline(cmd->ld, 12);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "urgent")) {
		**feerate = feerate_for_deadline(cmd->ld, 6);
		return NULL;
	} else if (json_tok_streq(buffer, tok, "minimum")) {
		**feerate = get_feerate_floor(cmd->ld);
		return NULL;
	}

	if (json_tok_endswith(buffer, tok, "blocks")) {
		jsmntok_t base = *tok;
		base.end -= strlen("blocks");
		u32 numblocks;

		if (!json_to_number(buffer, &base, &numblocks)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%s' should be an integer not '%.*s'",
					    name, base.end - base.start,
					    buffer + base.start);
		}
		**feerate = feerate_for_deadline(cmd->ld, numblocks);
		return NULL;
	}

	tal_free(*feerate);
	return param_feerate_val(cmd, name, buffer, tok, feerate);
}

struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate)
{
	struct command_result *ret;

	ret = param_feerate_unchecked(cmd, name, buffer, tok, feerate);
	if (ret)
		return ret;

	if (**feerate == 0)
		return command_fail(cmd, BCLI_NO_FEE_ESTIMATES,
				    "Cannot estimate fees (yet)");

	return NULL;
}

struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw)
{
	jsmntok_t base = *tok;
	enum feerate_style style;
	unsigned int num;

	if (json_tok_endswith(buffer, tok,
			      feerate_style_name(FEERATE_PER_KBYTE))) {
		style = FEERATE_PER_KBYTE;
		base.end -= strlen(feerate_style_name(FEERATE_PER_KBYTE));
	} else if (json_tok_endswith(buffer, tok,
				     feerate_style_name(FEERATE_PER_KSIPA))) {
		style = FEERATE_PER_KSIPA;
		base.end -= strlen(feerate_style_name(FEERATE_PER_KSIPA));
	} else
		style = FEERATE_PER_KBYTE;

	if (!json_to_number(buffer, &base, &num)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be an integer with optional perkw/perkb, not '%.*s'",
				    name, base.end - base.start,
				    buffer + base.start);
	}

	*feerate_per_kw = tal(cmd, u32);
	**feerate_per_kw = feerate_from_style(num, style);
	if (**feerate_per_kw < FEERATE_FLOOR)
		**feerate_per_kw = FEERATE_FLOOR;
	return NULL;
}
