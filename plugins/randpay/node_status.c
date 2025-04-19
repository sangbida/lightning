//
// Created by Jake Dean on 18/4/2025.
//

#include "config.h"
#include "node_status.h"
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include <stdlib.h>
#include <time.h>


typedef struct randpay_ctx {
	uint64_t amount_msat;
	int riskfactor;
	const char *node_id;
	const char *route_json;
	const char *payment_hash;
} randpay_ctx;



/* Initialize random seed once at plugin load time */
static void init_random_seed(void)
{
	static bool seed_initialized = false;
	if (!seed_initialized) {
		srand(time(NULL));
		seed_initialized = true;
	}
}

const char *enum_to_string(enum return_value val) {
	switch (val) {
	case RED:
		return "RED";
	case YELLOW:
		return "YELLOW";
	case GREEN:
		return "GREEN";
	default:
		return "UNKNOWN";
	}
}

// Determines payment status based on waitsendpay response
static struct command_result *on_waitsendpay_done(
    struct command *cmd,
    const char *method UNUSED,
    const char *buf,
    const jsmntok_t *input,
    void *udata)
{
	randpay_ctx *ctx = udata;
	enum return_value status;

	plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: Processing waitsendpay response");
	plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: Full response: %.*s", 
	          json_tok_full_len(input), json_tok_full(buf, input));
	
	// Log the raw buffer for debugging
	plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: Raw buffer: %s", buf);

	const jsmntok_t *error_tok = json_get_member(buf, input, "error");
	if (error_tok) {
		plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: Error found: %.*s", 
		          json_tok_full_len(error_tok), json_tok_full(buf, error_tok));
	}
	
	const jsmntok_t *data_tok = error_tok ? json_get_member(buf, error_tok, "data") : NULL;
	if (data_tok) {
		plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: Error data: %.*s", 
		          json_tok_full_len(data_tok), json_tok_full(buf, data_tok));
	}
	
	const jsmntok_t *failcode_tok = data_tok ? json_get_member(buf, data_tok, "failcode") : NULL;
	const jsmntok_t *erring_tok   = data_tok ? json_get_member(buf, data_tok, "erring_index") : NULL;

	if (!failcode_tok || !erring_tok) {
		plugin_log(cmd->plugin, LOG_BROKEN, "on_waitsendpay_done: Missing failcode or erring_index");
		status = RED;
	} else {
		u64 failcode = 0;
		u64 erring_index = 0;
		json_to_u64(buf, failcode_tok, &failcode);
		json_to_u64(buf, erring_tok, &erring_index);
		plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: failcode=%llu, erring_index=%llu", 
		          failcode, erring_index);
		
		if (failcode == 16399)
			status = GREEN;
		else if (erring_index == 0)
			status = RED;
		else
			status = YELLOW;
	}

	plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_done: Final status=%s", enum_to_string(status));

	struct json_stream *resp = jsonrpc_stream_success(cmd);
	json_add_string(resp, "node_id", ctx->node_id);
	json_add_u64   (resp, "amount_msat", ctx->amount_msat);
	json_add_num   (resp, "riskfactor", ctx->riskfactor);
	json_add_string(resp, "payment_hash", ctx->payment_hash);
	json_add_string(resp, "status", enum_to_string(status));
	json_add_num   (resp, "status_code", status);

	return command_finished(cmd, resp);
}

// Starts waitsendpay to track payment status after sendpay
static struct command_result *on_sendpay_sent(
    struct command *cmd,
    const char *method UNUSED,
    const char *buf UNUSED,
    const jsmntok_t *result UNUSED,
    void *udata)
{
	randpay_ctx *ctx = udata;
	plugin_log(cmd->plugin, LOG_INFORM, "on_sendpay_sent: Payment sent, starting waitsendpay");
	plugin_log(cmd->plugin, LOG_INFORM, "on_sendpay_sent: payment_hash=%s", ctx->payment_hash);
	
	struct out_req *req = jsonrpc_request_start(cmd,
						    "waitsendpay",
						    on_waitsendpay_done,
						    forward_error,
						    ctx);
	json_add_string(req->js, "payment_hash", ctx->payment_hash);
	
	// Log the payment hash for debugging
	plugin_log(cmd->plugin, LOG_INFORM, "on_sendpay_sent: waitsendpay request with payment_hash=%s", ctx->payment_hash);
	
	return send_outreq(req);
}

// Processes route from getroute and initiates payment if route found
static struct command_result *on_getroute_done(
    struct command *cmd,
    const char *method UNUSED,
    const char *buf,
    const jsmntok_t *result,
    void *udata)
{
	randpay_ctx *ctx = udata;
	
	plugin_log(cmd->plugin, LOG_INFORM, "on_getroute_done: Processing getroute response");
	plugin_log(cmd->plugin, LOG_INFORM, "on_getroute_done: Response: %.*s", 
	          json_tok_full_len(result), json_tok_full(buf, result));
	
	const jsmntok_t *r_tok = json_get_member(buf, result, "route");

	if (!r_tok || r_tok->type != JSMN_ARRAY || r_tok->size == 0) {
		plugin_log(cmd->plugin, LOG_BROKEN, "on_getroute_done: No valid route found");
		struct json_stream *resp = jsonrpc_stream_success(cmd);
		json_add_string(resp, "status", enum_to_string(RED));
		json_add_num   (resp, "status_code", RED);
		return command_finished(cmd, resp);
	}

	plugin_log(cmd->plugin, LOG_INFORM, "on_getroute_done: Found route with %d hops", r_tok->size);
	
	// Use a fixed all-zeros payment hash for testing
	char *ph = tal_arr(tmpctx, char, 65); // 32 bytes = 64 hex chars + null terminator
	for (int i = 0; i < 64; i++) {
		ph[i] = '0';
	}
	ph[64] = '\0';
	ctx->payment_hash = tal_strdup(ctx, ph);
	plugin_log(cmd->plugin, LOG_INFORM, "on_getroute_done: Using fixed payment_hash=%s", ctx->payment_hash);

	plugin_log(cmd->plugin, LOG_INFORM, "on_getroute_done: Initiating sendpay");
	struct out_req *req = jsonrpc_request_start(cmd,
						    "sendpay",
						    on_sendpay_sent,
						    forward_error,
						    ctx);
	
	// Add the route as a JSON array
	json_array_start(req->js, "route");
	
	// Copy each hop from the route to our request
	for (int i = 0; i < r_tok->size; i++) {
		const jsmntok_t *hop = json_get_arr(r_tok, i);
		json_object_start(req->js, NULL);
		
		// Copy each field from the hop
		const jsmntok_t *id_tok = json_get_member(buf, hop, "id");
		const jsmntok_t *channel_tok = json_get_member(buf, hop, "channel");
		const jsmntok_t *direction_tok = json_get_member(buf, hop, "direction");
		const jsmntok_t *amount_tok = json_get_member(buf, hop, "amount_msat");
		const jsmntok_t *delay_tok = json_get_member(buf, hop, "delay");
		const jsmntok_t *style_tok = json_get_member(buf, hop, "style");
		
		if (id_tok)
			json_add_tok(req->js, "id", id_tok, buf);
		if (channel_tok)
			json_add_tok(req->js, "channel", channel_tok, buf);
		if (direction_tok)
			json_add_tok(req->js, "direction", direction_tok, buf);
		if (amount_tok)
			json_add_tok(req->js, "amount_msat", amount_tok, buf);
		if (delay_tok)
			json_add_tok(req->js, "delay", delay_tok, buf);
		if (style_tok)
			json_add_tok(req->js, "style", style_tok, buf);
		
		json_object_end(req->js);
	}
	
	json_array_end(req->js);
	
	// Make sure to add the payment hash to the request
	json_add_string(req->js, "payment_hash", ctx->payment_hash);
	
	// Log the payment hash for debugging
	plugin_log(cmd->plugin, LOG_INFORM, "on_getroute_done: sendpay request with payment_hash=%s", ctx->payment_hash);
	
	return send_outreq(req);
}

// Selects random node from listnodes and requests route to it
static struct command_result *on_listnodes_done(
    struct command *cmd,
    const char *method UNUSED,
    const char *buf,
    const jsmntok_t *result,
    void *udata)
{
	randpay_ctx *ctx = udata;
	plugin_log(cmd->plugin, LOG_INFORM, "on_listnodes_done: Processing listnodes response");
	
	const jsmntok_t *nodes = json_get_member(buf, result, "nodes");
	if (!nodes || nodes->type != JSMN_ARRAY || nodes->size == 0) {
		plugin_log(cmd->plugin, LOG_BROKEN, "on_listnodes_done: No nodes found in network");
		struct json_stream *resp = jsonrpc_stream_success(cmd);
		json_add_string(resp, "status", enum_to_string(RED));
		json_add_num   (resp, "status_code", RED);
		return command_finished(cmd, resp);
	}
	
	plugin_log(cmd->plugin, LOG_INFORM, "on_listnodes_done: Found %d nodes in network", nodes->size);
	size_t idx = rand() % nodes->size;
	const jsmntok_t *n_tok = json_get_arr(nodes, idx);
	const jsmntok_t *nid = json_get_member(buf, n_tok, "nodeid");
	ctx->node_id = json_strdup(tmpctx, buf, nid);
	plugin_log(cmd->plugin, LOG_INFORM, "on_listnodes_done: Selected random node_id=%s", ctx->node_id);

	plugin_log(cmd->plugin, LOG_INFORM, "on_listnodes_done: Requesting route to node with amount_msat=%llu, riskfactor=%d", 
	          ctx->amount_msat, ctx->riskfactor);
	struct out_req *req = jsonrpc_request_start(cmd,
						    "getroute",
						    on_getroute_done,
						    forward_error,
						    ctx);
	json_add_string(req->js, "id", ctx->node_id);
	json_add_u64   (req->js, "amount_msat", ctx->amount_msat);
	json_add_num   (req->js, "riskfactor", ctx->riskfactor);
	return send_outreq(req);
}

/* Command handler for getting a random node */
struct command_result *json_randpay(struct command *cmd,
				    const char *buf,
				    const jsmntok_t *params)
{
	struct out_req *req;
	unsigned int *amount_msat;
	unsigned int *riskfactor;
	
	plugin_log(cmd->plugin, LOG_INFORM, "json_randpay: Starting randpay command");
	
	/* Initialize random seed */
	init_random_seed();
	
	/* Parse parameters */
	if (!param(cmd, buf, params,
			   p_opt("amount_msat", param_number, &amount_msat),
			   p_opt("riskfactor", param_number, &riskfactor),
			   NULL))
		return command_param_failed();
	
	plugin_log(cmd->plugin, LOG_INFORM, "json_randpay: Parameters parsed - amount_msat=%s, riskfactor=%s", 
	          amount_msat ? "provided" : "not provided", 
	          riskfactor ? "provided" : "not provided");
	
	/* If amount_msat is provided, we'll get a route too */
	if (amount_msat && *amount_msat > 0) {
		randpay_ctx *ctx = tal(cmd, randpay_ctx);
		ctx->amount_msat = *amount_msat;
		ctx->riskfactor = riskfactor ? *riskfactor : 100;
		
		plugin_log(cmd->plugin, LOG_INFORM, "json_randpay: Creating context with amount_msat=%llu, riskfactor=%d", 
		          ctx->amount_msat, ctx->riskfactor);
		
		/* Call listnodes and wait for the response */
		plugin_log(cmd->plugin, LOG_INFORM, "json_randpay: Requesting listnodes");
		req = jsonrpc_request_start(cmd, "listnodes",
								   on_listnodes_done,
								   forward_error,
								   ctx);
		return send_outreq(req);
	}
	
	/* If no amount provided, just return an error */
	plugin_log(cmd->plugin, LOG_BROKEN, "json_randpay: No amount_msat provided");
	struct json_stream *resp = jsonrpc_stream_success(cmd);
	json_add_string(resp, "status", enum_to_string(RED));
	json_add_num(resp, "status_code", RED);
	json_add_string(resp, "error", "amount_msat parameter is required");
	return command_finished(cmd, resp);
}