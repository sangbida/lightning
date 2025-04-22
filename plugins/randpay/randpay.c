//
// Created by Jake Dean on 18/4/2025.
//

#include "config.h"
#include "randpay.h"
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/json_parse.h>
#include <plugins/libplugin.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

/* Global variable to store local node ID */
static struct node_id local_id;

typedef struct randpay_ctx {
	uint64_t amount_msat;
	const char *node_id;
	const char *route_json;
	const char *error_msg;
	enum return_value status;
} randpay_ctx;

/* Context for passing route data between getroute and sendpay */
typedef struct route_ctx {
	randpay_ctx *parent;
	const char *payment_hash;
	u64 route_size;
} route_ctx;

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
	case ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}
}

/* Initialize plugin and get local node ID */
const char *init(struct command *cmd, const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	/* Get local node ID */
	rpc_scan(cmd, "getinfo",
			 take(json_out_obj(NULL, NULL, NULL)),
			 "{id:%}", JSON_SCAN(json_to_node_id, &local_id));
	/* Log initialization */
	plugin_log(cmd->plugin, LOG_INFORM, "Randpay plugin initialized");
	return NULL;
}

/* Helper function to create a response with status */
static struct command_result *create_status_response(struct command *cmd,
												   randpay_ctx *ctx,
												   enum return_value status,
												   const char *error_msg)
{
	struct json_stream *resp = jsonrpc_stream_success(cmd);
	json_add_string(resp, "node_id", ctx->node_id ? ctx->node_id : "");
	json_add_u64   (resp, "amount_msat", ctx->amount_msat);
	json_add_string(resp, "status", enum_to_string(status));
	if (error_msg)
		json_add_string(resp, "error", error_msg);
	return command_finished(cmd, resp);
}

/* Helper function to generate a payment hash (all zeros for testing) */
static const char *generate_payment_hash(void *ctx)
{
	char *payment_hash = tal_arr(tmpctx, char, 65); // 32 bytes = 64 hex chars + null terminator
	memset(payment_hash, '0', 64);
	payment_hash[64] = '\0';
	return tal_strdup(ctx, payment_hash);
}

/* Helper function to select a random node from the list, excluding our own node */
static const char *select_random_node(const char *buf, const jsmntok_t *nodes, void *ctx)
{
	/* Count valid nodes (excluding our own) */
	size_t valid_nodes = 0;
	for (size_t i = 0; i < nodes->size; i++) {
		const jsmntok_t *n_tok = json_get_arr(nodes, i);
		const jsmntok_t *nid = json_get_member(buf, n_tok, "nodeid");
		struct node_id nodeid;
		if (json_to_node_id(buf, nid, &nodeid) && !node_id_eq(&nodeid, &local_id)) {
			valid_nodes++;
		}
	}

	if (valid_nodes == 0) {
		return NULL;
	}
	/*Get a random node from the valid nodes*/
	size_t target_idx = rand() % valid_nodes;
	size_t current_idx = 0;
	for (size_t i = 0; i < nodes->size; i++) {
		const jsmntok_t *n_tok = json_get_arr(nodes, i);
		const jsmntok_t *nid = json_get_member(buf, n_tok, "nodeid");
		struct node_id nodeid;
		if (json_to_node_id(buf, nid, &nodeid) && !node_id_eq(&nodeid, &local_id)) {
			if (current_idx == target_idx) {
				return tal_strdup(ctx, json_strdup(tmpctx, buf, nid));
			}
			current_idx++;
		}
	}
	return NULL;
}

/* Helper function to parse error message from JSON */
static const char *parse_error_message(const char *buf, const jsmntok_t *error)
{
	const jsmntok_t *message = json_get_member(buf, error, "message");
	if (message)
		return json_strdup(tmpctx, buf, message);
	return "Unknown error";
}

/* Handle errors for randpay_ctx */
static struct command_result *on_randpay_error(
	struct command *cmd,
	const char *method UNUSED,
	const char *buf,
	const jsmntok_t *error,
	void *udata)
{
	randpay_ctx *ctx = udata;
	return create_status_response(cmd, ctx, RED, parse_error_message(buf, error));
}

/* Handle errors for route_ctx */
static struct command_result *on_route_error(
	struct command *cmd,
	const char *method UNUSED,
	const char *buf,
	const jsmntok_t *error,
	void *udata)
{
	route_ctx *route_data = udata;
	return create_status_response(cmd, route_data->parent, RED, parse_error_message(buf, error));
}

/* Classifies failcodes into return values */
static enum return_value determine_return_value(struct command *cmd, u64 failcode, u64 erring_index, u64 route_size) {
	plugin_log(cmd->plugin, LOG_INFORM, "determine_return_value called with failcode: %llu, erring_index: %llu, route_size: %llu",
		failcode, erring_index, route_size);

	if (failcode == WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS && erring_index == route_size) {
		plugin_log(cmd->plugin, LOG_INFORM, "Returning GREEN (payment details incorrect at final node)");
		return GREEN;
	}
	switch (failcode) {
	// Errors that should only appear at final node
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning RED (final node error)");
		return RED;

	// Unreachable node errors
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_UNKNOWN_NEXT_PEER:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning RED (node unreachable)");
		return RED;

	// Policy or liquidity-related errors
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
	case WIRE_PERMANENT_CHANNEL_FAILURE:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning YELLOW (liquidity/routing issue)");
		return YELLOW;

	default:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning ERROR (unknown failcode: %llu)", failcode);
		return RED;
	}
}

/* Handle errors for route_ctx */
static struct command_result *on_waitsendpay_handle(
	struct command *cmd,
	const char *method UNUSED,
	const char *buf,
	const jsmntok_t *input,
	void *udata)
{
	struct route_ctx *ctx = udata;
	enum return_value ret;
	u64 failcode = 0, erring_index = 0;
	const char *failcodename = NULL;

	plugin_log(cmd->plugin, LOG_INFORM, "on_waitsendpay_handle called with input: %.*s",
		input->end - input->start, buf + input->start);

	/* Use json_get_member to find the tokens directly */
	const jsmntok_t *data_tok = json_get_member(buf, input, "data");
	const jsmntok_t *failcode_tok, *erring_index_tok, *failcodename_tok;

	/* If no data at top level, look for error.data structure */
	if (!data_tok) {
		const jsmntok_t *error_tok = json_get_member(buf, input, "error");
		if (error_tok)
			data_tok = json_get_member(buf, error_tok, "data");
	}

	/* If we found data, get values from there, otherwise try from the root */
	if (data_tok) {
		failcode_tok = json_get_member(buf, data_tok, "failcode");
		erring_index_tok = json_get_member(buf, data_tok, "erring_index");
		failcodename_tok = json_get_member(buf, data_tok, "failcodename");
	} else {
		failcode_tok = json_get_member(buf, input, "failcode");
		erring_index_tok = json_get_member(buf, input, "erring_index");
		failcodename_tok = json_get_member(buf, input, "failcodename");
	}

	/* Check if we found the required fields */
	if (!failcode_tok || !erring_index_tok) {
		plugin_log(cmd->plugin, LOG_INFORM, "Couldn't find failcode or erring_index in the response");
		return create_status_response(cmd, ctx->parent, RED, "Missing failcode or erring_index in response");
	}

	/* Extract the values using tal's json functions */
	if (!json_to_u64(buf, failcode_tok, &failcode) ||
	    !json_to_u64(buf, erring_index_tok, &erring_index)) {
		plugin_log(cmd->plugin, LOG_INFORM, "Failed to parse failcode or erring_index values");
		return create_status_response(cmd, ctx->parent, RED, "Invalid failcode or erring_index format");
	}

	/* Extract failcodename if available */
	if (failcodename_tok)
		failcodename = json_strdup(tmpctx, buf, failcodename_tok);

	plugin_log(cmd->plugin, LOG_INFORM, "Extracted failcode: %llu, erring_index: %llu, failcodename: %s",
		failcode, erring_index, failcodename ? failcodename : "N/A");

	/* Determine the return value based on failcode and erring_index */
	ret = determine_return_value(cmd, failcode, erring_index, ctx->route_size);

	/* Return appropriate response based on the determined return value */
	switch (ret) {
	case GREEN:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning GREEN status");
		return create_status_response(cmd, ctx->parent, GREEN, NULL);

	case YELLOW:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning YELLOW status");
		return create_status_response(cmd, ctx->parent, YELLOW, NULL);

	case RED:
		plugin_log(cmd->plugin, LOG_INFORM, "Returning RED status");
		return create_status_response(cmd, ctx->parent, RED, NULL);

	case ERROR:
	default:
		return create_status_response(cmd, ctx->parent, ret,
			failcodename ? tal_fmt(tmpctx, "Error: %s", failcodename) : "Unknown error");
	}
}

/* Starts waitsendpay to track payment status after sendpay */
static struct command_result *on_sendpay_sent(
	struct command *cmd,
	const char *method UNUSED,
	const char *buf,
	const jsmntok_t *result,
	void *udata)
{
	route_ctx *route_data = udata;
	plugin_log(cmd->plugin, LOG_INFORM, "Sendpay request sent, starting waitsendpay");
	struct out_req *req = jsonrpc_request_start(cmd,
							"waitsendpay",
							on_waitsendpay_handle,
							on_waitsendpay_handle,
							route_data);
	json_add_string(req->js, "payment_hash", route_data->payment_hash);
	plugin_log(cmd->plugin, LOG_INFORM, "Waiting for payment result");
	return send_outreq(req);
}

/* Process route from getroute and initiate payment if route found */
static struct command_result *on_getroute_done(
	struct command *cmd,
	const char *method UNUSED,
	const char *buf,
	const jsmntok_t *result,
	void *udata)
{
	randpay_ctx *ctx = udata;
	plugin_log(cmd->plugin, LOG_INFORM, "Processing route from getroute");
	/* Check if we got a valid route */
	const jsmntok_t *route_array = json_get_member(buf, result, "route");
	if (!route_array || route_array->type != JSMN_ARRAY || route_array->size == 0) {
		plugin_log(cmd->plugin, LOG_INFORM, "No valid route found");
		return create_status_response(cmd, ctx, RED, "No valid route found");
	}
	plugin_log(cmd->plugin, LOG_INFORM, "Found valid route with %d hops", route_array->size);
	/* Create route context and generate payment hash */
	route_ctx *route_data = tal(cmd, route_ctx);
	route_data->parent = ctx;
	route_data->payment_hash = generate_payment_hash(route_data);
	route_data->route_size = route_array->size;
	plugin_log(cmd->plugin, LOG_INFORM, "Generated payment hash: %s", route_data->payment_hash);

	/* Start sendpay request */
	struct out_req *sendpay_req = jsonrpc_request_start(cmd,
													  "sendpay",
													  on_sendpay_sent,
													  on_route_error,
													  route_data);
	/* Build route array in sendpay request */
	json_array_start(sendpay_req->js, "route");
	/* Copy each hop from the route */
	for (int hop_index = 0; hop_index < route_array->size; hop_index++) {
		const jsmntok_t *current_hop = json_get_arr(route_array, hop_index);
		json_object_start(sendpay_req->js, NULL);
		/* Copy hop fields directly */
		json_add_tok(sendpay_req->js, "id", json_get_member(buf, current_hop, "id"), buf);
		json_add_tok(sendpay_req->js, "channel", json_get_member(buf, current_hop, "channel"), buf);
		json_add_tok(sendpay_req->js, "direction", json_get_member(buf, current_hop, "direction"), buf);
		json_add_tok(sendpay_req->js, "amount_msat", json_get_member(buf, current_hop, "amount_msat"), buf);
		json_add_tok(sendpay_req->js, "delay", json_get_member(buf, current_hop, "delay"), buf);
		json_add_tok(sendpay_req->js, "style", json_get_member(buf, current_hop, "style"), buf);
		json_object_end(sendpay_req->js);
	}
	json_array_end(sendpay_req->js);
	/* Add payment hash to request */
	json_add_string(sendpay_req->js, "payment_hash", route_data->payment_hash);
	plugin_log(cmd->plugin, LOG_INFORM, "Sending sendpay request");
	return send_outreq(sendpay_req);
}

/* Selects random node from listnodes and requests route to it */
static struct command_result *on_listnodes_done(
	struct command *cmd,
	const char *method UNUSED,
	const char *buf,
	const jsmntok_t *result,
	void *udata)
{
	randpay_ctx *ctx = udata;
	plugin_log(cmd->plugin, LOG_INFORM, "Processing listnodes response");
	/*Get the nodes array*/
	const jsmntok_t *nodes = json_get_member(buf, result, "nodes");
	/*Check if nodes array is valid, return RED if not*/
	if (!nodes || nodes->type != JSMN_ARRAY || nodes->size == 0) {
		plugin_log(cmd->plugin, LOG_INFORM, "No nodes found in listnodes response");
		return create_status_response(cmd, ctx, ERROR, "No nodes found in network");
	}
	plugin_log(cmd->plugin, LOG_INFORM, "Found %d nodes", nodes->size);
	/* Select a random node */
	ctx->node_id = select_random_node(buf, nodes, ctx);
	if (!ctx->node_id) {
		plugin_log(cmd->plugin, LOG_INFORM, "No valid random node selected");
		return create_status_response(cmd, ctx, ERROR, "No valid random node found");
	}

	plugin_log(cmd->plugin, LOG_INFORM, "Selected node: %s", ctx->node_id);
	/*Request a route to the selected node*/
	struct out_req *req = jsonrpc_request_start(cmd,
							"getroute",
							on_getroute_done,
							on_randpay_error,
							ctx);
	json_add_string(req->js, "id", ctx->node_id);
	json_add_u64   (req->js, "amount_msat", ctx->amount_msat);
	json_add_num   (req->js, "riskfactor", 10);
	plugin_log(cmd->plugin, LOG_INFORM, "Requesting route to node %s with amount %" PRIu64 " msat", ctx->node_id, ctx->amount_msat);
	return send_outreq(req);
}

/* Command handler for getting a random node */
struct command_result *json_randpay(struct command *cmd,
				    const char *buf,
				    const jsmntok_t *params)
{
	struct out_req *req;
	unsigned int *amount_msat;
	plugin_log(cmd->plugin, LOG_INFORM, "Starting randpay command");
	/* Initialize random seed */
	init_random_seed();
	/* Parse parameters */
	if (!param(cmd, buf, params,
			   p_opt("amount_msat", param_number, &amount_msat),
			   NULL))
		return command_param_failed();
	/* If amount_msat is provided, we'll get a route too */
	if (amount_msat && *amount_msat > 0) {
		randpay_ctx *ctx = tal(cmd, randpay_ctx);
		ctx->amount_msat = *amount_msat;
		ctx->node_id = NULL;  // Initialize node_id to NULL
		ctx->error_msg = NULL;  // Initialize error_msg to NULL
		plugin_log(cmd->plugin, LOG_INFORM, "Starting randpay with amount %" PRIu64 " msat", ctx->amount_msat);
		/* Call listnodes and wait for the response */
		req = jsonrpc_request_start(cmd, "listnodes",
								   on_listnodes_done,
								   on_randpay_error,
								   ctx);
		return send_outreq(req);
	}
	/* If no amount provided, just return an error */
	plugin_log(cmd->plugin, LOG_INFORM, "No amount provided, returning error");
	randpay_ctx *ctx = tal(cmd, randpay_ctx);
	return create_status_response(cmd, ctx, ERROR, "A positive amount_msat parameter is required");
}