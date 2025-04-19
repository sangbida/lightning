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

static struct command_result *get_route_done(struct command *cmd,
										   const char *method,
										   const char *buf,
										   const jsmntok_t *result,
										   void *arg);

typedef struct get_route_params {
	uint64_t amount_msat;
	int riskfactor;
	const char *node_id;
	const char *alias;
	size_t total_nodes;
} get_route_params;


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

/* Callback for listnodes command in get_random_node */
static struct command_result *get_random_node_done(struct command *cmd,
												 const char *method,
												 const char *buf,
												 const jsmntok_t *result,
												 void *arg)
{
	const jsmntok_t *nodes;
	struct json_stream *response;
	const char *node_id = NULL;
	const char *alias = NULL;
	struct out_req *route_req;
	struct get_route_params *route_params = arg;
	
	/* Get the nodes array from the result */
	nodes = json_get_member(buf, result, "nodes");
	if (!nodes) {
		plugin_log(cmd->plugin, LOG_BROKEN, "No nodes in listnodes response");
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "No nodes in listnodes response");
	}
	
	/* Pick a random node if there are any */
	if (nodes->size > 0) {
		/* Use standard rand() function */
		size_t index = rand() % nodes->size;
		const jsmntok_t *node = json_get_arr(nodes, index);
		const jsmntok_t *nodeid_tok = json_get_member(buf, node, "nodeid");
		const jsmntok_t *alias_tok = json_get_member(buf, node, "alias");
		
		if (nodeid_tok) {
			node_id = json_strdup(tmpctx, buf, nodeid_tok);
		}
		
		if (alias_tok) {
			alias = json_strdup(tmpctx, buf, alias_tok);
		}
	}

	if (node_id) {
		if (route_params) {
			route_params->node_id = node_id;
			route_params->alias = alias;
			route_params->total_nodes = nodes->size;
			
			route_req = jsonrpc_request_start(cmd, "getroute", get_route_done, forward_error, route_params);
			json_add_string(route_req->js, "id", node_id);
			json_add_num(route_req->js, "amount_msat", route_params->amount_msat);
			json_add_num(route_req->js, "riskfactor", route_params->riskfactor);
			return send_outreq(route_req);
		}
	}
	
	/* Create response with the random node info */
	response = jsonrpc_stream_success(cmd);
	if (node_id) {
		json_add_string(response, "node_id", node_id);
		if (alias) {
			json_add_string(response, "alias", alias);
		}
		json_add_num(response, "total_nodes", nodes->size);
	} else {
		json_add_null(response, "node_id");
		json_add_num(response, "total_nodes", 0);
	}
	
	return command_finished(cmd, response);
}

static struct command_result *get_route_done(struct command *cmd,
											const char *method,
											const char *buf,
											const jsmntok_t *result,
											void *arg)
{
	struct get_route_params *params = arg;
	struct json_stream *response;
	const jsmntok_t *route;
	enum return_value status = RED;
	
	route = json_get_member(buf, result, "route");
	if (!route) {
		plugin_log(cmd->plugin, LOG_BROKEN, "No route in getroute response");
		status = RED;
	} else if (route->size == 0) {
		plugin_log(cmd->plugin, LOG_BROKEN, "Empty route in getroute response");
		status = RED;
	} else if (route->size <= 2) {
		status = GREEN;
	} else {
		status = YELLOW;
	}
	
	response = jsonrpc_stream_success(cmd);
	
	json_add_string(response, "node_id", params->node_id);
	if (params->alias) {
		json_add_string(response, "alias", params->alias);
	}
	json_add_num(response, "total_nodes", params->total_nodes);
	
	json_add_tok(response, "route", route, buf);
	json_add_num(response, "amount_msat", params->amount_msat);
	json_add_num(response, "riskfactor", params->riskfactor);
	
	json_add_num(response, "status_code", status);
	json_add_string(response, "status", enum_to_string(status));
	
	plugin_log(cmd->plugin, LOG_INFORM, "Route status: %s", enum_to_string(status));
	
	return command_finished(cmd, response);
}

/* Command handler for getting a random node */
struct command_result *json_get_random_node(struct command *cmd,
										   const char *buf,
										   const jsmntok_t *params)
{
	struct out_req *req;
	struct get_route_params *route_params = NULL;
	unsigned int *amount_msat_ptr = NULL;
	unsigned int *riskfactor_ptr = NULL;
	u64 amount_msat = 0;
	int riskfactor = 100;
	
	/* Initialize random seed */
	init_random_seed();
	
	/* Parse parameters */
	if (!param(cmd, buf, params,
			   p_opt("amount_msat", param_number, &amount_msat_ptr),
			   p_opt("riskfactor", param_number, &riskfactor_ptr),
			   NULL))
		return command_param_failed();
	
	if (!amount_msat_ptr && params && params->size > 0) {
		amount_msat = json_tok_number(buf, params);
		plugin_log(cmd->plugin, LOG_INFORM, "Using positional parameter as amount_msat: %lu", amount_msat);
	} else if (amount_msat_ptr) {
		amount_msat = *amount_msat_ptr;
	}
	
	if (riskfactor_ptr) {
		riskfactor = *riskfactor_ptr;
	}
	
	if (amount_msat > 0) {
		route_params = tal(cmd, struct get_route_params);
		route_params->amount_msat = amount_msat;
		route_params->riskfactor = riskfactor;
	}
	
	/* Call listnodes and wait for the response */
	req = jsonrpc_request_start(cmd, "listnodes",
							   get_random_node_done,
							   forward_error,
							   route_params);
	return send_outreq(req);
}