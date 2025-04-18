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
												 void *unused)
{
	const jsmntok_t *nodes;
	struct json_stream *response;
	const char *node_id = NULL;
	const char *alias = NULL;
	const char *color = NULL;
	
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
		const jsmntok_t *color_tok = json_get_member(buf, node, "color");
		
		if (nodeid_tok) {
			node_id = json_strdup(tmpctx, buf, nodeid_tok);
		}
		
		if (alias_tok) {
			alias = json_strdup(tmpctx, buf, alias_tok);
		}
		
		if (color_tok) {
			color = json_strdup(tmpctx, buf, color_tok);
		}
	}
	
	/* Create response with the random node info */
	response = jsonrpc_stream_success(cmd);
	if (node_id) {
		json_add_string(response, "node_id", node_id);
		if (alias) {
			json_add_string(response, "alias", alias);
		}
		if (color) {
			json_add_string(response, "color", color);
		}
		json_add_num(response, "total_nodes", nodes->size);
	} else {
		json_add_null(response, "node_id");
		json_add_num(response, "total_nodes", 0);
	}
	
	return command_finished(cmd, response);
}

/* Command handler for getting a random node */
struct command_result *json_get_random_node(struct command *cmd,
										   const char *buf,
										   const jsmntok_t *params)
{
	struct out_req *req;
	
	/* Initialize random seed */
	init_random_seed();
	
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();
	
	/* Call listnodes and wait for the response */
	req = jsonrpc_request_start(cmd, "listnodes",
							   get_random_node_done,
							   forward_error,
							   NULL);
	return send_outreq(req);
}