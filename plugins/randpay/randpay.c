//
// Created by Jake Dean on 18/4/2025.
//

#include "config.h"
#include "randpay.h"
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

	// Check if this is an error response
	const jsmntok_t *error_tok = json_get_member(buf, input, "error");
	if (error_tok) {
		// Get the data field from the error
		const jsmntok_t *data_tok = json_get_member(buf, error_tok, "data");
		if (data_tok) {
			// Extract failcode and erring_index
			const jsmntok_t *failcode_tok = json_get_member(buf, data_tok, "failcode");
			const jsmntok_t *erring_tok = json_get_member(buf, data_tok, "erring_index");
			
			if (failcode_tok && erring_tok) {
				u64 failcode = 0;
				u64 erring_index = 0;
				json_to_u64(buf, failcode_tok, &failcode);
				json_to_u64(buf, erring_tok, &erring_index);
				
				// Return GREEN for failcode 16399 (WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS)
				if (failcode == 16399) {
					status = GREEN;
				} else if (erring_index == 0) {
					status = RED;
				} else {
					status = YELLOW;
				}
			} else {
				status = RED;
			}
		} else {
			status = RED;
		}
	} else {
		// This is a success response
		status = GREEN;
	}

	struct json_stream *resp = jsonrpc_stream_success(cmd);
	json_add_string(resp, "node_id", ctx->node_id ? ctx->node_id : "");
	json_add_u64   (resp, "amount_msat", ctx->amount_msat);
	json_add_num   (resp, "riskfactor", ctx->riskfactor);
	json_add_string(resp, "payment_hash", ctx->payment_hash ? ctx->payment_hash : "");
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
	
	struct out_req *req = jsonrpc_request_start(cmd,
						    "waitsendpay",
						    on_waitsendpay_done,
						    on_waitsendpay_done,
						    ctx);
	json_add_string(req->js, "payment_hash", ctx->payment_hash);
	
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
    
    /* Check if we got a valid route */
    const jsmntok_t *route_array = json_get_member(buf, result, "route");
    if (!route_array || route_array->type != JSMN_ARRAY || route_array->size == 0) {
        struct json_stream *response = jsonrpc_stream_success(cmd);
        json_add_string(response, "node_id", ctx->node_id ? ctx->node_id : "");
        json_add_string(response, "status", enum_to_string(RED));
        json_add_num(response, "status_code", RED);
        return command_finished(cmd, response);
    }
    
    /* Generate payment hash (all zeros for testing) */
    char *payment_hash = tal_arr(tmpctx, char, 65); // 32 bytes = 64 hex chars + null terminator
    for (int i = 0; i < 64; i++) {
        payment_hash[i] = '0';
    }
    payment_hash[64] = '\0';
    ctx->payment_hash = tal_strdup(ctx, payment_hash);

    /* Start sendpay request */
    struct out_req *sendpay_req = jsonrpc_request_start(cmd,
                                                      "sendpay",
                                                      on_sendpay_sent,
                                                      forward_error,
                                                      ctx);
    
    /* Build route array in sendpay request */
    json_array_start(sendpay_req->js, "route");
    
    /* Copy each hop from the route */
    for (int hop_index = 0; hop_index < route_array->size; hop_index++) {
        const jsmntok_t *current_hop = json_get_arr(route_array, hop_index);
        json_object_start(sendpay_req->js, NULL);
        
        /* Define hop fields to copy */
        struct {
            const char *name;
            const jsmntok_t *token;
        } hop_fields[] = {
            {"id", json_get_member(buf, current_hop, "id")},
            {"channel", json_get_member(buf, current_hop, "channel")},
            {"direction", json_get_member(buf, current_hop, "direction")},
            {"amount_msat", json_get_member(buf, current_hop, "amount_msat")},
            {"delay", json_get_member(buf, current_hop, "delay")},
            {"style", json_get_member(buf, current_hop, "style")}
        };
        
        /* Copy each field if present */
        for (size_t field_index = 0; field_index < sizeof(hop_fields)/sizeof(hop_fields[0]); field_index++) {
            if (hop_fields[field_index].token) {
                json_add_tok(sendpay_req->js, hop_fields[field_index].name, 
                           hop_fields[field_index].token, buf);
            }
        }
        
        json_object_end(sendpay_req->js);
    }
    
    json_array_end(sendpay_req->js);
    
    /* Add payment hash to request */
    json_add_string(sendpay_req->js, "payment_hash", ctx->payment_hash);
    
    return send_outreq(sendpay_req);
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
	
	/*Get the nodes array*/
	const jsmntok_t *nodes = json_get_member(buf, result, "nodes");

	/*Check if nodes array is valid, return RED if not*/
	if (!nodes || nodes->type != JSMN_ARRAY || nodes->size == 0) {
		struct json_stream *resp = jsonrpc_stream_success(cmd);
		json_add_string(resp, "node_id", "");
		json_add_string(resp, "status", enum_to_string(RED));
		json_add_num   (resp, "status_code", RED);
		return command_finished(cmd, resp);
	}
	
	/*Get a random node from the nodes array*/
	size_t idx = rand() % nodes->size;
	const jsmntok_t *n_tok = json_get_arr(nodes, idx);
	const jsmntok_t *nid = json_get_member(buf, n_tok, "nodeid");
	ctx->node_id = tal_strdup(ctx, json_strdup(tmpctx, buf, nid));

	/*Request a route to the selected node*/
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
	
	/* Initialize random seed */
	init_random_seed();
	
	/* Parse parameters */
	if (!param(cmd, buf, params,
			   p_opt("amount_msat", param_number, &amount_msat),
			   p_opt("riskfactor", param_number, &riskfactor),
			   NULL))
		return command_param_failed();
	
	/* If amount_msat is provided, we'll get a route too */
	if (amount_msat && *amount_msat > 0) {
		randpay_ctx *ctx = tal(cmd, randpay_ctx);
		ctx->amount_msat = *amount_msat;
		ctx->riskfactor = riskfactor ? *riskfactor : 100;
		ctx->node_id = NULL;  // Initialize node_id to NULL
		ctx->payment_hash = NULL;  // Initialize payment_hash to NULL
		
		/* Call listnodes and wait for the response */
		req = jsonrpc_request_start(cmd, "listnodes",
								   on_listnodes_done,
								   forward_error,
								   ctx);
		return send_outreq(req);
	}
	
	/* If no amount provided, just return an error */
	struct json_stream *resp = jsonrpc_stream_success(cmd);
	json_add_string(resp, "node_id", "");
	json_add_string(resp, "status", enum_to_string(RED));
	json_add_num(resp, "status_code", RED);
	json_add_string(resp, "error", "amount_msat parameter is required");
	return command_finished(cmd, resp);
}