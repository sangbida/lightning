#include "config.h"
#include <ccan/tal/str/str.h>
#include <ccan/array_size/array_size.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>

/* Command handler for the "hello" command */

enum return_value {
	RED,
	YELLOW,
	GREEN,
};

static const char *enum_to_string(enum return_value val) {
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

static struct command_result *json_hello(struct command *cmd,
                                       const char *buf,
                                       const jsmntok_t *params)
{
    uint32_t *enum_val;
    const char *enum_str;
    const char *message;
    struct json_stream *response;

    /* Log entry to the command handler */
    plugin_log(cmd->plugin, LOG_DBG, "Hello command received, parsing parameters...");

    /* Parse parameters: optional "name" parameter */
    if (!param(cmd, buf, params,
              p_req("status_code", param_number, &enum_val),
	       	  p_req("message", param_string, &message),
              NULL)) {
        plugin_log(cmd->plugin, LOG_BROKEN, "Parameter parsing failed!");
        return command_param_failed();
    }

    enum_str = enum_to_string((enum return_value)*enum_val);

    plugin_log(cmd->plugin, LOG_DBG, "Status code: %ld, Message: %s",
               (long)enum_val, message);


    response = jsonrpc_stream_success(cmd);

    json_add_num(response, "status_code", *enum_val);
    json_add_string(response, "status", enum_str);
    json_add_string(response, "message", message);


    plugin_log(cmd->plugin, LOG_INFORM, "Returning status %s with message: %s",
               enum_str, message);

    /* Return the response to the caller */
    return command_success(cmd, response->jout);
}

/* Array of commands we provide */
static const struct plugin_command commands[] = {
    {
        "hello",           /* command name */
        json_hello,        /* handler function */
        NULL, NULL,        /* not deprecated: depr_start, depr_end = NULL */
        false              /* dev_only: false */
    }
};

/* Plugin initialization */
static const char *init(struct command *cmd,
                       const char *buf UNUSED,
                       const jsmntok_t *config UNUSED)
{
    /* Log a message to confirm plugin initialization */
    plugin_log(cmd->plugin, LOG_INFORM, "Hello plugin initialization started");
    plugin_log(cmd->plugin, LOG_INFORM, "Plugin version: 1.0");
    plugin_log(cmd->plugin, LOG_INFORM, "Registering 'hello' command");
    plugin_log(cmd->plugin, LOG_INFORM, "Hello plugin initialization completed successfully!");
    return NULL;
}

int main(int argc, char *argv[])
{
    /* Set up locale for proper formatting */
    setup_locale();

    /* Start plugin */
    plugin_main(argv,
                init,                /* initialization function */
                NULL,               /* plugin-specific data */
                PLUGIN_STATIC,      /* plugin type */
                true,              /* initialize RPC */
                NULL,              /* features */
                commands,          /* commands */
                ARRAY_SIZE(commands),
                NULL, 0,           /* notifications */
                NULL, 0,           /* hooks */
                NULL, 0,           /* notification topics */
                NULL);             /* options */

    return 0;
}