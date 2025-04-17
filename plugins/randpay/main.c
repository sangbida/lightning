#include "config.h"
#include <ccan/tal/str/str.h>
#include <ccan/array_size/array_size.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>

/* Command handler for the "hello" command */
static struct command_result *json_hello(struct command *cmd,
                                       const char *buf,
                                       const jsmntok_t *params)
{
    struct json_stream *response;
    const char *name;
    
    /* Log entry to the command handler */
    plugin_log(cmd->plugin, LOG_DBG, "Hello command received, parsing parameters...");

    /* Parse parameters: optional "name" parameter */
    if (!param(cmd, buf, params,
              p_opt("name", param_string, &name),
              NULL)) {
        plugin_log(cmd->plugin, LOG_BROKEN, "Parameter parsing failed!");
        return command_param_failed();
    }

    /* If no name provided, use "world" */
    if (!name) {
        plugin_log(cmd->plugin, LOG_DBG, "No name provided, using default 'world'");
        name = "world";
    } else {
        plugin_log(cmd->plugin, LOG_DBG, "Name parameter: %s", name);
    }

    /* Log that we're creating the response */
    plugin_log(cmd->plugin, LOG_DBG, "Creating success response...");

    /* Create success response */
    response = jsonrpc_stream_success(cmd);
    if (!response) {
        plugin_log(cmd->plugin, LOG_BROKEN, "Failed to create JSON response stream!");
        return command_fail(cmd, LIGHTNINGD, "Internal error: couldn't create response");
    }

    /* Add the greeting to the response */
    plugin_log(cmd->plugin, LOG_DBG, "Adding greeting to response...");
    json_add_string(response, "greeting", tal_fmt(cmd, "Hello, %s!", name));

    /* Log before returning the response */
    plugin_log(cmd->plugin, LOG_DBG, "Returning successful response with greeting");

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