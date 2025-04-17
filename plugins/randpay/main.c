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
    
    /* Parse parameters: optional "name" parameter */
    if (!param(cmd, buf, params,
              p_opt("name", param_string, &name),
              NULL))
        return command_param_failed();

    /* If no name provided, use "world" */
    if (!name)
        name = "world";

    /* Create success response */
    response = jsonrpc_stream_success(cmd);
    json_add_string(response, "greeting", tal_fmt(cmd, "Hello, %s!", name));
    
    return command_success(cmd, response->jout);
}

/* Array of commands we provide */
static const struct plugin_command commands[] = {
    {
        "hello",           /* Command name */
        json_hello,        /* Command handler */
        "Say hello",       /* Command description */
        "hello [name]",    /* Command usage */
        false             /* Not a developer command */
    }
};

/* Plugin initialization */
static const char *init(struct command *cmd,
                       const char *buf UNUSED,
                       const jsmntok_t *config UNUSED)
{
    /* Nothing to initialize */
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