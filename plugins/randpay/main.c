#include "config.h"
#include <ccan/tal/str/str.h>
#include <ccan/array_size/array_size.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include "node_status.h"


/* Plugin initialization */
static const char *init(struct command *cmd,
                       const char *buf UNUSED,
                       const jsmntok_t *config UNUSED)
{
    /* Log a message to confirm plugin initialization */
    plugin_log(cmd->plugin, LOG_INFORM, "Randpay plugin initialized");
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