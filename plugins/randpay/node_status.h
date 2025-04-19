//
// Created by Jake Dean on 18/4/2025.
//

#ifndef NODE_STATUS_H
#define NODE_STATUS_H

#include <plugins/libplugin.h>

enum return_value
{
	RED,
	YELLOW,
	GREEN,
};

const char *enum_to_string(enum return_value val);
struct command_result *json_randpay(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params);

static const struct plugin_command commands[] = {
    {
        "randpay", /* command name */
        json_randpay, /* handler function */
        NULL, NULL,        /* not deprecated: depr_start, depr_end = NULL */
        false              /* dev_only: false */
    }
};

/* Command handler for getting a random node */


#endif //NODE_STATUS_H
