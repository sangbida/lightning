//
// Created by Jake Dean on 18/4/2025.
//

#ifndef RANDPAY_H
#define RANDPAY_H

#include <plugins/libplugin.h>

enum return_value
{
	RED,
	YELLOW,
	GREEN,
};

const char *enum_to_string(enum return_value val);

/* Initialize plugin and get local node ID */
const char *init(struct command *cmd, const char *buf, const jsmntok_t *config);

/* Command handler for getting a random node */
struct command_result *json_randpay(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params);

static const struct plugin_command commands[] = {
    {
        "randpay",
        json_randpay,
    }
};

#endif //RANDPAY_H
