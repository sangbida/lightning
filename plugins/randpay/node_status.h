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

/* Command handler for getting a random node */
struct command_result *json_get_random_node(struct command *cmd,
                                           const char *buf,
                                           const jsmntok_t *params);

#endif //NODE_STATUS_H
