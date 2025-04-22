#include "config.h"
#include <ccan/tal/str/str.h>
#include <ccan/array_size/array_size.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include "randpay.h"

int main(int argc, char *argv[])
{
    setup_locale();
    plugin_main(argv,
                init,
                NULL,
                PLUGIN_STATIC,
                true,
                NULL,
                commands,
                ARRAY_SIZE(commands),
                NULL, 0,
                NULL, 0,
                NULL, 0,
                NULL);

    return 0;
}