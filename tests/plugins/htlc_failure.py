#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, plugin, **kwargs):
    plugin.log("Failing htlc on purpose")
    plugin.log("onion: %r" % (onion))
    # WIRE_TEMPORARY_CHANNEL_FAILURE 0x1007
    return {"result": "fail", "failure_message": "1007"}


plugin.run()
