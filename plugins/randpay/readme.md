Randpay Plugin

RED = any hop (including the final one) is unreachable (node or channel down)

YELLOW = all nodes were reachable, but the payment failed for another reason (e.g. liquidity, fee mismatch, CLTV expiry)

GREEN = we reached the destination and it responded, even with a bogus hash


Usage

Testing 
This plugin has integration tests, since it's so heavily reliant 
Implementation 


Assumptions and Tradeoffs 

- We're not doing a very thorough input validation, we do test for 
unusual inputs but we're okay to surface these up with their error code since the prc system seems to performing input validations for non integer, 
including negative integer, inputs.
- If there is an error due to the plugin not being able to find a route, for example due to channel liquidity issues, we show an ERROR instead of RED.