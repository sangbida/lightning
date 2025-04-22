# Randpay Plugin

The Randpay plugin probes the Lightning Network by randomly selecting a node and attempting a payment to it.
The plugin uses a bogus payment hash, which ensures that no funds are actually transferred,
though HTLCs are temporarily created to test channel liquidity and connectivity.

## Status Responses
- RED = when any hop (including the final one) is unreachable (node or channel down)

- YELLOW = when all nodes were reachable, but the payment failed for another reason
(e.g. liquidity, CLTV expiry etc)

- GREEN = we reached the destination and it responded

## Usage:
```bash
lightning-cli ranpday amount_msat
```
- `amount_msat` is the amount in millisatoshis to use for the probe payment

## Testing 
This plugin includes integration tests rather than unit tests. Since the functionality heavily depends
on interactions with other RPC commands, integration tests provide more realistic coverage without the 
need to mock several components. 

For macOS, Run the tests using:
```bash
poetry run pytest tests/plugins/test_randpay.py
```
Ensure that the locally built version of lightningd is being used to run the tests,
on macOS can default to the Homebrew version of lightningd.

## Implementation Details
The plugin follows this sequence of operations:
```
listnodes -> getroute -> sendpay -> waitsendpay 
```
- `listnodes` - Retrieves a list of nodes in the network
- Randomly selects a destination node
- `getroute` - Finds a route to the selected node
- `sendpay` - Initiates the payment with a bogus payment hash
- `waitsendpay` - Waits for and analyzes the payment result


## Assumptions and Tradeoffs 

- Input Validation: The plugin performs basic input validation but 
relies on the RPC system for handling invalid inputs (non-integers, negative values, etc.).
- keysend vs getroute + sendpay: This is being used so htlcs are created but no funds are transferred. 
- listpeers vs nodes: The plugin uses listnodes rather than listpeers because listpeers could include nodes that have
established connections but haven't broadcast node announcements to the network yet.
- getroute can mask different types of failures. For example if there is a channel liquidity constraint 
on one channel (set by a htlc min) it returns a "Can not find a route error",
it also returns the same error if on of the nodes are offline. 
- The plugin excludes the local node from the list of potential payment destinations.
