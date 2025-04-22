import os
import pytest
import json
from pyln.testing.fixtures import *  # noqa: F403, F401
from pyln.client import RpcError
import time
import random

def test_randpay_missing_amount(node_factory):
    l1 = node_factory.get_node()

    plugins = l1.rpc.plugin_list()
    assert any(p['name'].endswith('cln-randpay') for p in plugins['plugins']), "cln-randpay plugin not loaded"

    response = l1.rpc.randpay(amount_msat=None)

    assert 'status' in response
    assert response['status'] == 'ERROR'
    assert 'error' in response
    assert response['error'] == 'A positive amount_msat parameter is required'


def test_randpay_no_nodes(node_factory):
    l1 = node_factory.get_node()
    response = l1.rpc.randpay(amount_msat=1000)
    assert response['status'] == 'ERROR'
    assert 'No nodes found' in response['error'] or 'No valid random node' in response['error']

def test_randpay_no_route(node_factory):
    l1, l2 = node_factory.get_nodes(2)

    # Call randpay - should result in RED because no route available
    response = l1.rpc.randpay(amount_msat=1000)
    assert response['status'] == 'ERROR'
    assert response['error'] == 'No nodes found in network'

def test_randpay_direct_payment(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)
    response = l1.rpc.randpay(amount_msat=1000)
    assert response['status'] == 'GREEN'

def test_randpay_mpp_payment(node_factory):
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    l1.connect(l2)
    l1.connect(l3)
    l2.connect(l4)
    l3.connect(l4)

    l1.fundchannel(l2, 100_000)
    l1.fundchannel(l3, 100_000)
    l2.fundchannel(l4, 100_000)
    l3.fundchannel(l4, 100_000)

    time.sleep(1)
    response = l1.rpc.randpay(amount_msat=150_000)
    assert response['status'] == 'GREEN'

def test_randpay_node_offline(node_factory):
    """Test randpay when destination node is unreachable (RED status)"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)
    
    # Disconnect l2 from l3 to simulate unreachable node
    l2.stop()
    
    time.sleep(1)
    response = l1.rpc.randpay(amount_msat=1000)
    
    # Should return RED for unreachable node
    assert response['status'] == 'RED'
    assert response['error'] == 'Could not find a route'
def test_randpay_red_with_failure_plugin(node_factory, bitcoind):
    """Test RED status by forcing WIRE_TEMPORARY_NODE_FAILURE using the fail_htlcs plugin"""

    # Create a three-node network with the failure plugin on the middle node
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')

    # Verify the plugin file exists
    assert os.path.exists(plugin_path), f"Plugin file not found: {plugin_path}"

    # Create the network with the plugin loaded on the middle node
    l1, l2, l3 = node_factory.line_graph(3,
                                         opts=[{},
                                               {'plugin': plugin_path},
                                               {}],
                                         wait_for_announce=True)

    # Ensure channels are active
    bitcoind.generate_block(6)
    for node in [l1, l2, l3]:
        node.daemon.wait_for_logs([r"update for channel .* now ACTIVE"])

    # Try multiple payments to increase the chance of hitting the failing node
    red_found = False
    for i in range(5):
        try:
            response = l1.rpc.randpay(amount_msat=1000)
            print(f"Attempt {i+1} result: {response}")
            if response['status'] == 'RED':
                red_found = True
                break
        except Exception as e:
            print(f"Exception on attempt {i+1}: {e}")
        time.sleep(1)

    # Check if we found a RED status
    assert red_found, "Failed to get RED status after multiple attempts"

def test_randpay_yellow_plugin(node_factory, bitcoind):
    """Test RED status by forcing WIRE_TEMPORARY_NODE_FAILURE using the fail_htlcs plugin"""

    # Create a three-node network with the failure plugin on the middle node
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/htlc_failure.py')

    # Verify the plugin file exists
    assert os.path.exists(plugin_path), f"Plugin file not found: {plugin_path}"

    # Create the network with the plugin loaded on the middle node
    l1, l2, l3 = node_factory.line_graph(3,
                                         opts=[{},
                                               {'plugin': plugin_path},
                                               {}],
                                         wait_for_announce=True)

    # Ensure channels are active
    bitcoind.generate_block(6)
    for node in [l1, l2, l3]:
        node.daemon.wait_for_logs([r"update for channel .* now ACTIVE"])

    # Try multiple payments to increase the chance of hitting the failing node
    yellow_found = False
    for i in range(5):
        try:
            response = l1.rpc.randpay(amount_msat=1000)
            print(f"Attempt {i+1} result: {response}")
            if response['status'] == 'YELLOW':
                yellow_found = True
                break
        except Exception as e:
            print(f"Exception on attempt {i+1}: {e}")
        time.sleep(1)

    # Check if we found a YELLOW status
    assert yellow_found, "Failed to get YELLOW status after multiple attempts"