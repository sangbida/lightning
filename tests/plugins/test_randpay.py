import os
import pytest
import json
from pyln.testing.fixtures import *  # noqa: F403, F401
from pyln.client import RpcError
import time

def test_randpay_missing_amount(node_factory):
    l1 = node_factory.get_node()

    plugins = l1.rpc.plugin_list()
    assert any(p['name'].endswith('cln-randpay') for p in plugins['plugins']), "cln-randpay plugin not loaded"

    response = l1.rpc.randpay(amount_msat=None)

    assert 'status' in response
    assert response['status'] == 'ERROR'
    assert 'error' in response
    assert response['error'] == 'A positive amount_msat parameter is required'

# def test_randpay_parameter_validation(node_factory):
#     l1 = node_factory.get_node()
#
#     response = l1.rpc.randpay()
#     assert response['status'] == 'ERROR'
#     assert 'amount_msat parameter is required' in response['error']
#
#     response = l1.rpc.randpay(amount_msat=-1000)
#     assert response['status'] == 'ERROR'
#     assert 'amount_msat must be positive' in response['error']

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

def test_randpay_insufficient_liquidity(node_factory):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=100_000, wait_for_announce=True)

    # Drain liquidity from l2->l3 by sending from l3 to l2
    l3.pay(l2, 80_000)

    # Verify payment succeeded (l2 received the funds)
    assert l2.rpc.listpeers(l3.info['id'])['peers'][0]['channels'][0]['to_us_msat'] > 80_000 * 1000

    # Try to send a payment requiring more liquidity than available
    response = l1.rpc.randpay(amount_msat=100_000)

    # Should return YELLOW for liquidity issues
    assert response['status'] == 'YELLOW'
