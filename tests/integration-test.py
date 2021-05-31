#!/usr/bin/env -S python3 -u
import atexit
import logging
import os
import signal
import subprocess
import time
from shutil import rmtree
from subprocess import Popen

import jsonrpc_requests
import grpc
from retrying import retry

from admin_pb2_grpc import AdminStub
from admin_pb2 import PingRequest, ChannelNewRequest, ChannelCloseRequest, Void, InvoiceNewRequest, PaymentSendRequest, Payment, PeerConnectRequest

processes: [Popen] = []
OUTPUT_DIR = 'test-output'
NUM_PAYMENTS = 200
WAIT_TIMEOUT = 10
CHANNEL_BALANCE_SYNC_INTERVAL = 50
CHANNEL_VALUE_SAT = 10_000_000
PAYMENT_MSAT = 2_000_000
SLEEP_ON_FAIL = False
USE_RELEASE_BINARIES = False
SIGNER = "rls"

logger = logging.getLogger()


def kill_procs():
    global processes
    for p in processes:
        p.send_signal(signal.SIGTERM)


class Bitcoind(jsonrpc_requests.Server):
    def __init__(self, name, url, **kwargs):
        self.name = name
        self.mine_address = None
        super().__init__(url, **kwargs)

    def wait_for_ready(self):
        timeout = 5
        request_exception = None
        while timeout > 0:
            try:
                self.getblockchaininfo()
                break
            except Exception as e:
                request_exception = e
                time.sleep(1)
                timeout -= 1
        if timeout <= 0:
            if request_exception:
                raise request_exception
            raise Exception('Timeout')

    def setup(self):
        self.createwallet('default')
        # unload and reload with autoload, in case dev wants to play with it later
        self.unloadwallet('default')
        self.loadwallet('default', True)
        self.mine_address = self.getnewaddress()

    def mine(self, count=1):
        self.generatetoaddress(count, self.mine_address)


@retry(stop_max_attempt_number=50, wait_fixed=100)
def node(url):
    channel = grpc.insecure_channel(url)
    stub = AdminStub(channel)
    stub.Ping(PingRequest(message="hello"))
    return stub


# retry every 0.1 seconds until WAIT_TIMEOUT seconds have passed
def wait_until(name, func):
    logger.debug(f'wait for {name}')
    timeout = WAIT_TIMEOUT * 10
    exc = None
    while timeout > 0:
        try:
            if func():
                break
        except Exception as e:
            exc = e
        time.sleep(0.1)
        timeout -= 1
    if timeout <= 0:
        if SLEEP_ON_FAIL:
            print(f'failed with exc={exc}')
            time.sleep(1000000)
        if exc:
            raise exc
        raise Exception('Timeout')
    logger.debug(f'done {name}')


def run():
    # ensure we sync after the last payment
    assert NUM_PAYMENTS % CHANNEL_BALANCE_SYNC_INTERVAL == 0

    atexit.register(kill_procs)
    rmtree(OUTPUT_DIR, ignore_errors=True)
    os.mkdir(OUTPUT_DIR)
    print('Starting bitcoind')
    btc = start_bitcoind()

    print('Starting nodes')
    alice = start_node(1)
    bob = start_node(2)
    charlie = start_node(3)

    print('Generate initial blocks')
    btc.mine(110)
    balance = btc.getbalance()
    assert balance > 0

    alice_id = alice.NodeInfo(Void()).node_id
    bob_id = bob.NodeInfo(Void()).node_id
    charlie_id = charlie.NodeInfo(Void()).node_id

    print('Create channel alice -> bob')
    try:
        alice.PeerConnect(PeerConnectRequest(node_id=bob_id, address=f'127.0.0.1:{bob.lnport}'))
        alice.ChannelNew(ChannelNewRequest(node_id=bob_id, value_sat=CHANNEL_VALUE_SAT, is_public=True))
    except Exception as e:
        print(e)
        raise

    print('Create channel bob -> charlie')
    try:
        bob.PeerConnect(PeerConnectRequest(node_id=charlie_id, address=f'127.0.0.1:{charlie.lnport}'))
        bob.ChannelNew(ChannelNewRequest(node_id=charlie_id, value_sat=CHANNEL_VALUE_SAT, is_public=True))
    except Exception as e:
        print(e)
        raise

    wait_until('channel at bob', lambda: bob.ChannelList(Void()).channels[0])
    wait_until('channel at charlie', lambda: charlie.ChannelList(Void()).channels[0])

    assert alice.ChannelList(Void()).channels[0].is_pending
    assert bob.ChannelList(Void()).channels[0].is_pending
    assert charlie.ChannelList(Void()).channels[0].is_pending

    btc.mine(6)

    def channel_active():
        btc.mine(1)
        return (not alice.ChannelList(Void()).channels[0].is_pending and
                not bob.ChannelList(Void()).channels[0].is_pending and
                not bob.ChannelList(Void()).channels[1].is_pending and
                not charlie.ChannelList(Void()).channels[0].is_pending and
                alice.ChannelList(Void()).channels[0].is_active and
                bob.ChannelList(Void()).channels[0].is_active and
                bob.ChannelList(Void()).channels[1].is_active and
                charlie.ChannelList(Void()).channels[0].is_active)

    wait_until('active at both', channel_active)

    def best_block_sync(node):
        return node.NodeInfo(Void()).best_block_hash[::-1].hex() == btc.getblockchaininfo()['bestblockhash']

    wait_until('alice synced', lambda: best_block_sync(alice))
    wait_until('bob synced', lambda: best_block_sync(bob))
    wait_until('charlie synced', lambda: best_block_sync(charlie))

    assert alice.ChannelList(Void()).channels[0].is_active
    assert bob.ChannelList(Void()).channels[0].is_active

    for i in range(1, NUM_PAYMENTS + 1):
        print(f'Pay invoice {i}')
        invoice = charlie.InvoiceNew(InvoiceNewRequest(value_msat=PAYMENT_MSAT)).invoice
        alice.PaymentSend(PaymentSendRequest(invoice=invoice))

        if i % CHANNEL_BALANCE_SYNC_INTERVAL == 0:
            print('*** SYNC TO CHANNEL BALANCE')
            # check within 0.5%, due to fees
            wait_until('channel balance alice',
                       lambda: assert_equal_delta(CHANNEL_VALUE_SAT * 1000 - alice.ChannelList(Void()).channels[0].outbound_msat,
                                                  i * PAYMENT_MSAT))
            wait_until('channel balance charlie',
                       lambda: assert_equal_delta(charlie.ChannelList(Void()).channels[0].outbound_msat,
                                                  i * PAYMENT_MSAT))

    def check_payments():
        payment_list = alice.PaymentList(Void())
        assert len(payment_list.payments) == NUM_PAYMENTS
        for payment in payment_list.payments:
            assert payment.is_outbound
            assert payment.status == Payment.PaymentStatus.Succeeded, payment
        return True

    wait_until('check payments', check_payments)

    def wait_received(node_id, minimum=1):
        btc.mine(2)
        label = f'sweep-{node_id.hex()}'
        received = int(btc.getreceivedbylabel(label) * 100000000)
        return received >= minimum

    def get_swept_value(node_id):
        return int(btc.getreceivedbylabel(f'sweep-{node_id.hex()}') * 100000000)

    print('Closing alice - bob')
    alice_channel = alice.ChannelList(Void()).channels[0]
    alice.ChannelClose(ChannelCloseRequest(channel_id=alice_channel.channel_id))

    wait_until('alice sweep', lambda: wait_received(alice_id))
    wait_until('bob sweep', lambda: wait_received(bob_id))
    alice_sweep = int(get_swept_value(alice_id))
    bob_sweep = int(get_swept_value(bob_id))
    assert_equal_delta(CHANNEL_VALUE_SAT - (NUM_PAYMENTS * PAYMENT_MSAT) / 1000 - 1000, alice_sweep)
    assert_equal_delta((NUM_PAYMENTS * PAYMENT_MSAT) / 1000 - 1000, bob_sweep)

    print('Force closing bob - charlie at charlie')
    charlie_channel = charlie.ChannelList(Void()).channels[0]
    charlie.ChannelClose(ChannelCloseRequest(channel_id=charlie_channel.channel_id, is_force=True))
    wait_until('bob sweep', lambda: wait_received(bob_id, minimum=bob_sweep + 1))
    bob_sweep = int(get_swept_value(bob_id))
    # bob, as router, is flat except for fees
    assert_equal_delta(CHANNEL_VALUE_SAT - 2000, bob_sweep)

    # charlie should not have been able to sweep yet
    charlie_sweep = int(get_swept_value(charlie_id))
    assert charlie_sweep == 0

    # charlie eventually sweeps their payments
    wait_until('charlie sweep', lambda: wait_received(charlie_id))
    charlie_sweep = int(get_swept_value(charlie_id))
    assert_equal_delta((NUM_PAYMENTS * PAYMENT_MSAT) / 1000 - 1000, charlie_sweep)

    print('Done')


def assert_equal_delta(a, b):
    if a < b * 0.995 or a > b * 1.005:
        raise AssertionError(f'value out of range {a} vs {b}')
    return True


def start_bitcoind():
    global processes

    btc_log = open(OUTPUT_DIR + '/btc.log', 'w')
    btc_proc = Popen([
        # 'strace', '-o', '/tmp/out', '-s', '10000', '-f',
        'bitcoind', '--regtest', '--fallbackfee=0.0000001',
        '--rpcuser=user', '--rpcpassword=pass',
        f'--datadir={OUTPUT_DIR}'], stdout=btc_log)
    processes.append(btc_proc)
    btc = Bitcoind('btc-regtest', 'http://user:pass@localhost:18443')
    btc.wait_for_ready()
    btc.setup()
    return btc


def start_node(n):
    global processes

    stdout_log = open(OUTPUT_DIR + f'/node{n}.log', 'w')
    optimization = 'release' if USE_RELEASE_BINARIES else 'debug'
    lnrod = f'target/{optimization}/lnrod'
    p = Popen([lnrod,
               '--regtest',
               '--datadir', f'{OUTPUT_DIR}/data{n}',
               '--signer', SIGNER,
               '--rpcport', str(8800 + n), '--lnport', str(9900 + n)],
              stdout=stdout_log, stderr=subprocess.STDOUT)
    processes.append(p)
    lnrod = node(f'localhost:{8800 + n}')
    lnrod.lnport = 9900 + n
    return lnrod


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run()
