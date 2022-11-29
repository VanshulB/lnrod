#!/usr/bin/env -S python3 -u
import atexit
import logging
import os
import signal
import subprocess
import argparse

import sys
import time
from shutil import rmtree
from subprocess import Popen, call

import jsonrpc_requests
import grpc
from retrying import retry

from admin_pb2_grpc import AdminStub
from admin_pb2 import PingRequest, ChannelNewRequest, ChannelCloseRequest, Void, InvoiceNewRequest, PaymentSendRequest, Payment, PeerConnectRequest

processes: [Popen] = []
OUTPUT_DIR = 'test-output'
NUM_PAYMENTS = 250
WAIT_TIMEOUT = 10
CHANNEL_BALANCE_SYNC_INTERVAL = 50
CHANNEL_VALUE_SAT = 10_000_000
EXPECTED_FEE_SAT = 1458
PAYMENT_MSAT = 4_000_000  # FIXME 2_000_000 fails with dust limit policy violation
DEBUG_ON_FAIL = os.environ.get('DEBUG_ON_FAIL', '0') == '1'
USE_RELEASE_BINARIES = False
OPTIMIZATION = 'release' if USE_RELEASE_BINARIES else 'debug'
DEV_MODE = False
DEV_BINARIES_PATH = f'../vls/target/{OPTIMIZATION}'

# options: test, vls, vls-local, vls2-null, vls2-grpc
SIGNER = os.environ.get("SIGNER", "vls2-null")

logger = logging.getLogger()

os.environ['RUST_BACKTRACE'] = "1"

# we want to manage the allowlist ourselves, don't let a stray env var confuse us
os.environ.pop('ALLOWLIST', None)


def kill_procs():
    global processes
    for p in processes:
        p.send_signal(signal.SIGTERM)
    for p in processes:
        p.wait()


def stop_proc(p):
    p.send_signal(signal.SIGTERM)
    p.wait()


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
def grpc_client(url):
    channel = grpc.insecure_channel(url)
    stub = AdminStub(channel)
    stub.Ping(PingRequest(message="hello"), timeout=1)
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
        if DEBUG_ON_FAIL:
            print(f'failed with exc={exc}')
            import pdb; pdb.set_trace()
        if exc:
            raise exc
        raise Exception('Timeout')
    logger.debug(f'done {name}')


def run(test_disaster):
    # ensure we sync after the last payment
    assert NUM_PAYMENTS % CHANNEL_BALANCE_SYNC_INTERVAL == 0
    assert not test_disaster or SIGNER == 'vls2-grpc', "test_disaster only works with vls2-grpc"

    atexit.register(kill_procs)
    rmtree(OUTPUT_DIR, ignore_errors=True)
    os.mkdir(OUTPUT_DIR)
    print('Starting bitcoind')
    btc, btc_proc = start_bitcoind()

    if SIGNER == 'vls':
        print('Starting signers')
        alice_signer = start_vlsd(1)
        bob_signer = start_vlsd(2)
        charlie_signer = start_vlsd(3)

    print('Starting nodes')
    alice, _, _ = start_node(1)
    bob, _, _ = start_node(2)
    charlie, charlie_proc, charlie_proc1 = start_node(3)

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

    # we have to wait here to prevent a race condition on the bitcoin wallet UTXOs
    # TODO UTXO locking
    wait_until('channel at bob', lambda: bob.ChannelList(Void()).channels[0].is_pending)
    wait_until('channel at alice', lambda: alice.ChannelList(Void()).channels[0].is_pending)

    print('Create channel bob -> charlie')
    try:
        bob.PeerConnect(PeerConnectRequest(node_id=charlie_id, address=f'127.0.0.1:{charlie.lnport}'))
        bob.ChannelNew(ChannelNewRequest(node_id=charlie_id, value_sat=CHANNEL_VALUE_SAT, is_public=True))
    except Exception as e:
        print(e)
        raise

    wait_until('channel at charlie', lambda: charlie.ChannelList(Void()).channels[0].is_pending)

    btc.mine(6)

    def channel_active():
        btc.mine(1)
        alice_chans = alice.ChannelList(Void())
        bob_chans = bob.ChannelList(Void())
        charlie_chans = charlie.ChannelList(Void())
        return (not alice_chans.channels[0].is_pending and
                not bob_chans.channels[0].is_pending and
                not bob_chans.channels[1].is_pending and
                not charlie_chans.channels[0].is_pending and
                alice_chans.channels[0].is_active and
                bob_chans.channels[0].is_active and
                bob_chans.channels[1].is_active and
                charlie_chans.channels[0].is_active)

    wait_until('active at both', channel_active)

    def best_block_sync(node):
        return node.NodeInfo(Void()).best_block_hash[::-1].hex() == btc.getblockchaininfo()['bestblockhash']

    wait_until('alice synced', lambda: best_block_sync(alice))
    wait_until('bob synced', lambda: best_block_sync(bob))
    wait_until('charlie synced', lambda: best_block_sync(charlie))

    assert alice.ChannelList(Void()).channels[0].is_active
    assert bob.ChannelList(Void()).channels[0].is_active

    print(f'Alice initial balance {alice.ChannelList(Void()).channels[0].outbound_msat}')
    print(PAYMENT_MSAT * CHANNEL_BALANCE_SYNC_INTERVAL)

    for i in range(1, NUM_PAYMENTS + 1):
        print(f'Pay invoice {i}')
        invoice = charlie.InvoiceNew(InvoiceNewRequest(value_msat=PAYMENT_MSAT)).invoice
        alice.PaymentSend(PaymentSendRequest(invoice=invoice))

        if i % CHANNEL_BALANCE_SYNC_INTERVAL == 0:
            def check_payments():
                payments = alice.PaymentList(Void()).payments
                assert len(payments) == i
                return all(p.status == Payment.PaymentStatus.Succeeded for p in payments)

            print('*** SYNC TO PAYMENT STATUS')
            wait_until('payments succeed', check_payments)

            print('*** CHECK CHANNEL BALANCE')

            wait_until('channel balance alice',
                       lambda: assert_equal_delta(CHANNEL_VALUE_SAT * 1000 - EXPECTED_FEE_SAT * 1000 - alice.ChannelList(Void()).channels[0].outbound_msat,
                                                  i * PAYMENT_MSAT))
            wait_until('channel balance charlie',
                       lambda: assert_equal_delta(charlie.ChannelList(Void()).channels[0].outbound_msat,
                                                  max(0, i * PAYMENT_MSAT)))

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

    if test_disaster:
        print('Disaster recovery at charlie')
        stop_proc(charlie_proc)
        stop_proc(charlie_proc1)
        destination = btc.getnewaddress(label=f"sweep-{charlie_id.hex()}")
        stdout_log = open(OUTPUT_DIR + f'/vls3-recover.log', 'w')
        vlsd = DEV_BINARIES_PATH + '/vlsd2' if DEV_MODE else 'vlsd2'
        p = call([vlsd,
                  '--network=regtest',
                  '--datadir', f'{OUTPUT_DIR}/vls3',
                  '--recover-rpc', 'http://user:pass@localhost:18443',
                  '--recover-close', destination],
                 stdout=stdout_log,
                 stderr=subprocess.STDOUT)
        assert p == 0
        print('Sweep at charlie')
        btc.mine(145)
        p = call([vlsd,
                  '--network=regtest',
                  '--datadir', f'{OUTPUT_DIR}/vls3',
                  '--recover-rpc', 'http://user:pass@localhost:18443',
                  '--recover-close', destination],
                 stdout=stdout_log,
                 stderr=subprocess.STDOUT)
        assert p == 0
        print('Swept at charlie')
    else:
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
    return btc, btc_proc


def start_vlsd(n):
    global processes

    stdout_log = open(OUTPUT_DIR + f'/vls{n}.log', 'w')
    vlsd = DEV_BINARIES_PATH + '/vlsd' if DEV_MODE else 'vlsd'
    p = Popen([vlsd,
               # '--log-level-console=TRACE',
               '--network=regtest',
               '--datadir', f'{OUTPUT_DIR}/vls{n}',
               '--port', str(7700 + n)],
              stdout=stdout_log, stderr=subprocess.STDOUT)
    processes.append(p)
    # return grpc_client(f'localhost:{7700 + n}')
    time.sleep(1)
    return p


def start_vlsd2(n):
    global processes

    stdout_log = open(OUTPUT_DIR + f'/vls{n}.log', 'w')
    vlsd = DEV_BINARIES_PATH + '/vlsd2' if DEV_MODE else 'vlsd2'
    p = Popen([vlsd,
               # '--log-level-console=TRACE',
               '--network=regtest',
               '--datadir', f'{OUTPUT_DIR}/vls{n}',
               '--connect', f"http://127.0.0.1:{str(7700 + n)}"],
              stdout=stdout_log, stderr=subprocess.STDOUT)
    processes.append(p)
    time.sleep(1)
    return p


def start_node(n):
    global processes

    stdout_log = open(OUTPUT_DIR + f'/node{n}.log', 'w')
    optimization = 'release' if USE_RELEASE_BINARIES else 'debug'
    lnrod = f'target/{optimization}/lnrod'
    p = Popen([lnrod,
              # '--log-level-console=TRACE',
               '--regtest',
               '--datadir', f'{OUTPUT_DIR}/data{n}',
               '--signer', SIGNER,
               '--vlsport', str(7700 + n),
               '--rpcport', str(8800 + n),
               '--lnport', str(9900 + n)],
              stdout=stdout_log, stderr=subprocess.STDOUT)
    processes.append(p)
    time.sleep(2)  # FIXME allow gRPC to function before signer connects so we can ping instead of randomly waiting
    p2 = None
    if SIGNER == 'vls2-grpc':
        p2 = start_vlsd2(n)

    lnrod = grpc_client(f'localhost:{8800 + n}')
    lnrod.lnport = 9900 + n
    return lnrod, p, p2


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", help=f"use VLS binaries from {DEV_BINARIES_PATH} instead of $PATH", action="store_true")
    parser.add_argument("--test-disaster", help=f"test disaster recovery", action="store_true")
    args = parser.parse_args()
    if args.dev:
        DEV_MODE = True
    run(test_disaster=args.test_disaster)
