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
from admin_pb2 import PingRequest, ChannelNewRequest, Void, InvoiceNewRequest, PaymentSendRequest, Payment, PeerConnectRequest

processes: [Popen] = []
OUTPUT_DIR = 'test-output'
ALICE_LNPORT = '9901'
BOB_LNPORT = '9902'
NUM_PAYMENTS = 500
CHANNEL_BALANCE_SYNC_INTERVAL = 100
CHANNEL_VALUE_SAT = 10_000_000
PAYMENT_MSAT = 2_000_000
SLEEP_ON_FAIL = False
USE_RELEASE_BINARIES = False

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


def wait_until(name, func):
    logger.debug(f'wait for {name}')
    timeout = 100  # 10 seconds
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
    global processes

    atexit.register(kill_procs)
    rmtree(OUTPUT_DIR, ignore_errors=True)
    os.mkdir(OUTPUT_DIR)
    print('Starting bitcoind')
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

    print('Starting alice and bob')
    alice_stdout_log = open(OUTPUT_DIR + '/node1.log', 'w')
    optimization = 'release' if USE_RELEASE_BINARIES else 'debug'
    lnrod = f'target/{optimization}/lnrod'
    alice_proc = Popen([lnrod,
                        '--regtest',
                        '--datadir', OUTPUT_DIR + '/data1',
                        '--rpcport', '8801', '--lnport', ALICE_LNPORT],
                       stdout=alice_stdout_log, stderr=subprocess.STDOUT)
    processes.append(alice_proc)

    bob_stdout_log = open(OUTPUT_DIR + '/node2.log', 'w')
    bob_proc = Popen([lnrod,
                      '--regtest',
                      '--datadir', OUTPUT_DIR + '/data2',
                      '--rpcport', '8802', '--lnport', BOB_LNPORT],
                     stdout=bob_stdout_log, stderr=subprocess.STDOUT)
    processes.append(bob_proc)

    print('Connect to alice and bob')
    alice = node('localhost:8801')
    bob = node('localhost:8802')

    print('Generate initial blocks')
    btc.mine(110)
    balance = btc.getbalance()
    assert balance > 0

    alice_id = alice.NodeInfo(Void()).node_id
    bob_id = bob.NodeInfo(Void()).node_id

    print('Create channel alice -> bob')
    try:
        alice.PeerConnect(PeerConnectRequest(node_id=bob_id, address=f'127.0.0.1:{BOB_LNPORT}'))
        alice.ChannelNew(ChannelNewRequest(node_id=bob_id, value_sat=CHANNEL_VALUE_SAT))
    except Exception as e:
        print(e)
        raise

    wait_until('channel at bob', lambda: bob.ChannelList(Void()).channels[0])

    assert alice.ChannelList(Void()).channels[0].is_pending
    assert bob.ChannelList(Void()).channels[0].is_pending

    btc.mine(6)

    def channel_active():
        btc.mine(1)
        return (not alice.ChannelList(Void()).channels[0].is_pending and
                not bob.ChannelList(Void()).channels[0].is_pending and
                alice.ChannelList(Void()).channels[0].is_active and
                bob.ChannelList(Void()).channels[0].is_active)

    wait_until('active at both', channel_active)

    assert alice.ChannelList(Void()).channels[0].is_active
    assert bob.ChannelList(Void()).channels[0].is_active

    # ensure we sync after the last payment
    assert NUM_PAYMENTS % CHANNEL_BALANCE_SYNC_INTERVAL == 0

    for i in range(1, NUM_PAYMENTS + 1):
        print(f'Pay invoice {i}')
        invoice = bob.InvoiceNew(InvoiceNewRequest(value_msat=PAYMENT_MSAT)).invoice
        alice.PaymentSend(PaymentSendRequest(invoice=invoice))

        if i % CHANNEL_BALANCE_SYNC_INTERVAL == 0:
            print('*** SYNC TO CHANNEL BALANCE')
            wait_until('channel balance alice', lambda: alice.ChannelList(Void()).channels[0].outbound_msat == CHANNEL_VALUE_SAT * 1000 - i * PAYMENT_MSAT)
            wait_until('channel balance bob', lambda: bob.ChannelList(Void()).channels[0].outbound_msat == i * PAYMENT_MSAT)

            print(alice.ChannelList(Void()).channels[0].outbound_msat, bob.ChannelList(Void()).channels[0].outbound_msat)

    def check_payments():
        payment_list = alice.PaymentList(Void())
        assert len(payment_list.payments) == NUM_PAYMENTS
        for payment in payment_list.payments:
            assert payment.is_outbound
            assert payment.status == Payment.PaymentStatus.Succeeded, payment
        return True
    wait_until('check payments', check_payments)
    print('Done')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run()
