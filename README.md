# lnrod

A node implementation using LDK.

## Installation
```
git clone git@gitlab.com:lightning-signer/lnrod.git
```

## Usage
```
cd lnrod

cargo build

# Add bitcoind config to ~/.bitcoin/bitcoin.conf:
rpcuser=user
rpcpassword=pass
fallbackfee=0.0000001

# Start bitcoind in regtest mode
bitcoind -regtest -daemon

# Create wallet, unload and reload w/ autoload
bitcoin-cli --regtest createwallet default
bitcoin-cli --regtest unloadwallet default
bitcoin-cli --regtest loadwallet default true

a_mine=`bitcoin-cli -regtest getnewaddress` && echo $a_mine

# Advance 101 blocks
bitcoin-cli -regtest generatetoaddress 101 $a_mine

alias lnrod=target/debug/lnrod
alias lnrcli=target/debug/lnrcli

lnrod --regtest
lnrod --regtest --datadir ./data2 --rpcport 8802 --lnport 9902

# get the second node ID
node2=`lnrcli -c http://127.0.0.1:8802 node info | head -1` && echo $node2

# connect the first node to the second
lnrcli peer connect $node2 127.0.0.1:9902

# create channel
lnrcli channel new $node2 1000000

# mine 6 blocks to activate channel
bitcoin-cli --regtest generatetoaddress 6 $a_mine

# see that channel is active
lnrcli channel list

# create invoice and pay it
invoice=`lnrcli -c http://127.0.0.1:8802 invoice new 1000 | jq -r .invoice` && echo $invoice
lnrcli payment send $invoice

# see new channel balance
lnrcli channel list
```

## Integration test

If you have `bitcoind` in your path, and a recent Rust toolchain:

```
virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
cargo build
./scripts/compile-proto
./tests/integration-test.py
```

or in CI or if you don't want to install `bitcoind` and Python deps:

```
docker build -t latest .
docker run latest
```

### Using [kcov](https://github.com/SimonKagstrom/kcov) for Code Coverage

Dependencies:

    sudo dnf install -y elfutils-devel
    sudo dnf install -y curl-devel
    sudo dnf install -y binutils-devel

Build v38 of kcov from git@github.com:SimonKagstrom/kcov.git .

More dependencies:

    cargo install cargo-kcov
    cargo install cargo-coverage-annotations

Run coverage:

    ./scripts/run-kcov-all
        
View Coverage Report:

    [target/kcov/cov/index.html](target/kcov/cov/index.html)

Check coverage annotations in source files:

    cargo coverage-annotations

## License

Licensed under either:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
