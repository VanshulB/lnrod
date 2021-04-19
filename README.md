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

# Start bitcoind in regtest mode, advance 101 blocks
bitcoind -regtest -daemon
a_mine=`bitcoin-cli -regtest getnewaddress`
bitcoin-cli -regtest generatetoaddress 101 $a_mine

alias lnrod=target/debug/lnrod
alias lnrcli=target/debug/lnrcli

lnrod --regtest
lnrod --datadir ./data2 --rpcport 8802 --lnport 9902 --regtest

# get the second node ID
node2=`lnrcli -c http://[::1]:8802 node info`

# connect the first node to the second
lnrcli peer connect $node2 127.0.0.1:9902
# create channel
lnrcli channel new $node2 1000000

# mine 6 blocks to activate channel
bitcoin-cli --regtest generatetoaddress 6 $a_mine

# see that channel is active
lnrcli channel list

# create invoice and pay it
invoice=`lnrcli -c http://[::1]:8802 invoice new 1000 | jq -r .invoice`
lnrcli payment send $invoice

# see new channel balance
lnrcli channel list
```

## License

Licensed under either:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
