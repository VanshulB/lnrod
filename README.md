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

alias lnrod=target/debug/server
alias lncli=target/debug/cli

lnrod --regtest
lnrod --datadir ./data2 --rpcport 8802 --lnport 9902 --regtest

# get the second node ID
node2=`lncli -c http://[::1]:8802 node info`

# connect the first node to the second
lncli peer connect $node2 127.0.0.1:9902
# create channel
lncli channel new $node2 127.0.0.1:9902 1000000

# mine 6 blocks to activate channel
a_mine=`bitcoin-cli --regtest getnewaddress` 
bitcoin-cli --regtest generatetoaddress 6 $a_mine

# see that channel is active
lncli channel list

# create invoice and pay it
invoice=`lncli -c http://[::1]:8802 invoice new 1000 | jq -r .invoice`
lncli payment send $invoice

# see new channel balance
lncli channel list
```

## License

Licensed under either:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
