# ldk-sample
Sample node implementation using LDK.

## Installation
```
git clone git@github.com:valentinewallace/ldk-sample.git
```

## Usage
```
cd ldk-sample
cargo run <bitcoind-rpc-username>:<bitcoind-rpc-password>@<bitcoind-rpc-host>:<bitcoind-rpc-port> <ldk_storage_directory_path> [<ldk-peer-listening-port>] [bitcoin-network]
```
`bitcoin-network`: defaults to `testnet`. Options: `testnet`, `regtest`.
`ldk-peer-listening-port`: defaults to 9735.

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
