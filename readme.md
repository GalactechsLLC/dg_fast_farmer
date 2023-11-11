![Cargo Checks](https://github.com/GalactechsLLC/dg_xch_utils/actions/workflows/rust.yml/badge.svg)

FastFarmer
=====

A lite farmer for the Chia Blockchain.


Building
--------

Install Rust:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build from source:
```
git clone https://github.com/GalactechsLLC/dg_fast_farmer.git
cd dg_fast_farmer
cargo build --release
sudo cp target/release/ff /usr/local/bin/ff
```

Running
--------

To generate the farmer config:
```
ff -c "/path/to/config/fast_farmer.yaml" init -m "MNEMONIC" -f FULLNODE_HOST -p FULLNODE_RPC_PORT -n SELECTED_NETWORK
```

To run the Farmer:
```
ff -c "/path/to/config/fast_farmer.yaml" run
```