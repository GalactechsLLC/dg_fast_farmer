[![CI](https://github.com/GalactechsLLC/dg_fast_farmer/actions/workflows/ci.yml/badge.svg)](https://github.com/GalactechsLLC/dg_fast_farmer/actions/workflows/ci.yml)

FastFarmer
=====

A lite farmer for the Chia Blockchain.


Building
--------

Install Rust by following the instructions at https://www.rust-lang.org/tools/install

Once Rust is installed we can build from source:
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
ff init -f FULLNODE_HOST -p FULLNODE_PORT -n SELECTED_NETWORK
```

To use a separate Fullnode for RPC calls during setup:
```
ff init -f FULLNODE_HOST -p FULLNODE_PORT -r FULLNODE_RPC_HOST -o FULLNODE_RPC_PORT -n SELECTED_NETWORK
```

For Wallets with lots of transactions, the init call runs much faster when targeting a launcher_id with -l:
```
ff init -f FULLNODE_HOST -p FULLNODE_PORT -r FULLNODE_RPC_HOST -o FULLNODE_RPC_PORT -n SELECTED_NETWORK -l LAUNCHER_ID
```

To run the Farmer with TUI Interface(Default):
```
ff
```

To run the Farmer in CLI mode:
```
ff run
```

To Update the PlotNFTs in the Config:
```
ff update-pool-info 
```

To Migrate the PlotNFTs in the config:
```
ff join-pool --pool-url <POOL_URL> --mnemonic <MNEMONIC> --launcher-id <LAUNCHER_ID> --fee <FEE>
```

> [!TIP]
> To Print all available commands ```ff --help``` <br>
> To Print Command Help ```ff <COMMAND> --help```