[![CI](https://github.com/GalactechsLLC/dg_fast_farmer/actions/workflows/ci.yml/badge.svg)](https://github.com/GalactechsLLC/dg_fast_farmer/actions/workflows/ci.yml)

FastFarmer
=====

A lite farmer for the Chia Blockchain, written 100% in Rust. It currently supports harvesting Bladebit plots with CPU. Support for harvesting Bladebit plots with GPU will be added soon. Support for harvesting GH plots **with closed source** will also be added soon. NoSSD plots is not and will not be supported.

FastFarmer works with all pools (NFT) and OG plots.


```
                | CPU  | GPU  |
Bladebit Plots  |  ✅  | ❌  |
Gigahorse Plots |  ❌  | ❌  |
NoSSD Plots     |  ❌  | ❌  |
```

To use FastFarmer to harvest Gigahorse plots with the closed source binaries/executables, go to https://github.com/evergreen-xch/ff_giga_bins


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

To run the Farmer with TUI Interface(Default):
```
ff
```

To run the Farmer in CLI mode:
```
ff run
```

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
