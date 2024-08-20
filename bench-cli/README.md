
# Benchmarking CLI

The benchmarking CLI is designed to benchmark the performance of different network backends.

This data helps us drive improvements in various network components, such as the discovery process.

At the moment the CLI supports the following backends:

- [x] litep2p
- [x] libp2p

## Usage

### Discovery Kademlia Benchmarking (live chains)

Although the tool is targeting a live chain, it can also be used to benchmark the discovery process on a local chain by providing the genesis block hash and at least one boot node.

Local chains can be started with other tools, like zombie-net-cli, and is out of the scope of this tool.

- Benchmark the discovery process on kusama using the litep2p backend with 100 peers:

```bash
cargo run -- discovery --genesis b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe --bootnodes /dns/kusama-bootnode-0.polkadot.io/tcp/30333/p2p/12D3KooWSueCPH3puP2PcvqPJdNaDNF3jMZjtJtDiSy35pWrbt5h --backend-type litep2p --num-peers 100
```

- Benchmark the discovery process on kusama using the libp2p backend with 100 peers:

```bash
cargo run -- discovery --genesis b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe --bootnodes /dns/kusama-bootnode-0.polkadot.io/tcp/30333/p2p/12D3KooWSueCPH3puP2PcvqPJdNaDNF3jMZjtJtDiSy35pWrbt5h --backend-type litep2p --num-peers 100
```
