## subp2p-explorer

Substrate based chains p2p network explorer.

## Usage

Take a look at the examples provided in the [commands](./cli/src/commands/) folder to learn more about the p2p interface.

## discover-network

This command crawls the p2p network. For more details see the [kad-dht spec](https://github.com/libp2p/specs/blob/master/kad-dht/README.md).

The heuristic used for crawling is the following:

- The crawler starts from the provided boot nodes.
- 128 queries of random peerId are generated at a time.
- The crawler waits for 5 minutes for convergence.

After the crawling is finished, the crawler prints:

- The number of peers discovered.
- The number of peers that respond to "/ipfs/id/1.0.0" and support the genesis hash of the chain.
- The top-k cities with the most peers discovered.
- Optionally the list of all peers discovered with geolocation information.

The following command discovers all the peers of the polkadot network:

```bash
$ cargo run -- discover-network --genesis 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3 --bootnodes /dns/polkadot-connect-0.parity.io/tcp/443/wss/p2p/12D3KooWEPmjoRpDSUuiTjvyNDd8fejZ9eNWH5bE965nyBMDrB4o

INFO subp2p_explorer_cli::utils: Local peer ID PeerId("12D3KooWR5PoNAD5ucbHGnRbywM9tvPyhaWbWLBuYbYm8Q73hjka")
INFO subp2p_explorer_cli::utils: Bootnode peer=PeerId("12D3KooWNwWNRrPrTk4qMah1YszudMjxNw2qag7Kunhw3Ghs9ea5")

INFO subp2p_explorer_cli::commands::discovery: ...Discovery in progress last_query_num=18
INFO subp2p_explorer_cli::commands::discovery: ...Discovery in progress last_query_num=20
...

Dialed num=7717 peers
Discovered num=1358 peers
Peers with identity num=1586
Peers that support our genesis hash 1404
  Peers with public addresses 1404
  Peers with private addresses 0
   City="Helsinki" peers=75
   City="Frankfurt am Main" peers=72
   City="Zurich" peers=43
   City="Ashburn" peers=42
   City="Dublin" peers=40
   City="London" peers=29
   City="Singapore" peers=25
   City="Toronto" peers=25
   City="Paris" peers=21
   City="Groningen" peers=20
```

## verify-bootnodes

This command verifies that the provided bootnodes are valid.

A bootnode is considered valid when:

- It is reachable and responds to the identify p2p protocol "/ipfs/id/1.0.0". For more details see the [libp2p spec](https://github.com/libp2p/specs/blob/master/identify/README.md#identify).
- If the genesis hash of the chain is provided, the bootnode must have one p2p protocol that derives the genesis hash
  - For example, "/GENESIS/transactions/1", "/GENESIS/kad" etc.




The following command validates the bootnodes of the polkadot chain from the provided chain spec:

```bash
$ cargo run -- verify-bootnodes --chain-spec polkadot.json

Valid bootnodes:
 /dns/polkadot-bootnode.radiumblock.com/tcp/30335/wss/p2p/12D3KooWNwWNRrPrTk4qMah1YszudMjxNw2qag7Kunhw3Ghs9ea5
 /dns/polkadot-bootnode-1.polkadot.io/tcp/30334/ws/p2p/12D3KooWFN2mhgpkJsDBuNuE5427AcDrsib8EoqGMZmkxWwx3Md4
 /dns/boot-polkadot.metaspan.io/tcp/13016/wss/p2p/12D3KooWRjHFApinuqSBjoaDjQHvxwubQSpEVy5hrgC9Smvh92WF
 ...

Invalid bootnodes:
 /dns/polkadot-boot.dwellir.com/tcp/30334/ws/p2p/12D3KooWKvdDyRKqUfSAaUCbYiLwKY8uK3wDWpCuy2FiDLbkPTDJ
```

The following command validates the one bootnode with the optional genesis hash provided:

```bash
$ cargo run -- verify-bootnodes --genesis 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3 --bootnodes /dns/polkadot-bootnode.radiumblock.com/tcp/30335/wss/p2p/12D3KooWNwWNRrPrTk4qMah1YszudMjxNw2qag7Kunhw3Ghs9ea5
```


## send-extrinisic

Submit an extrinsic to a substrate base chain directly on the p2p network.

Note that chain inclusion is not guaranteed. The extrinsic is submitted on the p2p network via the "/GENESIS/transactions/1" notification protocol that does not provide an acknowledgment mechanism.

To verify that the extrinsic was included in the chain, use [subxt](https://github.com/paritytech/subxt/blob/master/subxt/examples/blocks_subscribing.rs) or [polkadot-js](https://polkadot.js.org/apps/#/explorer).


```bash
$ cargo run -- send-extrinisic --genesis 781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738 --bootnodes /ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp --extrinsics 04310...c0
```
