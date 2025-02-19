use crate::utils::build_swarm;
use codec::Decode;
use futures::FutureExt;
use futures::StreamExt;
use jsonrpsee::{
    client_transport::ws::{Url, WsTransportClientBuilder},
    core::client::{Client, ClientT},
    rpc_params,
};
use libp2p::{
    identify::Info,
    identity::Keypair,
    kad::{record::Key as KademliaKey, GetRecordOk, KademliaEvent, QueryId, QueryResult},
    multiaddr,
    swarm::{DialError, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use multihash_codetable::{Code, MultihashDigest};
use rand::{seq::SliceRandom, thread_rng};
use serde::Deserialize;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use subp2p_explorer::{
    peer_behavior::PeerInfoEvent,
    transport::{TransportBuilder, MIB},
    util::authorities::{decode_dht_record, hash_authority_id},
    util::crypto::sr25519,
    util::p2p::get_peer_id,
    util::ss58::{ss58hash, to_ss58},
    Behaviour, BehaviourEvent,
};

/// Construct a jsonrpc client to communicate with the target node.
pub async fn client(url: Url) -> Result<Client, Box<dyn std::error::Error>> {
    let (sender, receiver) = WsTransportClientBuilder::default().build(url).await?;

    Ok(Client::builder()
        .max_buffer_capacity_per_subscription(4096)
        .build_with_tokio(sender, receiver))
}

/// Call the runtime API of the target node to retrive the current set
/// of authorities.
///
/// This method calls into `AuthorityDiscoveryApi_authorities` runtime API.
async fn runtime_api_autorities(
    url: Url,
) -> Result<Vec<sr25519::PublicKey>, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    // State call provides the result hex-encoded.
    let raw: String = client
        .request(
            "state_call",
            rpc_params!["AuthorityDiscoveryApi_authorities", "0x"],
        )
        .await?;
    let raw = raw
        .strip_prefix("0x")
        .expect("Substrate API returned invalid hex");

    let bytes = hex::decode(&raw)?;

    let authorities: Vec<sr25519::PublicKey> = Decode::decode(&mut &bytes[..])?;
    Ok(authorities)
}

/// The maximum number of Kademlia `get-records` queried a time.
const MAX_QUERIES: usize = 8;

/// Discover the authorities on the network.
pub struct AuthorityDiscovery {
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,

    /// In flight `get-record` kademlia queries to ensure that a maximum of `MAX_QUERIES` are in flight.
    queries: HashMap<QueryId, sr25519::PublicKey>,
    /// In flight `get-closest-peers` kademlia queries to force the discovery of unidentified peers.
    queries_discovery: HashSet<QueryId>,

    /// Map the in-flight kademlia queries to the authority ids.
    records_keys: HashMap<KademliaKey, sr25519::PublicKey>,
    /// Peer details obtained from the DHT records.
    peer_details: HashMap<PeerId, PeerDetails>,
    /// Peer information from the identify protocol. This includes the version of the peer.
    peer_info: HashMap<PeerId, Info>,
    authority_to_details: HashMap<sr25519::PublicKey, HashSet<Multiaddr>>,

    /// Initially provided authority list.
    authorities: Vec<sr25519::PublicKey>,
    /// Query index.
    query_index: usize,

    /// Encountered DHT errors, either from decoding or protocol transport.
    dht_errors: usize,

    /// Remaining authorities to query.
    remaining_authorities: HashSet<sr25519::PublicKey>,
    /// Finished DHT queries for authority records.
    finished_query: bool,

    /// Time of the last log line.
    old_log: std::time::Instant,
    /// Interval at which to resubmit the remaining queries.
    interval_resubmit: tokio::time::Interval,
    /// Interval at which to bail out.
    interval_exit: tokio::time::Interval,
}

/// The peer details extracted from the DHT.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerDetails {
    /// Authority ID from the runtime API.
    #[allow(unused)]
    authority_id: sr25519::PublicKey,
    /// Discovered from the DHT.
    addresses: HashSet<Multiaddr>,
}

impl PeerDetails {
    pub fn addresses(&self) -> &HashSet<Multiaddr> {
        &self.addresses
    }

    pub fn authority_id(&self) -> &sr25519::PublicKey {
        &self.authority_id
    }
}

impl AuthorityDiscovery {
    /// Constructs a new [`AuthorityDiscovery`].
    pub fn new(
        swarm: Swarm<Behaviour>,
        authorities: Vec<sr25519::PublicKey>,
        timeout: std::time::Duration,
    ) -> Self {
        AuthorityDiscovery {
            swarm,
            queries: HashMap::with_capacity(1024),

            records_keys: HashMap::with_capacity(1024),

            queries_discovery: HashSet::with_capacity(1024),
            peer_info: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
            authority_to_details: HashMap::with_capacity(1024),

            authorities: authorities.clone(),
            query_index: 0,

            dht_errors: 0,
            remaining_authorities: authorities.into_iter().collect(),
            finished_query: false,

            old_log: std::time::Instant::now(),
            interval_resubmit: tokio::time::interval(std::time::Duration::from_secs(60)),
            interval_exit: tokio::time::interval(timeout),
        }
    }

    /// Query the DHT for the records of the authorities.
    fn query_dht_records(&mut self, authorities: impl IntoIterator<Item = sr25519::PublicKey>) {
        // Make a query for every authority.
        for authority in authorities {
            let key = hash_authority_id(&authority);
            self.records_keys.insert(key.clone(), authority);

            let id = self.swarm.behaviour_mut().discovery.get_record(key);
            self.queries.insert(id, authority.clone());
        }
    }

    /// Query the DHT for the closest peers of the authorities that
    /// are not reacheable at the moment. This function is called
    /// after the authorities are discovered from the DHT to avoid
    /// running out of file descriptors.
    ///
    /// Note: they may never be reachable due to NAT.
    fn query_peer_info(&mut self) {
        // This is not correlated with the `MAX_QUERIES`.
        const MAX_DISCOVERY_QUERIES: usize = 32;

        if self.queries_discovery.len() < MAX_DISCOVERY_QUERIES {
            let query_num = MAX_DISCOVERY_QUERIES - self.queries_discovery.len();
            for _ in 0..query_num {
                self.queries_discovery.insert(
                    self.swarm
                        .behaviour_mut()
                        .discovery
                        .get_closest_peers(PeerId::random()),
                );
            }
        }
    }

    /// Submit at most `MAX_QUERIES` DHT queries to find authority records.
    ///
    /// After one query is submitted for every authority this method will
    /// resubmit the DHT queries for the remaining authorities.
    fn advance_dht_queries(&mut self) {
        // Add more DHT queries.
        while self.queries.len() < MAX_QUERIES {
            if let Some(next) = self.authorities.get(self.query_index) {
                self.query_dht_records(std::iter::once(next.clone()));
                self.query_index += 1;
            } else {
                if self.queries.is_empty() {
                    self.resubmit_remaining_dht_queries();
                }
                log::debug!(
                    "queries: {} remaining authorities to discover {}",
                    self.queries.len(),
                    self.remaining_authorities.len()
                );

                break;
            }
        }

        self.query_peer_info();
    }

    /// Submit the DHT queries for the remaining authorities that did not receive a record yet.
    ///
    /// When the number of remaining authorities gets below a threashold (`MAX_QUERIES`),
    /// this method will also submit the `get-closest-peers` queries to force the discovery
    /// of the peers that are not reachable at the moment.
    fn resubmit_remaining_dht_queries(&mut self) {
        // Ignore older queries.
        self.queries.clear();

        let authorities = self.remaining_authorities.clone();
        let mut remaining: Vec<_> = authorities.iter().collect();
        remaining.shuffle(&mut thread_rng());

        let remaining_len = remaining.len();

        log::debug!(
            " Remaining authorities: {}",
            self.remaining_authorities.len()
        );

        self.query_dht_records(remaining.into_iter().take(MAX_QUERIES).cloned());

        if remaining_len < MAX_QUERIES {
            self.query_peer_info();
        }
    }

    /// Handle a swarm event from the p2p network.
    fn handle_swarm<T>(&mut self, event: SwarmEvent<BehaviourEvent, T>) {
        match event {
            // Discovery DHT record.
            SwarmEvent::Behaviour(behavior_event) => {
                match behavior_event {
                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetRecord(record),
                        ..
                    }) => {
                        // Has received at least one answer for this and can advance the queries.
                        self.queries.remove(&id);

                        match record {
                            Ok(GetRecordOk::FoundRecord(peer_record)) => {
                                let key = peer_record.record.key;
                                let value = peer_record.record.value;

                                let Some(authority) = self.records_keys.get(&key) else {
                                    return;
                                };
                                let authority = *authority;

                                let (peer_id, addresses) =
                                    match decode_dht_record(value, &authority) {
                                        Ok((peer_id, addresses)) => (peer_id, addresses),
                                        Err(e) => {
                                            log::debug!(
                                                " Decoding DHT failed for authority {:?}: {:?}",
                                                authority,
                                                e
                                            );
                                            self.dht_errors += 1;
                                            return;
                                        }
                                    };

                                self.authority_to_details
                                    .entry(authority)
                                    .and_modify(|entry| entry.extend(addresses.clone()))
                                    .or_insert_with(|| addresses.iter().cloned().collect());

                                self.peer_details
                                    .entry(peer_id)
                                    .and_modify(|entry| entry.addresses.extend(addresses.clone()))
                                    .or_insert_with(|| PeerDetails {
                                        authority_id: authority,
                                        addresses: addresses.iter().cloned().collect(),
                                    });

                                log::debug!(
                                    "{}/{} (err {}) authority: {:?} peer_id {:?} Addresses: {:?}",
                                    self.authority_to_details.len(),
                                    self.authorities.len(),
                                    self.dht_errors,
                                    authority,
                                    peer_id,
                                    addresses
                                );

                                let now = std::time::Instant::now();
                                if now.duration_since(self.old_log)
                                    > std::time::Duration::from_secs(10)
                                {
                                    self.old_log = now;
                                    log::info!(
                                        "... DHT records {}/{} (err {}) | Identified {}/{} | Active peer queries {} | authority={:?} peer_id={:?} addresses={:?}",
                                        self.authority_to_details.len(),
                                        self.authorities.len(),
                                        self.dht_errors,

                                        self.peer_details.keys().filter_map(|peer| self.peer_info.get(peer)).count(),
                                        self.peer_details.keys().count(),

                                        self.queries_discovery.len(),

                                        authority,
                                        peer_id,
                                        addresses
                                    );
                                }

                                self.remaining_authorities.remove(&authority);
                                self.advance_dht_queries();
                            }
                            _ => (),
                        }
                    }

                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetClosestPeers(_),
                        ..
                    }) => {
                        if self.finished_query {
                            log::debug!(" Discovered closes peers of {:?}", id);
                        }

                        self.queries_discovery.remove(&id);
                        self.query_peer_info();
                    }

                    BehaviourEvent::PeerInfo(info_event) => {
                        match info_event {
                            PeerInfoEvent::Identified { peer_id, info } => {
                                if self.finished_query {
                                    let discovered = self
                                        .peer_details
                                        .keys()
                                        .filter_map(|peer| self.peer_info.get(peer))
                                        .count();

                                    log::debug!(
                                        " {}/{} Info event {:?}",
                                        discovered,
                                        self.authorities.len(),
                                        peer_id
                                    );
                                }

                                // Save the record.
                                self.peer_info.insert(peer_id, info);
                            }
                        };
                    }
                    _ => (),
                }
            }

            _ => (),
        }
    }

    /// Run the discovery process.
    pub async fn discover(&mut self) {
        self.advance_dht_queries();

        // Should return immediately.
        self.interval_resubmit.tick().await;
        self.interval_exit.tick().await;

        loop {
            futures::select! {
                event = self.swarm.select_next_some().fuse() => {
                    self.handle_swarm(event);
                },

                _ = self.interval_resubmit.tick().fuse() => {
                    self.resubmit_remaining_dht_queries();
                }

                _ = self.interval_exit.tick().fuse() => {
                    if self.authority_to_details.len() == self.authorities.len() {
                        log::info!("All authorities discovered from DHT");
                    } else {
                        log::info!("Exiting due to timeout");
                    }

                    return;
                }
            }
        }
    }

    /// Returns a reference to the discovered peer details.
    pub fn peer_details(&self) -> &HashMap<PeerId, PeerDetails> {
        &self.peer_details
    }

    /// Returns a reference to the discovered peer info.
    pub fn peer_info(&self) -> &HashMap<PeerId, Info> {
        &self.peer_info
    }

    /// Returns a reference to the mapping between the authority discovery public key and the
    /// discovered addresses.
    pub fn authority_to_details(&self) -> &HashMap<sr25519::PublicKey, HashSet<Multiaddr>> {
        &self.authority_to_details
    }
}

/// Reach a single peer and query the identify protocol.
///
/// # Example
///
/// The following address is taken from the DHT.
/// However, the address cannot be reached directly.
/// For this to work, we'd need to implement NAT hole punching.
///
/// ```rust
/// let addr =
///     "/ip4/34.92.86.244/tcp/40333/p2p/12D3KooWKxsprneVYQxxPnPUwDA5p2huuCbZCNyuSHTmKDv3vT2n";
/// let addr: Multiaddr = addr.parse().expect("Valid multiaddress; qed");
/// let peer_id = get_peer_id(&addr);
/// let info = PeerInfo::new(local_key.clone(), vec![addr]);
/// let info = info.discover().await;
/// println!("Peer={:?} version={:?}", peer_id, info);
/// ```
#[allow(unused)]
struct PeerInfo {
    swarm: Swarm<libp2p::identify::Behaviour>,
}

impl PeerInfo {
    #[allow(unused)]
    pub fn new(local_key: Keypair, addresses: Vec<Multiaddr>) -> Self {
        // "/ip4/144.76.115.244/tcp/30333/p2p/12D3KooWKR7TX55EnZ6L6FUHfuZKAEgkL8ffE3KFYqnHZUysSVrW"
        let mut swarm: Swarm<libp2p::identify::Behaviour> = {
            let transport = TransportBuilder::new()
                .yamux_maximum_buffer_size(256 * MIB)
                .build(local_key.clone());

            let identify_config =
                libp2p::identify::Config::new("/substrate/1.0".to_string(), local_key.public())
                    .with_agent_version("subp2p-identify".to_string())
                    // Do not cache peer info.
                    .with_cache_size(0);
            let identify = libp2p::identify::Behaviour::new(identify_config);

            let local_peer_id = PeerId::from(local_key.public());
            libp2p::swarm::SwarmBuilder::with_tokio_executor(transport, identify, local_peer_id)
                .build()
        };

        // These are the initial peers for which the queries are performed against.
        for multiaddress in &addresses {
            let res = swarm.dial(multiaddress.clone());
        }

        PeerInfo { swarm }
    }

    #[allow(unused)]
    pub async fn discover(mut self) -> Result<Info, DialError> {
        loop {
            let event = self.swarm.select_next_some().await;

            match event {
                SwarmEvent::Behaviour(behavior) => match behavior {
                    libp2p::identify::Event::Received { info, .. } => {
                        return Ok(info);
                    }
                    _ => (),
                },

                SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error),

                _ => (),
            }
        }
    }
}

/// Entry function called from the CLI.
pub async fn discover_authorities(
    url: String,
    genesis: String,
    bootnodes: Vec<String>,
    timeout: std::time::Duration,
    address_format: String,
    raw_output: bool,
) -> Result<(AuthorityDiscovery, Vec<sr25519::PublicKey>), Box<dyn std::error::Error>> {
    let format_registry =
        ss58_registry::Ss58AddressFormatRegistry::try_from(address_format.as_str())
            .map_err(|err| format!("Cannot parse the provided address format: {:?}", err))?;
    let version: ss58_registry::Ss58AddressFormat = format_registry.into();
    let version = version.prefix();
    log::info!(
        "Address format {:?} with version prefix {:?}",
        format_registry,
        version
    );

    let url = Url::parse(&url)?;

    // Extract the authorities from the runtime API.
    let authorities = runtime_api_autorities(url).await?;

    // Perform DHT queries to find the authorities on the network.
    // Then, record the addresses of the authorities and the responses
    // from the identify protocol.
    let swarm = build_swarm(genesis.clone(), bootnodes)?;
    let mut authority_discovery = AuthorityDiscovery::new(swarm, authorities.clone(), timeout);
    authority_discovery.discover().await;
    log::info!("Finished discovery\n");

    let mut reached_peers = 0;
    let mut litep2p = 0;

    for authority in &authorities {
        let Some(details) = authority_discovery.authority_to_details.get(authority) else {
            println!(
                "authority={:?} - No dht response",
                to_ss58(authority, version),
            );
            continue;
        };

        let Some(addr) = details.iter().next() else {
            println!(
                "authority={:?} - No addresses found in DHT record",
                to_ss58(authority, version),
            );
            continue;
        };

        let peer_id = get_peer_id(addr).expect("All must have valid peerIDs");

        let info = authority_discovery.peer_info.get(&peer_id).cloned();
        if let Some(info) = info {
            reached_peers += 1;

            if info.agent_version.contains("litep2p") {
                litep2p += 1;
            }

            println!(
                "authority={:?} peer_id={:?} addresses={:?} version={:?} ",
                to_ss58(authority, version),
                peer_id,
                info.agent_version,
                details,
            );
        } else {
            println!(
                "authority={:?} peer_id={:?} addresses={:?} - Cannot be reached",
                to_ss58(authority, version),
                peer_id,
                details,
            );
        }
    }

    println!(
        "\n\n  Discovered {}/{} authorities",
        reached_peers,
        authorities.len()
    );

    println!(" Discovered peers {}", authority_discovery.peer_info.len());

    if raw_output {
        println!("\n Raw output of the discovered peers:");

        for (peer_id, info) in &authority_discovery.peer_info {
            println!("peer_id={:?} info={:?}", peer_id, info);
        }
    }

    println!(" Litep2p authorities {}", litep2p);

    Ok((authority_discovery, authorities))
}
