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
    kad::{Event as KademliaEvent, GetRecordOk, QueryId, QueryResult, RecordKey as KademliaKey},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use rand::{seq::SliceRandom, thread_rng};
use serde::Deserialize;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use subp2p_explorer::{
    peer_behavior::PeerInfoEvent,
    util::authorities::{decode_dht_record, hash_authority_id},
    util::crypto::sr25519,
    util::p2p::get_peer_id,
    util::ss58::to_ss58,
    Behaviour, BehaviourEvent,
};

/// Construct a jsonrpc client to communicate with the target node.
pub async fn client(url: Url) -> Result<Client, Box<dyn std::error::Error>> {
    let (sender, receiver) = WsTransportClientBuilder::default().build(url).await?;

    Ok(Client::builder()
        .max_buffer_capacity_per_subscription(4096)
        .build_with_tokio(sender, receiver))
}

/// Fetch bootnodes from the chain spec via the RPC endpoint.
///
/// Calls `sync_state_genSyncSpec` to retrieve the full chain spec and extracts
/// the `bootNodes` array.
pub(crate) async fn fetch_bootnodes_from_rpc(
    url: Url,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    let spec: serde_json::Value = client
        .request("sync_state_genSyncSpec", rpc_params![true])
        .await?;

    let bootnodes = spec
        .get("bootNodes")
        .ok_or("Chain spec missing `bootNodes` field")?
        .as_array()
        .ok_or("Invalid `bootNodes` format, expected array")?
        .iter()
        .filter_map(|node| node.as_str().map(|s| s.to_string()))
        .collect();

    Ok(bootnodes)
}

/// Fetch the genesis hash from the RPC endpoint.
///
/// Calls `chain_getBlockHash(0)` and returns the hex-encoded hash (without `0x` prefix).
pub(crate) async fn fetch_genesis_hash(url: Url) -> Result<String, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    let hash: String = client
        .request("chain_getBlockHash", rpc_params![0u32])
        .await?;

    Ok(hash.trim_start_matches("0x").to_string())
}

/// Fetch the SS58 address prefix from the RPC endpoint via `system_properties`.
pub(crate) async fn fetch_ss58_prefix(url: Url) -> Result<u16, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    let props: serde_json::Value = client
        .request("system_properties", rpc_params![])
        .await?;

    let prefix = props
        .get("ss58Format")
        .ok_or("system_properties missing `ss58Format` field")?
        .as_u64()
        .ok_or("Invalid `ss58Format`, expected integer")? as u16;

    Ok(prefix)
}

/// Call the runtime API of the target node to retrive the current set
/// of authorities.
///
/// This method calls into `AuthorityDiscoveryApi_authorities` runtime API.
pub(crate) async fn runtime_api_autorities(
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

    let bytes = hex::decode(raw)?;

    let authorities: Vec<sr25519::PublicKey> = Decode::decode(&mut &bytes[..])?;
    Ok(authorities)
}

/// The maximum number of Kademlia `get-records` queried a time.
const MAX_QUERIES: usize = 64;

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

    /// Whether to print an interactive progress bar to stdout.
    show_progress: bool,
    /// When the discovery process started.
    start_time: std::time::Instant,
    /// Timeout duration for display purposes.
    timeout_secs: u64,
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
    #[allow(dead_code)]
    pub fn addresses(&self) -> &HashSet<Multiaddr> {
        &self.addresses
    }

    #[allow(dead_code)]
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
            interval_resubmit: tokio::time::interval(std::time::Duration::from_secs(15)),
            interval_exit: tokio::time::interval(timeout),

            show_progress: false,
            start_time: std::time::Instant::now(),
            timeout_secs: timeout.as_secs(),
        }
    }

    /// Query the DHT for the records of the authorities.
    fn query_dht_records(&mut self, authorities: impl IntoIterator<Item = sr25519::PublicKey>) {
        // Make a query for every authority.
        for authority in authorities {
            let key = hash_authority_id(&authority);
            self.records_keys.insert(key.clone(), authority);

            let id = self.swarm.behaviour_mut().discovery.get_record(key);
            self.queries.insert(id, authority);
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
                self.query_dht_records(std::iter::once(*next));
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
    fn handle_swarm(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            // Discovery DHT record.
            SwarmEvent::Behaviour(behavior_event) => {
                log::trace!("Behaviour event: {:?}", behavior_event);

                match behavior_event {
                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetRecord(record),
                        ..
                    }) => {
                        // Has received at least one answer for this and can advance the queries.
                        self.queries.remove(&id);

                        if let Ok(GetRecordOk::FoundRecord(peer_record)) = record {
                            let key = peer_record.record.key;
                            let value = peer_record.record.value;

                            let Some(authority) = self.records_keys.get(&key) else {
                                self.advance_dht_queries();
                                return;
                            };
                            let authority = *authority;

                            let (peer_id, addresses) = match decode_dht_record(value, &authority) {
                                Ok((peer_id, addresses)) => (peer_id, addresses),
                                Err(e) => {
                                    log::debug!(
                                        " Decoding DHT failed for authority {:?}: {:?}",
                                        authority,
                                        e
                                    );
                                    self.dht_errors += 1;
                                    self.advance_dht_queries();
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
                            if now.duration_since(self.old_log) > std::time::Duration::from_secs(10)
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
                        } else {
                            log::debug!(
                                "DHT query failed: {:?} (in-flight: {}, remaining: {})",
                                record.err(),
                                self.queries.len(),
                                self.remaining_authorities.len()
                            );
                        }

                        // Always advance queries regardless of success or failure,
                        // otherwise failed queries reduce concurrency without replacement
                        // and the discovery stalls until the resubmit timer fires.
                        self.advance_dht_queries();
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

            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                ..
            } => {
                log::trace!(
                    "Connection closed: peer_id={:?} connection_id={:?} endpoint={:?} num_established={:?}",
                    peer_id,
                    connection_id,
                    endpoint,
                    num_established,
                );
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                ..
            } => {
                log::trace!(
                    "Connection established: peer_id={:?} connection_id={:?} endpoint={:?} num_established={:?}",
                    peer_id,
                    connection_id,
                    endpoint,
                    num_established,
                );
            }

            SwarmEvent::Dialing {
                peer_id,
                connection_id,
            } => {
                log::trace!(
                    "Dialing: peer_id={:?} connection_id={:?}",
                    peer_id,
                    connection_id,
                );
            }

            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => {
                log::trace!(
                    "Outgoing connection error: peer_id={:?} connection_id={:?} error={:?}",
                    peer_id,
                    connection_id,
                    error,
                );
            }

            SwarmEvent::IncomingConnectionError {
                connection_id,
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                log::trace!(
                    "Incoming connection error: connection_id={:?} local_addr={:?} send_back_addr={:?} error={:?}",
                    connection_id,
                    local_addr,
                    send_back_addr,
                    error,
                );
            }

            _ => (),
        }
    }

    /// Enable or disable interactive progress bar output on stdout.
    pub fn set_show_progress(&mut self, show: bool) {
        self.show_progress = show;
    }

    /// Print an in-place progress bar to stdout.
    fn print_progress(&self) {
        let elapsed = self.start_time.elapsed().as_secs();
        let total = self.authorities.len();
        let found = self.authority_to_details.len();
        let identified = self
            .peer_details
            .keys()
            .filter(|peer| self.peer_info.contains_key(peer))
            .count();

        let pct = if total > 0 {
            found as f64 / total as f64
        } else {
            0.0
        };
        let bar_width = 25;
        let filled = (pct * bar_width as f64) as usize;
        let bar = format!(
            "{}{}",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(bar_width - filled)
        );

        let connected_peers = self.swarm.connected_peers().count();
        let queries_inflight = self.queries.len();

        print!(
            "\r       [{}] {}/{} ({:.1}%) | Identified: {} | Errors: {} | Peers: {} | Queries: {} | {}s/{}s   ",
            bar,
            found,
            total,
            pct * 100.0,
            identified,
            self.dht_errors,
            connected_peers,
            queries_inflight,
            elapsed,
            self.timeout_secs,
        );
        let _ = std::io::stdout().flush();
    }

    /// Run the discovery process.
    pub async fn discover(&mut self) {
        self.advance_dht_queries();
        self.start_time = std::time::Instant::now();

        // Should return immediately.
        self.interval_resubmit.tick().await;
        self.interval_exit.tick().await;

        let mut progress_interval = tokio::time::interval(std::time::Duration::from_secs(1));
        progress_interval.tick().await;

        loop {
            futures::select! {
                event = self.swarm.select_next_some().fuse() => {
                    self.handle_swarm(event);
                },

                _ = self.interval_resubmit.tick().fuse() => {
                    self.resubmit_remaining_dht_queries();
                }

                _ = progress_interval.tick().fuse() => {
                    if self.show_progress {
                        self.print_progress();
                    }
                }

                _ = self.interval_exit.tick().fuse() => {
                    if self.show_progress {
                        // Clear the progress line.
                        print!("\r{}\r", " ".repeat(100));
                        let _ = std::io::stdout().flush();
                    }

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
    #[allow(dead_code)]
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
/// ```ignore
/// let addr =
///     "/ip4/34.92.86.244/tcp/40333/p2p/12D3KooWKxsprneVYQxxPnPUwDA5p2huuCbZCNyuSHTmKDv3vT2n";
/// let addr: Multiaddr = addr.parse().expect("Valid multiaddress; qed");
/// let peer_id = get_peer_id(&addr);
/// let info = PeerInfo::new(local_key.clone(), vec![addr]);
/// let info = info.discover().await;
/// println!("Peer={:?} version={:?}", peer_id, info);
/// ```
#[allow(dead_code)]
struct PeerInfo {
    swarm: Swarm<libp2p::identify::Behaviour>,
}

#[allow(dead_code)]
impl PeerInfo {
    pub async fn new(local_key: libp2p::identity::Keypair, addresses: Vec<Multiaddr>) -> Self {
        let identify_config =
            libp2p::identify::Config::new("/substrate/1.0".to_string(), local_key.public())
                .with_agent_version("subp2p-identify".to_string())
                .with_cache_size(0);
        let identify = libp2p::identify::Behaviour::new(identify_config);

        let tcp_config = libp2p::tcp::Config::new().nodelay(true);
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp_config,
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .expect("Can construct TCP; qed")
            .with_dns()
            .expect("Can construct DNS; qed")
            .with_websocket(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .await
            .expect("Can construct WebSocket; qed")
            .with_behaviour(|_key| identify)
            .expect("Can construct behaviour; qed")
            .build();

        for multiaddress in &addresses {
            let _ = swarm.dial(multiaddress.clone());
        }

        PeerInfo { swarm }
    }

    pub async fn discover(mut self) -> Result<Info, libp2p::swarm::DialError> {
        loop {
            let event = self.swarm.select_next_some().await;

            match event {
                SwarmEvent::Behaviour(libp2p::identify::Event::Received { info, .. }) => {
                    return Ok(info);
                }

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
    query_timeout: std::time::Duration,
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
    let swarm = build_swarm(genesis.clone(), bootnodes, query_timeout).await?;
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
