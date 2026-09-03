// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! On-disk cache of the peers seen during a crawl.
//!
//! Every `authority-check` run writes `cache/<chain>-peers.json` with the
//! peers it talked to. The aggressive litep2p mode reads it back to start
//! warm: the Kademlia routing table is seeded with every cached peer, so the
//! first hop of each record query lands next to the key instead of on the
//! bootnodes, and the cached validators are dialed before their records
//! arrive, so their identify responses land within the first seconds.

use crate::commands::authorities::DialOutcome;
use crate::commands::authority_check::DiscoveryResults;
use crate::utils::{is_dialable_transport, is_public_address, with_peer_id};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use subp2p_explorer::util::p2p::get_peer_id;

/// Peers seen by one crawl of one chain.
#[derive(Serialize, Deserialize)]
pub struct PeerCache {
    /// Hex-encoded genesis hash of the chain, without `0x`. A cache is only
    /// used for the chain it was written for.
    pub genesis: String,
    /// When the cache was written.
    pub saved_at: String,
    /// The peers, validators first.
    pub peers: Vec<CachedPeer>,
}

/// One cached peer.
#[derive(Serialize, Deserialize)]
pub struct CachedPeer {
    /// Base58 peer ID.
    pub peer_id: String,
    /// Whether the peer belonged to the authority set when the cache was
    /// written.
    pub validator: bool,
    /// Public, dialable addresses carrying the `/p2p/<peer>` suffix. The
    /// addresses a connection was established on come first.
    pub addresses: Vec<String>,
}

impl PeerCache {
    /// Location of the cache for a chain: `cache/<chain>-peers.json`, or the
    /// first bytes of the genesis hash for chains without a known name.
    pub fn path(chain: Option<&str>, genesis: &str) -> PathBuf {
        let name = match chain {
            Some(chain) => chain.to_string(),
            None => genesis.trim_start_matches("0x").chars().take(8).collect(),
        };
        PathBuf::from(format!("cache/{}-peers.json", name))
    }

    /// Read the cache at `path`, `Ok(None)` when there is none. A cache
    /// written for another chain is an error rather than a silent cold start.
    pub fn load(path: &Path, genesis: &str) -> Result<Option<Self>, Box<dyn Error>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let cache: PeerCache = serde_json::from_slice(&bytes)?;

        let genesis = genesis.trim_start_matches("0x");
        if cache.genesis != genesis {
            return Err(format!(
                "{} was written for another chain (genesis {})",
                path.display(),
                cache.genesis
            )
            .into());
        }
        Ok(Some(cache))
    }

    /// Collect the peers of a finished crawl.
    ///
    /// For every peer the addresses are, in order: the ones a connection was
    /// established on, the ones from its DHT record, and the ones it reported
    /// over identify. Private addresses and transports the crawler cannot dial
    /// are left out.
    pub fn from_results(genesis: &str, results: &DiscoveryResults) -> Self {
        let (authority_to_details, peer_info, dial_outcomes, _) = results;

        let mut addresses: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let mut push = |peer: PeerId, address: Multiaddr| {
            if !is_public_address(&address) || !is_dialable_transport(&address) {
                return;
            }
            let address = with_peer_id(&address, peer);
            let entry = addresses.entry(peer).or_default();
            if !entry.contains(&address) {
                entry.push(address);
            }
        };

        // Kademlia connects to many regular nodes on the way to the records;
        // every one of those connections is a reachable address.
        for (address, outcome) in dial_outcomes {
            if let (DialOutcome::Success, Some(peer)) = (outcome, get_peer_id(address)) {
                push(peer, address.clone());
            }
        }

        let mut validators: HashSet<PeerId> = HashSet::new();
        for address in authority_to_details.values().flatten() {
            if let Some(peer) = get_peer_id(address) {
                validators.insert(peer);
                push(peer, address.clone());
            }
        }

        for (peer, info) in peer_info {
            for address in &info.listen_addrs {
                push(*peer, address.clone());
            }
        }

        let mut peers: Vec<CachedPeer> = addresses
            .into_iter()
            .filter(|(_, addresses)| !addresses.is_empty())
            .map(|(peer, addresses)| CachedPeer {
                peer_id: peer.to_string(),
                validator: validators.contains(&peer),
                addresses: addresses.iter().map(|a| a.to_string()).collect(),
            })
            .collect();
        peers.sort_by(|a, b| {
            b.validator
                .cmp(&a.validator)
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });

        PeerCache {
            genesis: genesis.trim_start_matches("0x").to_string(),
            saved_at: chrono::Utc::now().to_rfc3339(),
            peers,
        }
    }

    /// Write the cache to `path`, creating the directory if needed.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = BufWriter::new(File::create(path)?);
        serde_json::to_writer(file, self)?;
        Ok(())
    }

    /// Number of cached validators.
    pub fn validator_count(&self) -> usize {
        self.peers.iter().filter(|peer| peer.validator).count()
    }

    /// Every cached peer with its parsed addresses. Entries that do not parse
    /// are skipped.
    pub fn known_peers(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.peers.iter().filter_map(CachedPeer::parse).collect()
    }

    /// The cached validators with their parsed addresses.
    pub fn validators(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.peers
            .iter()
            .filter(|peer| peer.validator)
            .filter_map(CachedPeer::parse)
            .collect()
    }
}

impl CachedPeer {
    fn parse(&self) -> Option<(PeerId, Vec<Multiaddr>)> {
        let peer: PeerId = self.peer_id.parse().ok()?;
        let addresses: Vec<Multiaddr> = self
            .addresses
            .iter()
            .filter_map(|address| address.parse().ok())
            .collect();
        (!addresses.is_empty()).then_some((peer, addresses))
    }
}
