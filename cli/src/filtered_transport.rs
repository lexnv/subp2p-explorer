// Copyright 2024 Zondax GmbH
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! Filtered transport wrapper that blocks connections to private IP addresses.

use ip_network::IpNetwork;
use libp2p::{
    core::transport::{DialOpts, ListenerId, TransportError, TransportEvent},
    multiaddr::Protocol,
    Multiaddr, Transport,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Wrapper transport that filters out private IP addresses before dialing.
#[derive(Debug, Clone)]
pub struct FilteredTransport<T> {
    inner: T,
}

impl<T> FilteredTransport<T> {
    /// Create a new filtered transport wrapping the given transport.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

/// Check if an address is a private/non-global IP address.
fn is_private_address(addr: &Multiaddr) -> bool {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                let network = IpNetwork::from(ip);
                if !network.is_global() {
                    log::debug!("Blocking private IPv4 address: {}", ip);
                    return true;
                }
            }
            Protocol::Ip6(ip) => {
                let network = IpNetwork::from(ip);
                if !network.is_global() {
                    log::debug!("Blocking private IPv6 address: {}", ip);
                    return true;
                }
            }
            // DNS addresses need resolution - we allow them
            // (the resolved IP will be checked by the underlying transport if needed)
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => {
                // Allow DNS - will be resolved later
            }
            _ => {}
        }
    }
    false
}

impl<T> Transport for FilteredTransport<T>
where
    T: Transport,
    T::Error: 'static,
{
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if is_private_address(&addr) {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        self.inner.dial(addr, opts)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        // SAFETY: We're not moving `inner`, just getting a pinned reference to it
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        inner.poll(cx)
    }
}
