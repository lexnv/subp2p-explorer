// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! Implements a 2-way handshake between peers for
//! establishing notification protocol streams.
//!
//! Notification protocols, as defined by substrate, are
//! unidirectional in nature.
//!
//! # Handshake
//!
//! Considering a bidirectional connection between 2 peers A and B.
//! A dials a connection with B, the following represent the handshake steps:
//!
//! 1. A submits a handshake to B
//!   - The handshake is protocol specific
//!   - The handshake is LBE128-prefix encoded over the wire
//!
//! 2. B reads the handshake from A
//!
//! 3. B submits the handshake to A
//!
//! 4. A reads the handshake.

use asynchronous_codec::Framed;
use bytes::BytesMut;
use futures::prelude::*;
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use log::{error, warn};
use unsigned_varint::codec::UviBytes;

use std::{
    convert::Infallible,
    io, mem,
    pin::Pin,
    task::{Context, Poll},
    vec,
};

/// Maximum allowed size of the handshake message in bytes.
const MAX_HANDSHAKE_SIZE: usize = 1024;

/// Upgrade that accepts a substream and sends back a handshake message.
#[derive(Debug, Clone)]
pub struct HandshakeInbound {
    /// Protocol name.
    pub name: String,
}

/// A substream for incoming notification messages.
///
/// When creating, this struct starts in a state in which we must first send back a handshake
/// message to the remote. No message will come before this has been done.
#[pin_project::pin_project]
pub struct HandshakeInboundSubstream<TSubstream> {
    #[pin]
    socket: Framed<TSubstream, UviBytes<io::Cursor<Vec<u8>>>>,
    state: HandshakeInboundSubstreamState,
    negotiated_name: String,
}

/// State of the handshake sending back process.
#[derive(Debug)]
pub enum HandshakeInboundSubstreamState {
    /// Wait for the higher levels to provide the handshake.
    Waiting,
    /// Push the handshake to the socket.
    Sending(Vec<u8>),
    /// Needs to flush the socket.
    Flush,
    /// Handshake was sent.
    Done,
    /// Remote has closed their writing side. We close our own writing side in return.
    NeedsClose,
    /// Both our side and the remote have closed their writing side.
    FullyClosed,
}

/// Upgrade that opens a substream, waits for the remote to accept by sending back a status
/// message, then becomes a unidirectional sink of data.
#[derive(Debug, Clone)]
pub struct HandshakeOutbound {
    /// Protocol name.
    pub name: String,
    /// Handshake message.
    pub handshake: Vec<u8>,
}

/// A substream for outgoing notification messages.
#[pin_project::pin_project]
pub struct HandshakeOutboundSubstream<TSubstream> {
    /// Substream where to send messages.
    #[pin]
    socket: Framed<TSubstream, UviBytes<io::Cursor<Vec<u8>>>>,
}

impl HandshakeInbound {
    /// Constructs a new [`HandshakeInbound`].
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl UpgradeInfo for HandshakeInbound {
    type Info = String;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.name.clone()].into_iter()
    }
}

impl<TSubstream> InboundUpgrade<TSubstream> for HandshakeInbound
where
    TSubstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = HandshakeInboundOpen<TSubstream>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;
    type Error = HandshakeError;

    fn upgrade_inbound(self, mut socket: TSubstream, negotiated_name: Self::Info) -> Self::Future {
        log::info!(
            "HandshakeInbound name={:?} current_name={:?}",
            negotiated_name,
            self.name
        );

        Box::pin(async move {
            let handshake_len = unsigned_varint::aio::read_usize(&mut socket).await?;
            log::debug!(
                "HandshakeInbound length={:?} name={:?}",
                handshake_len,
                negotiated_name
            );

            // Discard larger handshakes.
            if handshake_len > MAX_HANDSHAKE_SIZE {
                return Err(HandshakeError::TooLarge {
                    requested: handshake_len,
                    max: MAX_HANDSHAKE_SIZE,
                });
            }

            let mut handshake = vec![0u8; handshake_len];
            // Note: should always have data for substrate chains.
            if !handshake.is_empty() {
                socket.read_exact(&mut handshake).await?;
            }

            log::debug!(
                "HandshakeInbound received handshake={:?} name={:?}",
                handshake,
                negotiated_name
            );

            let mut codec: UviBytes<io::Cursor<Vec<u8>>> = UviBytes::default();
            codec.set_max_len(usize::MAX);

            // Create a handshake substream that waits the handshake from the higher level.
            let substream = HandshakeInboundSubstream {
                socket: Framed::new(socket, codec),
                state: HandshakeInboundSubstreamState::Waiting,
                negotiated_name,
            };

            Ok(HandshakeInboundOpen {
                handshake,
                substream,
            })
        })
    }
}

/// Generated by [`HandshakeInbound`] after reading the peer handshake.
pub struct HandshakeInboundOpen<TSubstream> {
    /// Handshake sent by the remote.
    pub handshake: Vec<u8>,
    /// Implementation of `Stream` receives messages from the substream.
    pub substream: HandshakeInboundSubstream<TSubstream>,
}

impl<TSubstream> HandshakeInboundSubstream<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Unpin,
{
    pub fn set_handshake(&mut self, handshake: Vec<u8>) {
        match &self.state {
            HandshakeInboundSubstreamState::Waiting => (),
            _ => return,
        };

        self.state = HandshakeInboundSubstreamState::Sending(handshake);
    }

    /// Similar to [`poll_next`] without event generation.
    ///
    /// Returns `Poll::Ready` only for errors.
    pub fn poll_process(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<Infallible, io::Error>> {
        let mut this = self.project();

        loop {
            // Move out the state data to own the handshake (if any).
            let state = mem::replace(this.state, HandshakeInboundSubstreamState::Done);

            match state {
                HandshakeInboundSubstreamState::Sending(handshake) => {
                    match Sink::poll_ready(this.socket.as_mut(), cx) {
                        Poll::Ready(_) => {
                            log::debug!("HandshakeInboundSubstream: poll_process: Sink is ready start sendind name={:?}", this.negotiated_name);

                            *this.state = HandshakeInboundSubstreamState::Flush;

                            match Sink::start_send(this.socket.as_mut(), io::Cursor::new(handshake))
                            {
                                Ok(()) => {}
                                Err(err) => {
                                    log::error!("HandshakeInboundSubstream: poll_process: Failed to start seding name={:?} error={:?}", this.negotiated_name, err);

                                    return Poll::Ready(Err(err));
                                }
                            }
                        }
                        Poll::Pending => {
                            *this.state = HandshakeInboundSubstreamState::Sending(handshake);
                            return Poll::Pending;
                        }
                    }
                }

                HandshakeInboundSubstreamState::Flush => {
                    log::debug!(
                        "HandshakeInboundSubstream: poll_process: poll_flush name={:?}",
                        this.negotiated_name
                    );
                    match Sink::poll_flush(this.socket.as_mut(), cx)? {
                        Poll::Ready(()) => *this.state = HandshakeInboundSubstreamState::Done,
                        Poll::Pending => {
                            *this.state = HandshakeInboundSubstreamState::Flush;
                            return Poll::Pending;
                        }
                    }
                }

                state => {
                    *this.state = state;
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<TSubstream> Stream for HandshakeInboundSubstream<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<BytesMut, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            // Move out the state data to own the handshake (if any).
            let state = mem::replace(this.state, HandshakeInboundSubstreamState::Done);

            log::debug!(
                "HandshakeInboundSubstream: poll_next: state={:?} name={:?}",
                state,
                this.negotiated_name
            );

            match state {
                HandshakeInboundSubstreamState::Waiting => {
                    *this.state = HandshakeInboundSubstreamState::Waiting;
                    return Poll::Pending;
                }
                HandshakeInboundSubstreamState::Sending(handshake) => {
                    match Sink::poll_ready(this.socket.as_mut(), cx) {
                        Poll::Ready(_) => {
                            *this.state = HandshakeInboundSubstreamState::Flush;

                            match Sink::start_send(this.socket.as_mut(), io::Cursor::new(handshake))
                            {
                                Ok(()) => (),
                                Err(err) => {
                                    log::trace!(
                                        "HandshakeInboundSubstream: Cannot send handshake name={:?}",
                                        this.negotiated_name
                                    );

                                    return Poll::Ready(Some(Err(err)));
                                }
                            }
                        }
                        Poll::Pending => {
                            *this.state = HandshakeInboundSubstreamState::Sending(handshake);
                            return Poll::Pending;
                        }
                    }
                }
                HandshakeInboundSubstreamState::Flush => {
                    match Sink::poll_flush(this.socket.as_mut(), cx)? {
                        Poll::Ready(()) => *this.state = HandshakeInboundSubstreamState::Done,
                        Poll::Pending => {
                            *this.state = HandshakeInboundSubstreamState::Flush;
                            return Poll::Pending;
                        }
                    }
                }
                HandshakeInboundSubstreamState::Done => {
                    match Stream::poll_next(this.socket.as_mut(), cx) {
                        Poll::Ready(None) => {
                            log::debug!(
								"HandshakeInboundSubstream: poll_next: Closing in response to peer name={:?}",
                                this.negotiated_name
							);
                            *this.state = HandshakeInboundSubstreamState::NeedsClose
                        }
                        Poll::Ready(Some(result)) => {
                            *this.state = HandshakeInboundSubstreamState::Done;
                            return Poll::Ready(Some(result));
                        }
                        Poll::Pending => {
                            *this.state = HandshakeInboundSubstreamState::Done;
                            return Poll::Pending;
                        }
                    }
                }
                HandshakeInboundSubstreamState::NeedsClose => {
                    match Sink::poll_close(this.socket.as_mut(), cx)? {
                        Poll::Ready(()) => {
                            log::debug!(
                                "HandshakeInboundSubstream: poll_close: fully clsoed name={:?}",
                                this.negotiated_name
                            );
                            *this.state = HandshakeInboundSubstreamState::FullyClosed
                        }
                        Poll::Pending => {
                            *this.state = HandshakeInboundSubstreamState::NeedsClose;
                            return Poll::Pending;
                        }
                    }
                }
                HandshakeInboundSubstreamState::FullyClosed => return Poll::Ready(None),
            }
        }
    }
}

impl HandshakeOutbound {
    /// Constructs a new [`HandshakeOutbound`].
    pub fn new(name: impl Into<String>, handshake: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            handshake: handshake.into(),
        }
    }
}

impl UpgradeInfo for HandshakeOutbound {
    type Info = String;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.name.clone()].into_iter()
    }
}

impl<TSubstream> OutboundUpgrade<TSubstream> for HandshakeOutbound
where
    TSubstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = HandshakeOutboundOpen<TSubstream>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;
    type Error = HandshakeError;

    fn upgrade_outbound(self, mut socket: TSubstream, negotiated_name: Self::Info) -> Self::Future {
        log::info!(
            "HandshakeOutbound name={:?} current_name={:?}",
            negotiated_name,
            self.name
        );

        Box::pin(async move {
            log::debug!(
                "HandshakeOutbound prepare to write handshake={:?} name={:?}",
                self.handshake,
                negotiated_name
            );

            upgrade::write_length_prefixed(&mut socket, &self.handshake).await?;

            log::debug!(
                "HandshakeOutbound prepare to read handshake length name={:?}",
                negotiated_name
            );

            let handshake_len = unsigned_varint::aio::read_usize(&mut socket).await?;

            log::debug!(
                "HandshakeOutbound handshake len={:?} name={:?}",
                handshake_len,
                negotiated_name
            );

            if handshake_len > MAX_HANDSHAKE_SIZE {
                return Err(HandshakeError::TooLarge {
                    requested: handshake_len,
                    max: MAX_HANDSHAKE_SIZE,
                });
            }

            let mut handshake = vec![0u8; handshake_len];
            if !handshake.is_empty() {
                socket.read_exact(&mut handshake).await?;
            }

            let mut codec = UviBytes::default();
            codec.set_max_len(usize::MAX);

            Ok(HandshakeOutboundOpen {
                handshake,
                substream: HandshakeOutboundSubstream {
                    socket: Framed::new(socket, codec),
                },
            })
        })
    }
}

/// Yielded by the [`NotificationsOut`] after a successfuly upgrade.
pub struct HandshakeOutboundOpen<TSubstream> {
    /// Handshake returned by the remote.
    pub handshake: Vec<u8>,
    /// Implementation of `Sink` that allows sending messages on the substream.
    pub substream: HandshakeOutboundSubstream<TSubstream>,
}

impl<TSubstream> Sink<Vec<u8>> for HandshakeOutboundSubstream<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Unpin,
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        Sink::poll_ready(this.socket.as_mut(), cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let mut this = self.project();
        Sink::start_send(this.socket.as_mut(), io::Cursor::new(item))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        Sink::poll_flush(this.socket.as_mut(), cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        Sink::poll_close(this.socket.as_mut(), cx)
    }
}

/// Error generated by sending on a notifications out substream.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// I/O error on the substream.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Initial message or handshake was too large.
    #[error("Initial message or handshake was too large: {requested}")]
    TooLarge {
        /// Size requested by the remote.
        requested: usize,
        /// Maximum allowed,
        max: usize,
    },
    /// Error while decoding the variable-length integer.
    #[error(transparent)]
    VarintDecode(#[from] unsigned_varint::decode::Error),
}

impl From<unsigned_varint::io::ReadError> for HandshakeError {
    fn from(err: unsigned_varint::io::ReadError) -> Self {
        match err {
            unsigned_varint::io::ReadError::Io(err) => Self::Io(err),
            unsigned_varint::io::ReadError::Decode(err) => Self::VarintDecode(err),
            _ => {
                warn!("Unrecognized varint decoding error");
                Self::Io(From::from(io::ErrorKind::InvalidData))
            }
        }
    }
}

/// Error generated by sending on a notifications out substream.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeOutboundError {
    /// I/O error on the substream.
    #[error(transparent)]
    Io(#[from] io::Error),
}
