use futures::prelude::*;
use libp2p::core::upgrade::{InboundUpgrade, UpgradeInfo};
use std::{
    pin::Pin,
    task::{Context, Poll},
    vec,
};

/// Upgrade that combines multiple upgrades into one.
///
/// Similar to [`libp2p::core::upgrade::SelectUpgrade`].
#[derive(Debug, Clone)]
pub struct CombineUpgrades<T>(pub Vec<T>);

impl<T> From<Vec<T>> for CombineUpgrades<T> {
    fn from(list: Vec<T>) -> Self {
        Self(list)
    }
}

impl<T: UpgradeInfo> UpgradeInfo for CombineUpgrades<T> {
    type Info = ProtocolResponse<T::Info>;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.0
            .iter()
            .enumerate()
            .flat_map(|(index, protocol)| {
                protocol
                    .protocol_info()
                    .into_iter()
                    .map(move |data| ProtocolResponse { data, index })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl<T, C> InboundUpgrade<C> for CombineUpgrades<T>
where
    T: InboundUpgrade<C>,
{
    type Output = ProtocolResponse<T::Output>;
    type Error = ProtocolResponse<T::Error>;
    type Future = FutureProtocolResponse<T::Future>;

    fn upgrade_inbound(mut self, sock: C, info: Self::Info) -> Self::Future {
        // Negociated only once.
        let protocol = self.0.remove(info.index);
        let future = protocol.upgrade_inbound(sock, info.data);

        FutureProtocolResponse {
            data: future,
            index: info.index,
        }
    }
}

/// The associated type of [`UpgradeInfo`].
#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolResponse<T> {
    /// Opaque data representing a negotiable protocol.
    pub data: T,
    /// The index of the protocol.
    pub index: usize,
}

impl<T: AsRef<str>> AsRef<str> for ProtocolResponse<T> {
    fn as_ref(&self) -> &str {
        self.data.as_ref()
    }
}

/// Groups the returned future result together with the protocol index.
#[pin_project::pin_project]
pub struct FutureProtocolResponse<T> {
    /// Future that handles the upgrade process.
    #[pin]
    data: T,
    /// The index of the protocol.
    index: usize,
}

impl<Out, Err, T> Future for FutureProtocolResponse<T>
where
    T: Future<Output = Result<Out, Err>>,
{
    type Output = Result<ProtocolResponse<Out>, ProtocolResponse<Err>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.project();

        match Future::poll(this.data, cx) {
            Poll::Ready(Ok(value)) => Poll::Ready(Ok(ProtocolResponse {
                data: value,
                index: *this.index,
            })),
            Poll::Ready(Err(error)) => Poll::Ready(Err(ProtocolResponse {
                data: error,
                index: *this.index,
            })),
            Poll::Pending => Poll::Pending,
        }
    }
}
