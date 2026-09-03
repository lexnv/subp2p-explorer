use litep2p::types::multihash::{Code as LiteP2pCode, Error as LiteP2pError, MultihashDigest as _};
use std::fmt::{self, Debug};

/// The multihash type shared by libp2p and litep2p since litep2p moved to
/// `multihash` 0.19: a 64-byte digest buffer.
type InnerMultihash = litep2p::types::multihash::Multihash<64>;

/// Multihash code of the identity hasher. `multihash-codetable` 0.2 dropped
/// it, so it is handled here directly.
const IDENTITY_CODE: u64 = 0x00;

/// Multihash code of SHA-256.
const SHA2_256_CODE: u64 = 0x12;

/// Default [`Multihash`] implementations. Only hashes used by substrate are defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// Identity hasher.
    Identity,
    /// SHA-256 (32-byte hash size).
    Sha2_256,
}

impl Code {
    /// Calculate digest using this [`Code`]'s hashing algorithm.
    ///
    /// The identity digest is the input itself, which must fit the 64-byte
    /// digest buffer; peer IDs inline keys of at most 42 bytes.
    pub fn digest(&self, input: &[u8]) -> Multihash {
        match self {
            Code::Identity => Multihash::wrap(IDENTITY_CODE, input)
                .expect("identity digests are inlined keys of at most 42 bytes; qed"),
            Code::Sha2_256 => LiteP2pCode::Sha2_256.digest(input).into(),
        }
    }
}

/// Error generated when converting to [`Code`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid multihash size.
    #[error("invalid multihash size '{0}'")]
    InvalidSize(u64),
    /// The multihash code is not supported.
    #[error("unsupported multihash code '{0:x}'")]
    UnsupportedCode(u64),
    /// Errors emitted when wrapping a digest or parsing a multihash from bytes.
    /// `multihash` 0.19 does not expose the error kind.
    #[error("other error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<LiteP2pError> for Error {
    fn from(error: LiteP2pError) -> Self {
        Self::Other(Box::new(error))
    }
}

impl TryFrom<u64> for Code {
    type Error = Error;

    fn try_from(code: u64) -> Result<Self, Self::Error> {
        match code {
            IDENTITY_CODE => Ok(Code::Identity),
            SHA2_256_CODE => Ok(Code::Sha2_256),
            code => Err(Error::UnsupportedCode(code)),
        }
    }
}

impl From<Code> for u64 {
    fn from(code: Code) -> Self {
        match code {
            Code::Identity => IDENTITY_CODE,
            Code::Sha2_256 => SHA2_256_CODE,
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct Multihash {
    multihash: InnerMultihash,
}

impl Multihash {
    /// Multihash code.
    pub fn code(&self) -> u64 {
        self.multihash.code()
    }

    /// Multihash digest.
    pub fn digest(&self) -> &[u8] {
        self.multihash.digest()
    }

    /// Wraps the digest in a multihash.
    pub fn wrap(code: u64, input_digest: &[u8]) -> Result<Self, Error> {
        InnerMultihash::wrap(code, input_digest)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Parses a multihash from bytes.
    ///
    /// You need to make sure the passed in bytes have the length of 64.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        InnerMultihash::from_bytes(bytes)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Returns the bytes of a multihash.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.multihash.to_bytes()
    }
}

/// Remove extra layer of nestedness by deferring to the wrapped value's [`Debug`].
impl Debug for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.multihash, f)
    }
}

impl From<InnerMultihash> for Multihash {
    fn from(multihash: InnerMultihash) -> Self {
        Multihash { multihash }
    }
}

impl From<Multihash> for InnerMultihash {
    fn from(multihash: Multihash) -> Self {
        multihash.multihash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_from_u64() {
        assert_eq!(Code::try_from(0x00).unwrap(), Code::Identity);
        assert_eq!(Code::try_from(0x12).unwrap(), Code::Sha2_256);
        assert!(matches!(
            Code::try_from(0x01).unwrap_err(),
            Error::UnsupportedCode(0x01)
        ));
    }

    #[test]
    fn code_into_u64() {
        assert_eq!(u64::from(Code::Identity), 0x00);
        assert_eq!(u64::from(Code::Sha2_256), 0x12);
    }

    #[test]
    fn digest_round_trips() {
        let identity = Code::Identity.digest(b"inline key");
        assert_eq!(identity.code(), 0x00);
        assert_eq!(identity.digest(), b"inline key");

        let sha = Code::Sha2_256.digest(b"payload");
        assert_eq!(sha.code(), 0x12);
        assert_eq!(sha.digest().len(), 32);
        assert_eq!(Multihash::from_bytes(&sha.to_bytes()).unwrap(), sha);
    }
}
