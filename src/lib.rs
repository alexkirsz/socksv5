use thiserror::Error;

use crate::io::*;

pub mod v4;
pub mod v5;

pub(crate) mod io {
    #[cfg(not(feature = "tokio"))]
    pub use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    #[cfg(feature = "tokio")]
    pub use tokio_compat::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
}

#[derive(Debug, Eq, PartialEq)]
pub enum SocksVersion {
    V4 = 0x04,
    V5 = 0x05,
}

impl SocksVersion {
    pub fn from_u8(n: u8) -> Option<SocksVersion> {
        match n {
            0x04 => Some(SocksVersion::V4),
            0x05 => Some(SocksVersion::V5),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SocksVersion::V4 => 0x04,
            SocksVersion::V5 => 0x05,
        }
    }
}

#[derive(Debug, Error)]
pub enum SocksVersionError {
    #[error("invalid version {0:x}, expected {:x} or {:x}", SocksVersion::V4.to_u8(), SocksVersion::V5 as u8)]
    InvalidVersion(u8),
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

pub type SocksVersionResult = Result<SocksVersion, SocksVersionError>;

pub async fn read_version<Stream>(mut stream: Stream) -> SocksVersionResult
where
    Stream: AsyncRead + Unpin,
{
    let mut version = [0u8];
    stream.read_exact(&mut version).await?;
    SocksVersion::from_u8(version[0]).ok_or_else(|| SocksVersionError::InvalidVersion(version[0]))
}
