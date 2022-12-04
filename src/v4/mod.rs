use byteorder::{BigEndian, ByteOrder};
#[cfg(not(feature = "tokio"))]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use thiserror::Error;
#[cfg(feature = "tokio")]
use tokio_compat::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod types;

use crate::SocksVersion;
pub use types::*;

#[derive(Debug, Error)]
pub enum SocksV4RequestError {
    #[error("invalid SOCKS version {0:02X}, expected {:02X}", SocksVersion::V4.to_u8())]
    InvalidVersion(u8),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

#[derive(Debug)]
pub enum SocksV4Host {
    Domain(Vec<u8>),
    Ip([u8; 4]),
}

#[derive(Debug)]
pub struct SocksV4Request {
    pub command: SocksV4Command,
    pub port: u16,
    pub host: SocksV4Host,
    pub userid: Vec<u8>,
}

pub type SocksV4RequestResult = Result<SocksV4Request, SocksV4RequestError>;

pub async fn read_request<Reader>(mut reader: Reader) -> SocksV4RequestResult
where
    Reader: AsyncRead + Unpin,
{
    let mut version = [0u8];
    reader.read_exact(&mut version).await?;
    let version = version[0];

    if version != SocksVersion::V4.to_u8() {
        return Err(SocksV4RequestError::InvalidVersion(version));
    }

    read_request_skip_version(reader).await
}

pub async fn read_request_skip_version<Reader>(mut reader: Reader) -> SocksV4RequestResult
where
    Reader: AsyncRead + Unpin,
{
    let mut command = [0u8];
    reader.read_exact(&mut command).await?;

    let command = SocksV4Command::from_u8(command[0]).ok_or_else(|| {
        SocksV4RequestError::InvalidRequest(format!(
            "invalid command {:x}, expected {:x} (CONNECT) or {:x} (BIND)",
            command[0],
            SocksV4Command::Bind.to_u8(),
            SocksV4Command::Connect.to_u8(),
        ))
    })?;

    let mut dstport = [0u8; 2];
    reader.read_exact(&mut dstport).await?;
    let port = BigEndian::read_u16(&dstport);

    let mut dstip = [0u8; 4];
    reader.read_exact(&mut dstip).await?;

    let mut userid = vec![];
    let mut byte = [0u8];
    loop {
        reader.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            break;
        }
        userid.push(byte[0]);
    }

    // V4a
    let host = if dstip[..3] == [0, 0, 0] && dstip[3] != 0 {
        let mut domain = vec![];
        let mut byte = [0u8];
        loop {
            reader.read_exact(&mut byte).await?;
            if byte[0] == 0 {
                break;
            }
            domain.push(byte[0]);
        }
        SocksV4Host::Domain(domain)
    } else {
        SocksV4Host::Ip(dstip)
    };

    Ok(SocksV4Request {
        command,
        port,
        host,
        userid,
    })
}

pub async fn write_request_status<Writer>(
    mut writer: Writer,
    status: SocksV4RequestStatus,
    host: [u8; 4],
    port: u16,
) -> std::io::Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8];
    buf[1] = status.to_u8();
    BigEndian::write_u16(&mut buf[2..4], port);
    buf[4..8].copy_from_slice(&host);
    writer.write_all(&buf).await?;
    Ok(())
}
