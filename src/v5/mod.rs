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
pub enum SocksV5HandshakeError {
    #[error("invalid SOCKS version {0:02X}, expected {:02X}", SocksVersion::V5.to_u8())]
    InvalidVersion(u8),
    #[error("invalid request: {0}")]
    InvalidHandshake(String),
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

#[derive(Debug)]
pub struct SocksV5Handshake {
    pub methods: Vec<SocksV5AuthMethod>,
}

pub type SocksV5HandshakeResult = Result<SocksV5Handshake, SocksV5HandshakeError>;

pub async fn read_handshake<Reader>(mut reader: Reader) -> SocksV5HandshakeResult
where
    Reader: AsyncRead + Unpin,
{
    let mut version = [0u8];
    reader.read_exact(&mut version).await?;
    let version = version[0];

    if version != SocksVersion::V5.to_u8() {
        return Err(SocksV5HandshakeError::InvalidVersion(version));
    }

    read_handshake_skip_version(reader).await
}

pub async fn read_handshake_skip_version<Reader>(mut reader: Reader) -> SocksV5HandshakeResult
where
    Reader: AsyncRead + Unpin,
{
    let mut nmethods = [0u8];
    reader.read_exact(&mut nmethods).await?;
    let nmethods = nmethods[0];

    if nmethods == 0 {
        return Err(SocksV5HandshakeError::InvalidHandshake(
            "handshake must provide at least one authentication method".to_owned(),
        ));
    }

    let mut methods = vec![0u8; nmethods as usize];
    reader.read_exact(&mut methods).await?;
    let methods: Vec<SocksV5AuthMethod> = methods
        .into_iter()
        .map(|method| SocksV5AuthMethod::from_u8(method))
        .collect();

    Ok(SocksV5Handshake { methods })
}

pub async fn write_auth_method<Writer>(
    mut writer: Writer,
    status: SocksV5AuthMethod,
) -> std::io::Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    writer
        .write_all(&[SocksVersion::V5.to_u8(), status.to_u8()])
        .await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum SocksV5RequestError {
    #[error("invalid SOCKS version {0:02X}, expected {:02X}", SocksVersion::V5.to_u8())]
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
pub enum SocksV5Host {
    Domain(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

#[derive(Debug)]
pub struct SocksV5Request {
    pub command: SocksV5Command,
    pub host: SocksV5Host,
    pub port: u16,
}

pub type SocksV5RequestResult = Result<SocksV5Request, SocksV5RequestError>;

pub async fn read_request<Reader>(mut reader: Reader) -> SocksV5RequestResult
where
    Reader: AsyncRead + Unpin,
{
    let mut version = [0u8];
    reader.read_exact(&mut version).await?;
    let version = version[0];

    if version != SocksVersion::V5.to_u8() {
        return Err(SocksV5RequestError::InvalidVersion(version));
    }

    let mut command = [0u8];
    reader.read_exact(&mut command).await?;
    let command = SocksV5Command::from_u8(command[0]).ok_or_else(|| {
        SocksV5RequestError::InvalidRequest(format!(
            "invalid command {:02X}, expected {:02X} (CONNECT), {:02X} (BIND), or  {:02X} (UDP ASSOCIATE)",
            command[0],
            SocksV5Command::Bind.to_u8(),
            SocksV5Command::Connect.to_u8(),
            SocksV5Command::UdpAssociate.to_u8(),
        ))
    })?;

    // Skip RSV
    reader.read_exact(&mut [0]).await?;

    let mut atyp = [0u8];
    reader.read_exact(&mut atyp).await?;
    let atyp = SocksV5AddressType::from_u8(atyp[0]).ok_or_else(|| {
        SocksV5RequestError::InvalidRequest(format!(
            "invalid address type {:02X}, expected {:02X} (IP V4), {:02X} (DOMAINNAME), or  {:02X} (IP V6)",
            atyp[0],
            SocksV5AddressType::Ipv4.to_u8(),
            SocksV5AddressType::Domain.to_u8(),
            SocksV5AddressType::Ipv6.to_u8(),
        ))
    })?;

    let host = match atyp {
        SocksV5AddressType::Ipv4 => {
            let mut host = [0u8; 4];
            reader.read_exact(&mut host).await?;
            SocksV5Host::Ipv4(host)
        }
        SocksV5AddressType::Ipv6 => {
            let mut host = [0u8; 16];
            reader.read_exact(&mut host).await?;
            SocksV5Host::Ipv6(host)
        }
        SocksV5AddressType::Domain => {
            let mut domain_length = [0u8];
            reader.read_exact(&mut domain_length).await?;
            let mut domain = vec![0u8; domain_length[0] as usize];
            reader.read_exact(&mut domain).await?;
            SocksV5Host::Domain(domain)
        }
    };

    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    let port = BigEndian::read_u16(&port);

    Ok(SocksV5Request {
        command,
        port,
        host,
    })
}

pub async fn write_request_status<Writer>(
    mut writer: Writer,
    status: SocksV5RequestStatus,
    host: SocksV5Host,
    port: u16,
) -> std::io::Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    let mut buf = vec![
        0u8;
        6 + match &host {
            SocksV5Host::Ipv4(_) => 4,
            SocksV5Host::Ipv6(_) => 16,
            SocksV5Host::Domain(d) => 1 + d.len(),
        }
    ];
    buf[0] = SocksVersion::V5.to_u8();
    buf[1] = status.to_u8();
    let idx = match &host {
        SocksV5Host::Ipv4(ip) => {
            buf[3] = SocksV5AddressType::Ipv4.to_u8();
            buf[4..8].clone_from_slice(ip);
            8
        }
        SocksV5Host::Ipv6(ip) => {
            buf[3] = SocksV5AddressType::Ipv6.to_u8();
            buf[4..20].clone_from_slice(ip);
            20
        }
        SocksV5Host::Domain(d) => {
            buf[3] = SocksV5AddressType::Domain.to_u8();
            buf[4] = d.len() as u8;
            buf[5..5 + d.len()].clone_from_slice(d);
            5 + d.len()
        }
    };
    BigEndian::write_u16(&mut buf[idx..idx + 2], port);
    writer.write_all(&buf).await?;
    Ok(())
}
