use byteorder::{ByteOrder, NetworkEndian};
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

/// Writes a SOCKSv5 "version identifier/method selection message",
/// requesting the specified authentication methods.
///
/// The methods are added to the request as they are returned by the supplied iterator;
/// no ordering or deduplication is performed. However, if `methods` returns more than 255 values,
/// this function will silently truncate the list to 255 elements (the maximum allowed by the spec).
///
/// # Errors
///
/// If writing to `writer` fails, this function will return the I/O error.
///
/// # Panics
///
/// If the list of auth methods is empty. The SOCKSv5 specification requires at least one method to be specified.
pub async fn write_handshake<Writer, Methods>(
    mut writer: Writer,
    methods: Methods,
) -> std::io::Result<()>
where
    Writer: AsyncWrite + Unpin,
    Methods: IntoIterator<Item = SocksV5AuthMethod>,
{
    let mut data = vec![SocksVersion::V5.to_u8(), 0u8];
    data.extend(methods.into_iter().take(255).map(|m| m.to_u8()));
    let method_count = (data.len() - 2) as u8;
    assert!(method_count > 0, "must specify at least one auth method");
    data[1] = method_count;
    writer.write_all(&data).await
}

pub type SocksV5AuthMethodResult = Result<SocksV5AuthMethod, SocksV5HandshakeError>;

/// Reads a SOCKSv5 "METHOD selection message", verifying the protocol version
/// and returning the authentication method selected by the server.
///
/// This function consumes from 0 to 2 bytes from `reader`, depending on the data and errors.
/// When the result is successful, it will have consumed exactly 2 bytes.
///
/// # Errors
///
/// If reading from `reader` fails, including if a premature EOF is encountered,
/// this function will return the I/O error (wrapped in `SocksV5HandshakeError::Io`).
///
/// If the first byte read from `reader` is not `05`, as required by the SOCKSv5 specification,
/// then this function will return `SocksV5HandshakeError::InvalidVersion` with the actual "version number".
pub async fn read_auth_method<Reader>(mut reader: Reader) -> SocksV5AuthMethodResult
where
    Reader: AsyncRead + Unpin,
{
    let mut data = [0u8];
    // read protocol version
    reader.read_exact(&mut data).await?;
    if data[0] != SocksVersion::V5.to_u8() {
        return Err(SocksV5HandshakeError::InvalidVersion(data[0]));
    }
    // read selected auth method
    reader.read_exact(&mut data).await?;
    Ok(SocksV5AuthMethod::from_u8(data[0]))
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
    let port = NetworkEndian::read_u16(&port);

    Ok(SocksV5Request {
        command,
        port,
        host,
    })
}

/// Writes a SOCKSv5 request with the specified command, host and port.
///
/// # Errors
///
/// If writing to `writer` fails, this function will return the I/O error.
///
/// # Panics
///
/// If `host` is a domain name, the length of which is greater than 255 bytes.
/// The SOCKSv5 specification leaves only a single octet for encoding the domain name length,
/// so a target longer than 255 bytes cannot be properly encoded.
pub async fn write_request<Writer>(
    mut writer: Writer,
    command: SocksV5Command,
    host: SocksV5Host,
    port: u16,
) -> std::io::Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    let mut data = Vec::<u8>::with_capacity(
        6 + match &host {
            SocksV5Host::Domain(domain) => {
                assert!(
                    domain.len() <= 256,
                    "domain name must be shorter than 256 bytes"
                );
                1 + domain.len()
            }
            SocksV5Host::Ipv4(_) => 4,
            SocksV5Host::Ipv6(_) => 16,
        },
    );
    data.push(SocksVersion::V5.to_u8());
    data.push(command.to_u8());
    data.push(0u8); // reserved bits in SOCKSv5
    match &host {
        SocksV5Host::Domain(domain) => {
            data.push(SocksV5AddressType::Domain.to_u8());
            data.push(domain.len() as u8);
            data.extend_from_slice(domain);
        }
        SocksV5Host::Ipv4(octets) => {
            data.push(SocksV5AddressType::Ipv4.to_u8());
            data.extend_from_slice(octets);
        }
        SocksV5Host::Ipv6(octets) => {
            data.push(SocksV5AddressType::Ipv6.to_u8());
            data.extend_from_slice(octets);
        }
    }
    let port_start = data.len();
    data.extend_from_slice(b"\0\0");
    NetworkEndian::write_u16(&mut data[port_start..], port);

    writer.write_all(&data).await
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
            buf[4..8].copy_from_slice(ip);
            8
        }
        SocksV5Host::Ipv6(ip) => {
            buf[3] = SocksV5AddressType::Ipv6.to_u8();
            buf[4..20].copy_from_slice(ip);
            20
        }
        SocksV5Host::Domain(d) => {
            buf[3] = SocksV5AddressType::Domain.to_u8();
            buf[4] = d.len() as u8;
            buf[5..5 + d.len()].copy_from_slice(d);
            5 + d.len()
        }
    };
    NetworkEndian::write_u16(&mut buf[idx..idx + 2], port);
    writer.write_all(&buf).await?;
    Ok(())
}
