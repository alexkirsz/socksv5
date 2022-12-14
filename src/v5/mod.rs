use byteorder::{ByteOrder, NetworkEndian};
#[cfg(not(feature = "tokio"))]
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use thiserror::Error;
#[cfg(feature = "tokio")]
use tokio_compat::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod handshake;
mod hosts;
mod types;

use crate::SocksVersion;
pub use handshake::*;
pub use hosts::*;
pub use types::*;

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
            "invalid command {:02X}, expected {:02X} (CONNECT), {:02X} (BIND), or {:02X} (UDP ASSOCIATE)",
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

#[derive(Debug)]
pub struct SocksV5Response {
    pub status: SocksV5RequestStatus,
    pub host: SocksV5Host,
    pub port: u16,
}

pub type SocksV5ResponseResult = Result<SocksV5Response, SocksV5RequestError>;

/// Reads and parses a SOCKSv5 command response message.
///
/// Depending on the data (in case of parsing errors),
/// this function may not consume the whole response from the server.
///
/// # Errors
///
/// If reading from `reader` fails, including if a premature EOF is encountered,
/// this function will return the I/O error (wrapped in `SocksV5RequestError::Io`).
///
/// If the first byte read from `reader` is not `05`, as required by the SOCKSv5 specification,
/// then this function will return `SocksV5RequestError::InvalidVersion` with the actual "version number".
///
/// If the status byte or the address type byte are not from the respective lists in the specification,
/// then this function will return `SocksV5RequestError::InvalidRequest`
/// with a human-readable description of the error.
pub async fn read_request_status<Reader>(mut reader: Reader) -> SocksV5ResponseResult
where
    Reader: AsyncRead + Unpin,
{
    let mut buf = [0u8; 2];

    reader.read_exact(&mut buf[0..1]).await?;
    if buf[0] != SocksVersion::V5.to_u8() {
        return Err(SocksV5RequestError::InvalidVersion(buf[0]));
    }

    reader.read_exact(&mut buf[0..1]).await?;
    let status = SocksV5RequestStatus::from_u8(buf[0]).ok_or_else(|| {
        SocksV5RequestError::InvalidRequest(format!("invalid status {:02X}", buf[0]))
    })?;

    reader.read_exact(&mut buf).await?;
    // ignore a reserved octet, use the following one
    let atyp = SocksV5AddressType::from_u8(buf[1]).ok_or_else(|| {
        SocksV5RequestError::InvalidRequest(format!(
            "invalid address type {:02X}, expected {:02X} (IP V4), {:02X} (DOMAINNAME), or {:02X} (IP V6)",
            buf[1],
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
            reader.read_exact(&mut buf[0..1]).await?;
            let mut domain = vec![0u8; buf[0] as usize];
            reader.read_exact(&mut domain).await?;
            SocksV5Host::Domain(domain)
        }
    };

    reader.read_exact(&mut buf).await?;
    let port = NetworkEndian::read_u16(&buf);

    Ok(SocksV5Response { status, port, host })
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

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use super::*;

    #[test]
    fn write_request_ipv4() {
        let mut buf = Vec::<u8>::new();
        block_on(write_request(
            &mut buf,
            SocksV5Command::Connect,
            SocksV5Host::Ipv4([127, 0, 0, 1]),
            1080,
        ))
        .unwrap();
        assert_eq!(buf, &[5, 1, 0, 1, 127, 0, 0, 1, 4, 56]);
    }

    #[test]
    fn write_request_ipv6() {
        let mut buf = Vec::<u8>::new();
        block_on(write_request(
            &mut buf,
            SocksV5Command::Connect,
            SocksV5Host::Ipv6([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]),
            1080,
        ))
        .unwrap();
        assert_eq!(
            buf,
            &[5, 1, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 4, 56]
        );
    }

    #[test]
    fn write_request_domain() {
        let mut buf = Vec::<u8>::new();
        block_on(write_request(
            &mut buf,
            SocksV5Command::Connect,
            SocksV5Host::Domain("A".into()),
            1080,
        ))
        .unwrap();
        assert_eq!(buf, &[5, 1, 0, 3, 1, 65, 4, 56]);
    }

    #[test]
    fn read_request_status_good() {
        let data = [5, 0, 0, 1, 127, 0, 0, 1, 4, 56];
        let response = block_on(read_request_status(data.as_slice())).unwrap();
        assert_eq!(response.status, SocksV5RequestStatus::Success);
        match response.host {
            SocksV5Host::Ipv4(ip) => assert_eq!(ip, [127, 0, 0, 1]),
            _ => panic!("parsed host was not IPv4 as expected"),
        }
        assert_eq!(response.port, 1080);
    }
}
