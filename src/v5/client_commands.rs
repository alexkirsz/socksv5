use byteorder::{ByteOrder, NetworkEndian};
use thiserror::Error;

use crate::io::*;
use crate::v5::{
    SocksV5AddressType, SocksV5Command, SocksV5Host, SocksV5RequestError, SocksV5RequestStatus,
};
use crate::SocksVersion;

/// Writes a SOCKSv5 request with the specified command, host and port.
///
/// # Errors
///
/// If writing to `writer` fails, this function will return the I/O error.
///
/// # Panics
///
/// If `host` is a domain name, and its length is greater than 255 bytes.
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
    let mut data = Vec::<u8>::with_capacity(6 + host.repr_len());
    data.push(SocksVersion::V5.to_u8());
    data.push(command.to_u8());
    data.push(0u8); // reserved bits in SOCKSv5
    match &host {
        SocksV5Host::Domain(domain) => {
            assert!(
                domain.len() < 256,
                "domain name must be shorter than 256 bytes"
            );
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

#[derive(Debug, Error)]
pub enum SocksV5ConnectError {
    #[error("invalid SOCKS version {0:02X}, expected {:02X}", SocksVersion::V5.to_u8())]
    InvalidVersion(u8),
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("server returned an error: {0:?}")]
    ServerError(SocksV5RequestStatus),
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

impl From<SocksV5RequestError> for SocksV5ConnectError {
    fn from(he: SocksV5RequestError) -> Self {
        use SocksV5ConnectError::*;
        match he {
            SocksV5RequestError::InvalidVersion(v) => InvalidVersion(v),
            SocksV5RequestError::InvalidRequest(msg) => InvalidResponse(msg),
            SocksV5RequestError::Io(e) => Io(e),
        }
    }
}

/// As a client, send a CONNECT request to a stream and process the response.
///
/// # Returns
///
/// If the server accepts the command, this function returns the stream (that can now be used
/// to communicate with the target through the proxy), as well as the host and port that the proxy
/// server used to connect to the target socket.
///
/// # Errors
///
/// - `Io` if either sending the request or receiving the response fails due to I/O error, including a premature EOF.
/// - `InvalidVersion` if the server returns an unexpected version number.
/// - `InvalidResponse` if the server's reply cannot be interpreted (because, for example, it uses
/// an unsupported status code or address type).
/// - `ServerError` if the server returns a non-success status.
pub async fn request_connect<Stream, Host>(
    mut stream: Stream,
    target_host: Host,
    target_port: u16,
) -> Result<(Stream, SocksV5Host, u16), SocksV5ConnectError>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
    Host: Into<SocksV5Host>,
{
    write_request(
        &mut stream,
        SocksV5Command::Connect,
        target_host.into(),
        target_port,
    )
    .await?;

    let response = read_request_status(&mut stream).await?;
    if response.status != SocksV5RequestStatus::Success {
        return Err(SocksV5ConnectError::ServerError(response.status));
    }

    Ok((stream, response.host, response.port))
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
}
