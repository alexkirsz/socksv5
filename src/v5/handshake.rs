use thiserror::Error;

use crate::io::*;
use crate::v5::SocksV5AuthMethod;
use crate::SocksVersion;

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
        .map(SocksV5AuthMethod::from_u8)
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
pub enum SocksV5AuthError {
    #[error("invalid SOCKS version {0:02X}, expected {:02X}", SocksVersion::V5.to_u8())]
    InvalidVersion(u8),
    #[error("handshake protocol violation: {0}")]
    InvalidHandshake(String),
    #[error("could not agree on auth methods")]
    NoAcceptableMethods,
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

impl From<SocksV5HandshakeError> for SocksV5AuthError {
    fn from(he: SocksV5HandshakeError) -> Self {
        use SocksV5AuthError::*;
        match he {
            SocksV5HandshakeError::InvalidVersion(v) => InvalidVersion(v),
            SocksV5HandshakeError::InvalidHandshake(msg) => InvalidHandshake(msg),
            SocksV5HandshakeError::Io(e) => Io(e),
        }
    }
}

/// Send a handshake request (offering no-op authentication) and process the response.
///
/// # Returns
///
/// On successful (no-op) authentication, this function returns the same stream that it received as an argument.
///
/// # Errors
///
/// - `Io` if either sending the request or receiving the response fails due to I/O error, including a premature EOF.
/// - `InvalidVersion` if the server returns an unexpected version number.
/// - `NoAcceptableMethods` if the server does not agree to skip authentication.
/// - `InvalidHandshake` is never returned by this function.

// The choice to receive the stream by value and return it anticipates probable future implementations
// of other authentication methods that may want to encrypt the data passed within the stream.
// For such cases, the negotiation function would return a "wrapper" stream.
pub async fn negotiate_noauth_with_server<Stream>(
    mut stream: Stream,
) -> Result<Stream, SocksV5AuthError>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    use SocksV5AuthError::*;

    write_handshake(&mut stream, [SocksV5AuthMethod::Noauth])
        .await
        .map_err(Io)?;

    let server_auth_method = read_auth_method(&mut stream).await?;
    if server_auth_method != SocksV5AuthMethod::Noauth {
        return Err(NoAcceptableMethods);
    }
    Ok(stream)
}

/// Receive a handshake request and reply to it, supporting only NOAUTH.
///
/// # Returns
///
/// On successful (no-op) authentication, this function returns the same stream that it received as an argument.
/// A successful response will have been sent to the client.
///
/// # Errors
///
/// - `Io` if either reading the request or writing the response fails due to I/O error, including a premature EOF.
/// - `InvalidVersion` if the client sends an unexpected version number.
/// - `InvalidHandshake` if the client violates the SOCKSv5 protocol (e.g. does not offer any auth methods).
/// - `NoAcceptableMethods` if the client does not offer to use NOAUTH.
///
/// In case of `NoAcceptableMethods`, the corresponding response is sent to the client.
/// In other error cases no reply is sent.
pub async fn negotiate_noauth_with_client<Stream>(
    mut stream: Stream,
) -> Result<Stream, SocksV5AuthError>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    use SocksV5AuthError::*;

    let auth_methods = read_handshake(&mut stream).await?.methods;
    if !auth_methods.contains(&SocksV5AuthMethod::Noauth) {
        write_auth_method(&mut stream, SocksV5AuthMethod::NoAcceptableMethod).await?;
        return Err(NoAcceptableMethods);
    }
    write_auth_method(&mut stream, SocksV5AuthMethod::Noauth).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use super::*;

    #[test]
    fn write_handshake_good() {
        let mut buf = Vec::<u8>::new();
        block_on(write_handshake(&mut buf, [SocksV5AuthMethod::Noauth])).unwrap();
        assert_eq!(buf, &[0x05, 0x01, 0x00]);
    }

    #[test]
    fn read_auth_method_good() {
        assert_eq!(
            block_on(read_auth_method([0x05u8, 0x00].as_slice())).unwrap(),
            SocksV5AuthMethod::Noauth
        );
    }
}
