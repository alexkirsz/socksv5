#[derive(Debug, Eq, PartialEq)]
pub enum SocksV5AuthMethod {
    Noauth,
    Gssapi,
    UsernamePassword,
    NoAcceptableMethod,
    Other(u8),
}

impl SocksV5AuthMethod {
    pub(crate) fn from_u8(n: u8) -> SocksV5AuthMethod {
        match n {
            0x00 => SocksV5AuthMethod::Noauth,
            0x01 => SocksV5AuthMethod::Gssapi,
            0x02 => SocksV5AuthMethod::UsernamePassword,
            0xff => SocksV5AuthMethod::NoAcceptableMethod,
            other => SocksV5AuthMethod::Other(other),
        }
    }

    pub(crate) fn to_u8(&self) -> u8 {
        match self {
            SocksV5AuthMethod::Noauth => 0x00,
            SocksV5AuthMethod::Gssapi => 0x01,
            SocksV5AuthMethod::UsernamePassword => 0x02,
            SocksV5AuthMethod::NoAcceptableMethod => 0xff,
            SocksV5AuthMethod::Other(other) => *other,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SocksV5Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl SocksV5Command {
    pub fn from_u8(n: u8) -> Option<SocksV5Command> {
        match n {
            0x01 => Some(SocksV5Command::Connect),
            0x02 => Some(SocksV5Command::Bind),
            0x03 => Some(SocksV5Command::UdpAssociate),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SocksV5Command::Connect => 0x01,
            SocksV5Command::Bind => 0x02,
            SocksV5Command::UdpAssociate => 0x03,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SocksV5AddressType {
    Ipv4,
    Domain,
    Ipv6,
}

impl SocksV5AddressType {
    pub fn from_u8(n: u8) -> Option<SocksV5AddressType> {
        match n {
            0x01 => Some(SocksV5AddressType::Ipv4),
            0x03 => Some(SocksV5AddressType::Domain),
            0x04 => Some(SocksV5AddressType::Ipv6),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SocksV5AddressType::Ipv4 => 0x01,
            SocksV5AddressType::Domain => 0x03,
            SocksV5AddressType::Ipv6 => 0x04,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SocksV5RequestStatus {
    Success,
    ServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddrtypeNotSupported,
}

impl SocksV5RequestStatus {
    pub fn from_u8(n: u8) -> Option<SocksV5RequestStatus> {
        match n {
            0x00 => Some(SocksV5RequestStatus::Success),
            0x01 => Some(SocksV5RequestStatus::ServerFailure),
            0x02 => Some(SocksV5RequestStatus::ConnectionNotAllowed),
            0x03 => Some(SocksV5RequestStatus::NetworkUnreachable),
            0x04 => Some(SocksV5RequestStatus::HostUnreachable),
            0x05 => Some(SocksV5RequestStatus::ConnectionRefused),
            0x06 => Some(SocksV5RequestStatus::TtlExpired),
            0x07 => Some(SocksV5RequestStatus::CommandNotSupported),
            0x08 => Some(SocksV5RequestStatus::AddrtypeNotSupported),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SocksV5RequestStatus::Success => 0x00,
            SocksV5RequestStatus::ServerFailure => 0x01,
            SocksV5RequestStatus::ConnectionNotAllowed => 0x02,
            SocksV5RequestStatus::NetworkUnreachable => 0x03,
            SocksV5RequestStatus::HostUnreachable => 0x04,
            SocksV5RequestStatus::ConnectionRefused => 0x05,
            SocksV5RequestStatus::TtlExpired => 0x06,
            SocksV5RequestStatus::CommandNotSupported => 0x07,
            SocksV5RequestStatus::AddrtypeNotSupported => 0x08,
        }
    }

    #[cfg(unix)]
    pub fn from_io_error(e: std::io::Error) -> SocksV5RequestStatus {
        match e.raw_os_error() {
            // ENETUNREACH
            Some(101) => SocksV5RequestStatus::NetworkUnreachable,
            // ETIMEDOUT
            Some(110) => SocksV5RequestStatus::TtlExpired,
            // ECONNREFUSED
            Some(111) => SocksV5RequestStatus::ConnectionRefused,
            // EHOSTUNREACH
            Some(113) => SocksV5RequestStatus::HostUnreachable,
            // Unhandled error code
            _ => SocksV5RequestStatus::ServerFailure,
        }
    }

    #[cfg(not(unix))]
    pub fn from_io_error(e: std::io::Error) -> SocksV5RequestStatus {
        SocksV5RequestStatus::ServerFailure
    }
}
