use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::io::*;
use crate::v5::SocksV5AddressType;

#[derive(Clone, Debug)]
pub enum SocksV5Host {
    Domain(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl SocksV5Host {
    pub fn is_ip_addr(&self) -> bool {
        !matches!(self, SocksV5Host::Domain(_))
    }

    pub fn is_ip_v4(&self) -> bool {
        matches!(self, SocksV5Host::Ipv4(_))
    }

    pub fn is_ip_v6(&self) -> bool {
        matches!(self, SocksV5Host::Ipv6(_))
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, SocksV5Host::Domain(_))
    }

    pub(crate) fn repr_len(&self) -> usize {
        match self {
            SocksV5Host::Domain(domain) => 1 + domain.len(),
            SocksV5Host::Ipv4(_) => 4,
            SocksV5Host::Ipv6(_) => 16,
        }
    }

    pub(crate) async fn read<Reader>(
        mut reader: Reader,
        addr_type: SocksV5AddressType,
    ) -> std::io::Result<SocksV5Host>
    where
        Reader: AsyncRead + Unpin,
    {
        match addr_type {
            SocksV5AddressType::Ipv4 => {
                let mut host = [0u8; 4];
                reader.read_exact(&mut host).await?;
                Ok(host.into())
            }
            SocksV5AddressType::Ipv6 => {
                let mut host = [0u8; 16];
                reader.read_exact(&mut host).await?;
                Ok(host.into())
            }
            SocksV5AddressType::Domain => {
                let mut buf = [0u8];
                reader.read_exact(&mut buf).await?;
                let mut domain = vec![0u8; buf[0] as usize];
                reader.read_exact(&mut domain).await?;
                Ok(domain.into())
            }
        }
    }
}

impl From<[u8; 4]> for SocksV5Host {
    fn from(octets: [u8; 4]) -> Self {
        SocksV5Host::Ipv4(octets)
    }
}

impl From<[u8; 16]> for SocksV5Host {
    fn from(octets: [u8; 16]) -> Self {
        SocksV5Host::Ipv6(octets)
    }
}

impl From<Vec<u8>> for SocksV5Host {
    fn from(domain_bytes: Vec<u8>) -> Self {
        SocksV5Host::Domain(domain_bytes)
    }
}

impl From<Ipv4Addr> for SocksV5Host {
    fn from(addr: Ipv4Addr) -> Self {
        SocksV5Host::Ipv4(addr.octets())
    }
}

impl From<Ipv6Addr> for SocksV5Host {
    fn from(addr: Ipv6Addr) -> Self {
        SocksV5Host::Ipv6(addr.octets())
    }
}

impl From<IpAddr> for SocksV5Host {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => addr.into(),
            IpAddr::V6(addr) => addr.into(),
        }
    }
}

impl<'a> From<&'a str> for SocksV5Host {
    fn from(addr: &'a str) -> Self {
        SocksV5Host::Domain(addr.into())
    }
}

impl From<String> for SocksV5Host {
    fn from(addr: String) -> Self {
        SocksV5Host::Domain(addr.into())
    }
}

impl TryFrom<SocksV5Host> for Ipv4Addr {
    type Error = SocksV5Host;

    fn try_from(host: SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Ipv4(octets) => Ok(octets.into()),
            other => Err(other),
        }
    }
}

impl<'a> TryFrom<&'a SocksV5Host> for Ipv4Addr {
    type Error = ();

    fn try_from(host: &'a SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Ipv4(octets) => Ok((*octets).into()),
            _ => Err(()),
        }
    }
}

impl TryFrom<SocksV5Host> for Ipv6Addr {
    type Error = SocksV5Host;

    fn try_from(host: SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Ipv6(octets) => Ok(octets.into()),
            other => Err(other),
        }
    }
}

impl<'a> TryFrom<&'a SocksV5Host> for Ipv6Addr {
    type Error = ();

    fn try_from(host: &'a SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Ipv6(octets) => Ok((*octets).into()),
            _ => Err(()),
        }
    }
}

impl TryFrom<SocksV5Host> for IpAddr {
    type Error = SocksV5Host;

    fn try_from(host: SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Ipv4(octets) => Ok(octets.into()),
            SocksV5Host::Ipv6(octets) => Ok(octets.into()),
            other => Err(other),
        }
    }
}

impl<'a> TryFrom<&'a SocksV5Host> for IpAddr {
    type Error = ();

    fn try_from(host: &'a SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Ipv4(octets) => Ok((*octets).into()),
            SocksV5Host::Ipv6(octets) => Ok((*octets).into()),
            _ => Err(()),
        }
    }
}

impl TryFrom<SocksV5Host> for Vec<u8> {
    type Error = SocksV5Host;

    fn try_from(host: SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Domain(bytes) => Ok(bytes),
            other => Err(other),
        }
    }
}

impl<'a> TryFrom<&'a SocksV5Host> for &'a [u8] {
    type Error = ();

    fn try_from(host: &'a SocksV5Host) -> Result<Self, Self::Error> {
        match host {
            SocksV5Host::Domain(bytes) => Ok(bytes),
            _ => Err(()),
        }
    }
}
