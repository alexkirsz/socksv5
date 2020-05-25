#[derive(Debug, Eq, PartialEq)]
pub enum SocksV4Command {
    Connect,
    Bind,
}

impl SocksV4Command {
    pub fn from_u8(n: u8) -> Option<SocksV4Command> {
        match n {
            0x01 => Some(SocksV4Command::Connect),
            0x02 => Some(SocksV4Command::Bind),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SocksV4Command::Connect => 0x01,
            SocksV4Command::Bind => 0x02,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SocksV4RequestStatus {
    Granted,
    // Also known as Refused
    Failed,
    IdentdFailed,
    WrongUserid,
}

impl SocksV4RequestStatus {
    pub fn from_u8(n: u8) -> Option<SocksV4RequestStatus> {
        match n {
            0x5a => Some(SocksV4RequestStatus::Granted),
            0x5b => Some(SocksV4RequestStatus::Failed),
            0x5c => Some(SocksV4RequestStatus::IdentdFailed),
            0x5d => Some(SocksV4RequestStatus::WrongUserid),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            SocksV4RequestStatus::Granted => 0x5a,
            SocksV4RequestStatus::Failed => 0x5b,
            SocksV4RequestStatus::IdentdFailed => 0x5c,
            SocksV4RequestStatus::WrongUserid => 0x5d,
        }
    }
}
