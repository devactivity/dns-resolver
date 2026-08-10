use crate::dns::wire::WireReader;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    // dns stateful operations
    Dso = 6,
}

impl Opcode {
    fn from_byte(byte: u8) -> Self {
        match (byte >> 3) & 0x0F {
            // 0x0F 0000_1111
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            6 => Self::Dso,
            _ => Self::Query,
        }
    }

    fn to_bits(self) -> u8 {
        (self as u8) << 3
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
}

impl Rcode {
    fn from_byte(byte: u8) -> Self {
        match &0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            _ => Self::NoError,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::NoError => "No error",
            Self::FormErr => "Format error",
            Self::ServFail => "Server failure",
            Self::NxDomain => "Non-existent domain",
            Self::NotImp => "Not implemented",
            Self::Refused => "Query refused",
            Self::YXDomain => "Name exists when it should not",
            Self::YXRRSet => "RR set exists when it should not",
            Self::NXRRSet => "RR set that should exist does not",
            Self::NotAuth => "Server not authoritative for zone",
            Self::NotZone => "Name not contained in zone",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: Rcode,

    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn from_header(reader: &mut WireReader<'_>) -> Result<Self> {
        let id = reader.read_u16()?;

        let flags_hi = reader.read_u8()?;
        let flags_lo = reader.read_u8()?;

        let qr = (flags_hi & 0x80) != 0;
        let opcode = Opcode::from_byte(flags_hi);
        let aa = (flags_hi & 0x04) != 0;
        let tc = (flags_hi & 0x02) != 0;
        let rd = (flags_hi & 0x01) != 0;

        let ra = (flags_lo & 0x80) != 0;
        let _ = (flags_lo & 0x40) != 0;
        let ad = (flags_lo & 0x20) != 0;
        let cd = (flags_lo & 0x10) != 0;
        let rcode = Rcode::from_byte(flags_lo);

        let qdcount = reader.read_u16()?;
        let ancount = reader.read_u16()?;
        let nscount = reader.read_u16()?;
        let arcount = reader.read_u16()?;

        Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            ad,
            cd,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);

        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags_hi = self.opcode.to_bits();
        if self.qr {
            flags_hi |= 0x80;
        }
        if self.aa {
            flags_hi |= 0x04;
        }

        if self.tc {
            flags_hi |= 0x02;
        }

        if self.rd {
            flags_hi |= 0x01;
        }

        buf.push(flags_hi);

        let mut flags_lo = self.rcode as u8;

        if self.ra {
            flags_lo |= 0x80;
        }

        if self.ad {
            flags_lo |= 0x20;
        }

        if self.cd {
            flags_lo |= 0x10;
        }
        buf.push(flags_lo);

        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());

        buf
    }

    pub fn is_response(&self) -> bool {
        self.qr
    }

    pub fn is_truncated(&self) -> bool {
        self.tc
    }
}
