use std::fmt;

use crate::dns::wire::{WireReader, WireWriter};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    ANY = 255,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordTypeOrUnknown {
    Known(RecordType),
    Unknown(u16),
}

impl RecordTypeOrUnknown {
    pub fn to_u16(self) -> u16 {
        match self {
            Self::Known(k) => k.to_u16(),
            Self::Unknown(n) => n,
        }
    }
}

impl fmt::Display for RecordTypeOrUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(k) => write!(f, "{}", k.name()),
            Self::Unknown(n) => write!(f, "TYPE{n}"),
        }
    }
}

impl RecordType {
    pub fn from_u16(v: u16) -> RecordTypeOrUnknown {
        match v {
            1 => RecordTypeOrUnknown::Known(Self::A),
            2 => RecordTypeOrUnknown::Known(Self::NS),
            5 => RecordTypeOrUnknown::Known(Self::CNAME),
            6 => RecordTypeOrUnknown::Known(Self::SOA),
            15 => RecordTypeOrUnknown::Known(Self::MX),
            16 => RecordTypeOrUnknown::Known(Self::TXT),
            28 => RecordTypeOrUnknown::Known(Self::AAAA),
            33 => RecordTypeOrUnknown::Known(Self::SRV),
            255 => RecordTypeOrUnknown::Known(Self::ANY),
            n => RecordTypeOrUnknown::Unknown(n),
        }
    }

    pub fn from_str(s: &str) -> Option<RecordTypeOrUnknown> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordTypeOrUnknown::Known(Self::A)),
            "NS" => Some(RecordTypeOrUnknown::Known(Self::NS)),
            "CNAME" => Some(RecordTypeOrUnknown::Known(Self::CNAME)),
            "SOA" => Some(RecordTypeOrUnknown::Known(Self::SOA)),
            "MX" => Some(RecordTypeOrUnknown::Known(Self::MX)),
            "TXT" => Some(RecordTypeOrUnknown::Known(Self::TXT)),
            "AAAA" => Some(RecordTypeOrUnknown::Known(Self::AAAA)),
            "SRV" => Some(RecordTypeOrUnknown::Known(Self::SRV)),
            "ANY" => Some(RecordTypeOrUnknown::Known(Self::ANY)),
            other => other.parse::<u16>().ok().map(RecordTypeOrUnknown::Unknown),
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::NS => "NS",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::AAAA => "AAAA",
            Self::SRV => "SRV",
            Self::ANY => "ANY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN = 1,
    CH = 3,
    HS = 4,
    ANY = 255,
}

impl RecordClass {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::IN,
            3 => Self::CH,
            4 => Self::HS,
            255 => Self::ANY,
            _ => Self::IN,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    pub qname: String,
    pub qtype: RecordTypeOrUnknown,
    pub qclass: RecordClass,
}

impl Question {
    pub fn new(name: &str, qtype: RecordTypeOrUnknown) -> Self {
        let qname = name.strip_suffix('.').unwrap_or(name).to_lowercase();

        Self {
            qname,
            qtype,
            qclass: RecordClass::IN,
        }
    }

    pub fn from_reader(reader: &mut WireReader<'_>) -> Result<Self> {
        let qname = reader.read_name()?;
        let raw_type = reader.read_u16()?;
        let raw_class = reader.read_u16()?;

        Ok(Self {
            qname: qname.strip_suffix('.').unwrap_or(&qname).to_lowercase(),
            qtype: RecordType::from_u16(raw_type),
            qclass: RecordClass::from_u16(raw_class),
        })
    }

    pub fn to_wire(&self, writer: &mut WireWriter) -> Result<()> {
        writer.write_name(&self.qname)?;
        writer.write_u16(self.qtype.to_u16());
        writer.write_u16(self.qclass.to_u16());

        Ok(())
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} IN", self.qname, self.qtype)
    }
}
