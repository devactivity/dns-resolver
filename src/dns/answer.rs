use std::{
    fmt::{self, write},
    net::{Ipv4Addr, Ipv6Addr},
    usize,
};

use crate::dns::{
    question::{RecordClass, RecordType, RecordTypeOrUnknown},
    wire::WireReader,
};
use crate::error::Result;

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Ns(String),
    Cname(String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Aaaa(Ipv6Addr),

    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },

    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: RecordTypeOrUnknown,
    pub class: RecordClass,
    pub ttl: i32,
    pub rdata: RData,
}

impl ResourceRecord {
    pub fn from_reader(reader: &mut WireReader<'_>) -> Result<Self> {
        let name = reader.read_name()?;
        let raw_type = reader.read_u16()?;
        let raw_class = reader.read_u16()?;
        let ttl = reader.read_i32()?;
        let rd_length = reader.read_u16()? as usize;

        let rtype = RecordType::from_u16(raw_type);
        let class = RecordClass::from_u16(raw_class);

        let rdata_start = reader.position();

        let rdata = match rtype {
            RecordTypeOrUnknown::Known(RecordType::A) => {
                let addr = Ipv4Addr::from_bits(reader.read_u32()?);
                RData::A(addr)
            }
            RecordTypeOrUnknown::Known(RecordType::NS) => {
                let nsdname = reader.read_name()?;
                RData::Ns(nsdname)
            }
            RecordTypeOrUnknown::Known(RecordType::CNAME) => {
                let cname = reader.read_name()?;
                RData::Cname(cname)
            }
            RecordTypeOrUnknown::Known(RecordType::SOA) => {
                let mname = reader.read_name()?;
                let rname = reader.read_name()?;
                let serial = reader.read_u32()?;
                let refresh = reader.read_i32()?;
                let retry = reader.read_i32()?;
                let expire = reader.read_i32()?;
                let minimum = reader.read_u32()?;
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            RecordTypeOrUnknown::Known(RecordType::MX) => {
                let preference = reader.read_u16()?;
                let exchange = reader.read_name()?;

                RData::Mx {
                    preference,
                    exchange,
                }
            }
            RecordTypeOrUnknown::Known(RecordType::TXT) => {
                let end = rdata_start + rd_length;
                let mut strings = Vec::new();

                while reader.position() < end {
                    let len = reader.read_u8()? as usize;
                    let bytes = reader.read_vec(len)?;

                    strings.push(String::from_utf8_lossy(&bytes).to_string());
                }

                RData::Txt(strings)
            }
            RecordTypeOrUnknown::Known(RecordType::AAAA) => {
                let hi = u64::from(reader.read_u32()?) << 32 | u64::from(reader.read_u32()?);
                let lo = u64::from(reader.read_u32()?) << 32 | u64::from(reader.read_u32()?);

                let addr = Ipv6Addr::from((u128::from(hi) << 64) | u128::from(lo));

                RData::Aaaa(addr)
            }

            RecordTypeOrUnknown::Known(RecordType::SRV) => {
                let priority = reader.read_u16()?;
                let weight = reader.read_u16()?;
                let port = reader.read_u16()?;
                let target = reader.read_name()?;

                RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            _ => {
                let bytes = reader.read_vec(rd_length)?;
                RData::Unknown(bytes)
            }
        };

        let consumed = reader.position() - rdata_start;
        if consumed < rd_length {
            reader.skip(rd_length - consumed)?;
        }

        Ok(Self {
            name: name.strip_suffix('.').unwrap_or(&name).to_lowercase(),
            rtype,
            class,
            ttl,
            rdata,
        })
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}\t{}", self.name, self.ttl, self.rtype)?;

        match &self.rdata {
            RData::A(addr) => write!(f, "\t{addr}"),
            RData::Ns(ns) => write!(f, "\t{ns}"),
            RData::Cname(cname) => write!(f, "\t{cname}"),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                write!(
                    f,
                    "\t{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
                )
            }
            RData::Mx {
                preference,
                exchange,
            } => write!(f, "\t{preference} {exchange}"),
            RData::Txt(strings) => {
                for s in strings {
                    write!(f, "\t\"{s}\"")?;
                }
                Ok(())
            }
            RData::Aaaa(addr) => write!(f, "\t{addr}"),
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "\t{priority} {weight} {port} {target}"),
            RData::Unknown(bytes) => {
                write!(f, "\t<{} bytes>", bytes.len())
            }
        }
    }
}
