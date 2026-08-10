use std::collections::HashSet;

use crate::error::{ResolverError, Result};

pub const MAX_NAME_LENGTH: usize = 255;
pub const MAX_LABEL_LENGTH: usize = 63;

pub const POINTER_MASK: u8 = 0xC0;
pub const MAX_UDP_PAYLOAD: usize = 512;

pub const DNS_PORT: u16 = 53;

#[derive(Debug)]
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        self.check(n)?;
        Ok(&self.buf[self.pos..self.pos + n])
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.check(n)?;
        self.pos += n;
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        self.check(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_data::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_data::<4>()?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_data::<4>()?;
        Ok(i32::from_be_bytes(bytes))
    }

    pub fn read_vec(&mut self, n: usize) -> Result<Vec<u8>> {
        self.check(n)?;
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    pub fn read_name(&mut self) -> Result<String> {
        if self.pos < self.buf.len() && self.buf[self.pos] == 0 {
            self.pos += 1;
            return Ok(".".to_string());
        }

        let mut labels: Vec<String> = Vec::with_capacity(4);
        let mut visited: HashSet<usize> = HashSet::new();
        self.read_labels(&mut labels, &mut visited, self.pos)?;

        let mut name = labels.join(".");
        name.push('.');
        Ok(name)
    }

    fn read_labels(
        &mut self,
        labels: &mut Vec<String>,
        visited: &mut HashSet<usize>,
        start_pos: usize,
    ) -> Result<()> {
        let mut pos = start_pos;
        let mut first_pointer: Option<usize> = None;

        loop {
            if pos >= self.buf.len() {
                return Err(ResolverError::Protocol(
                    "unexpected end of message while reading label".into(),
                ));
            }

            let len_or_ptr = self.buf[pos];

            if len_or_ptr == 0 {
                pos += 1;
                break;
            }

            if len_or_ptr & POINTER_MASK == POINTER_MASK {
                if pos + 1 >= self.buf.len() {
                    return Err(ResolverError::Protocol(
                        "truncated compression pointer".into(),
                    ));
                }

                let offset_hi = (len_or_ptr & !POINTER_MASK) as usize;
                let offset_lo = self.buf[pos + 1] as usize;
                let offset = (offset_hi << 8) | offset_lo;

                if offset >= self.buf.len() {
                    return Err(ResolverError::InvalidPointer {
                        offset,
                        len: self.buf.len(),
                    });
                }

                if !visited.insert(offset) {
                    return Err(ResolverError::PointerLoop);
                }

                if first_pointer.is_none() {
                    first_pointer = Some(pos);
                }

                pos = offset;
                continue;
            }

            let label_len = len_or_ptr as usize;
            if label_len > MAX_LABEL_LENGTH {
                return Err(ResolverError::LabelTooLong {
                    label: String::from_utf8_lossy(&self.buf[pos + 1..pos + 1 + label_len])
                        .to_string(),
                });
            }

            pos += 1;

            if pos + label_len > self.buf.len() {
                return Err(ResolverError::Protocol("truncated label in name".into()));
            }

            let label_bytes = &self.buf[pos..pos + label_len];
            labels.push(String::from_utf8_lossy(label_bytes).to_lowercase());

            pos += label_len;

            if first_pointer.is_none() {
                self.pos = pos;
            }
        }

        if let Some(ptr_pos) = first_pointer {
            self.pos = ptr_pos + 2;
        } else {
            self.pos = pos;
        }

        Ok(())
    }

    fn read_data<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.check(N)?;

        let mut arr = [0_u8; N];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(arr)
    }

    fn check(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            return Err(ResolverError::Protocol(format!(
                "Unexpected end of message: need {n} bytes at position {}, have {}",
                self.pos,
                self.buf.len()
            )));
        }
        Ok(())
    }
}

pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_name(&mut self, name: &str) -> Result<()> {
        let name = name.strip_suffix('.').unwrap_or(name);

        if name.is_empty() {
            self.write_u8(0);
            return Ok(());
        }

        let len = name.len();
        if len > MAX_NAME_LENGTH {
            return Err(ResolverError::NameTooLong(name.to_string()));
        }

        for label in name.split('.') {
            let label_bytes = label.as_bytes();
            if label_bytes.is_empty() {
                return Err(ResolverError::EmptyLabel(name.to_string()));
            }

            if label_bytes.len() > MAX_LABEL_LENGTH {
                return Err(ResolverError::LabelTooLong {
                    label: label.to_string(),
                });
            }

            self.write_u8(label_bytes.len() as u8);
            self.write_bytes(label_bytes);
        }

        self.write_u8(0);
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn set_u16(&mut self, offset: usize, v: u16) {
        let bytes = v.to_be_bytes();
        self.buf[offset] = bytes[0];
        self.buf[offset + 1] = bytes[1];
    }
}
