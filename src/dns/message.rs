use crate::{
    dns::{
        answer::ResourceRecord,
        header::Header,
        question::Question,
        wire::{WireReader, WireWriter},
    },
    error::Result,
};

#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn new(id: u16, question: Question) -> Self {
        Self {
            header: Header::new_query(id),
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = WireReader::new(bytes);

        let header = Header::from_header(&mut reader)?;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            questions.push(Question::from_reader(&mut reader)?);
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(ResourceRecord::from_reader(&mut reader)?);
        }

        let mut authorities = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.nscount {
            authorities.push(ResourceRecord::from_reader(&mut reader)?);
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            additionals.push(ResourceRecord::from_reader(&mut reader)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = WireWriter::with_capacity(512);

        writer.write_bytes(&self.header.to_bytes());

        for q in &self.questions {
            let _ = q.to_wire(&mut writer);
        }

        writer.set_u16(4, self.questions.len() as u16);
        writer.set_u16(6, self.answers.len() as u16);
        writer.set_u16(8, self.authorities.len() as u16);
        writer.set_u16(10, self.additionals.len() as u16);

        writer.into_bytes()
    }
}
