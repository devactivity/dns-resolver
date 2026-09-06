use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use crate::{
    dns::{
        answer::ResourceRecord,
        header::Rcode,
        message::Message,
        question::{Question, RecordTypeOrUnknown},
        wire::MAX_UDP_PAYLOAD,
    },
    error::{ResolverError, Result},
};

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub server: SocketAddr,
    pub timeout_secs: u64,
    pub max_retries: u8,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            server: SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
            timeout_secs: 6,
            max_retries: 3,
        }
    }
}

#[derive(Debug)]
pub struct Resolver {
    config: ResolverConfig,
    socket: UdpSocket,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;

        socket
            .set_read_timeout(Some(Duration::from_secs(config.timeout_secs)))
            .map_err(ResolverError::Io)?;

        Ok(Self { config, socket })
    }

    pub fn resolve(&self, question: &Question) -> Result<Message> {
        let id: u16 = rand::random();
        let query = Message::new(id, question.clone());
        let query_bytes = query.to_bytes();

        let mut last_error = String::new();

        for attempt in 1..=self.config.max_retries {
            match self.send_and_receive(&query_bytes, id) {
                Ok(response) => {
                    let msg = match Message::from_bytes(&response) {
                        Ok(msg) => msg,
                        Err(e) => {
                            let tc_bit = response.len() >= 3 && (response[2] & 0x02) != 0;
                            let full_payload = response.len() == MAX_UDP_PAYLOAD;

                            if tc_bit || full_payload {
                                return Err(ResolverError::TruncatedResponse);
                            }

                            return Err(e);
                        }
                    };

                    if msg.header.is_truncated() {
                        return Err(ResolverError::TruncatedResponse);
                    }

                    match msg.header.rcode {
                        Rcode::NoError => {}
                        Rcode::NxDomain => {
                            eprintln!("domain does not exist");
                        }
                        others => {
                            return Err(ResolverError::ServerError(format!(
                                "{} (rcode={others:?})",
                                others.description()
                            )));
                        }
                    }

                    return Ok(msg);
                }

                Err(e) => {
                    last_error = e.to_string();

                    if attempt < self.config.max_retries {
                        std::thread::sleep(Duration::from_millis(250 * u64::from(attempt)));
                    }
                }
            }
        }

        Err(ResolverError::QueryFailed {
            attempts: self.config.max_retries,
            last_error,
        })
    }

    pub fn lookup(&self, name: &str, qtype: RecordTypeOrUnknown) -> Result<Vec<ResourceRecord>> {
        let question = Question::new(name, qtype);
        let msg = self.resolve(&question)?;
        Ok(msg.answers)
    }

    fn send_and_receive(&self, query_bytes: &[u8], id: u16) -> Result<Vec<u8>> {
        let sent_at = Instant::now();

        // send
        let bytes_sent = self.socket.send_to(query_bytes, self.config.server)?;

        // receive
        let mut buf = vec![0_u8; MAX_UDP_PAYLOAD];
        let (bytes_recv, peer) = match self.socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(ResolverError::Timeout {
                    server: self.config.server.to_string(),
                    timeout: self.config.timeout_secs,
                });
            }
            Err(e) => return Err(ResolverError::Io(e)),
        };

        let elapsed = sent_at.elapsed();

        buf.truncate(bytes_recv);

        if bytes_recv >= 2 {
            let response_id = u16::from_be_bytes([buf[0], buf[1]]);
            if response_id != id {
                eprintln!("response id mismatch");
            }
        }

        Ok(buf)
    }
}
