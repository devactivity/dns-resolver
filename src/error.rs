use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    Protocol(String),

    #[error("DNS server error: {0}")]
    ServerError(String),

    #[error("DNS name exceeds octets: {0}")]
    NameTooLong(String),

    #[error("DNS label is emtpy at position '{0}'")]
    EmptyLabel(String),

    #[error("DNS label exceeds octets: '{label}'")]
    LabelTooLong { label: String },

    #[error("Label compression out of bounds (offset {offset}, message length {len})")]
    InvalidPointer { offset: usize, len: usize },

    #[error("Label compression pointer loop detected")]
    PointerLoop,

    #[error("Timeout waiting for response from {server} after {timeout}s")]
    Timeout { server: String, timeout: u64 },

    #[error("Response tuncated, retry over TCP is not yet supported")]
    TruncatedResponse,

    #[error("Query failed after {attempts} attempt(s): {last_error}")]
    QueryFailed { attempts: u8, last_error: String },

    #[error("Unsupported query type: {0}")]
    UnsupportedType(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ResolverError>;
