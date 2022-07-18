#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Serde(serde_json::Error),
    InvalidClaimContents,
    InvalidHex(hex::FromHexError),
    InvalidRootHash,
    ConnectionError(subxt::BasicError),
    InvalidDid,
    DidNotFound,
    InvalidSignature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::Serde(err) => write!(f, "Serde error: {}", err),
            Error::InvalidClaimContents => write!(f, "Invalid claim contents"),
            Error::InvalidHex(err) => write!(f, "Invalid hex: {}", err),
            Error::InvalidRootHash => write!(f, "Invalid root hash"),
            Error::ConnectionError(err) => write!(f, "Connection error: {}", err),
            Error::InvalidDid => write!(f, "Invalid DID"),
            Error::DidNotFound => write!(f, "DID not found"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serde(err)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::InvalidHex(err)
    }
}

impl From<subxt::BasicError> for Error {
    fn from(err: subxt::BasicError) -> Self {
        Error::ConnectionError(err)
    }
}
