//! Labelled digests: algorithms, encodings, parsing and formatting.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Alg {
    Sha256,
}

impl Alg {
    pub const ALL: &'static [Alg] = &[Alg::Sha256];

    pub fn name(self) -> &'static str {
        todo!()
    }

    pub fn from_name(_s: &str) -> Option<Alg> {
        todo!()
    }

    // Digest size in bytes; an algorithm has no "empty" state.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        todo!()
    }

    pub fn b64ut_len(self) -> usize {
        todo!()
    }

    pub fn hex_len(self) -> usize {
        todo!()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enc {
    B64ut,
    Hex,
}

/// Invariant: `bytes.len() == alg.len()`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    alg: Alg,
    bytes: Box<[u8]>,
}

impl Digest {
    pub fn from_bytes(_alg: Alg, _bytes: &[u8]) -> Result<Digest, DigestError> {
        todo!()
    }

    pub fn compute(_alg: Alg, _data: &[u8]) -> Digest {
        todo!()
    }

    pub fn alg(&self) -> Alg {
        todo!()
    }

    pub fn bytes(&self) -> &[u8] {
        todo!()
    }

    pub fn encode(&self, _enc: Enc) -> String {
        todo!()
    }

    pub fn to_reverse(&self, _enc: Enc) -> String {
        todo!()
    }

    pub fn decode_value(_alg: Alg, _s: &str) -> Result<Digest, DigestError> {
        todo!()
    }

    pub fn parse_labelled(_s: &str) -> Result<Digest, DigestError> {
        todo!()
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest has no ':' label")]
    Unlabelled,
    #[error("digest has more than one ':'")]
    TooManyColons,
    #[error("unknown algorithm {0:?}")]
    UnknownAlg(String),
    #[error("{alg:?} value has wrong length {got}")]
    WrongLength { alg: Alg, got: usize },
    #[error("invalid character {ch:?} at index {index}")]
    InvalidChar { index: usize, ch: char },
    #[error("non-canonical base64 trailing bits")]
    NonCanonical,
    #[error("{alg:?} digest has wrong byte length {got}")]
    WrongByteLength { alg: Alg, got: usize },
}
