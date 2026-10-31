//! `<store>/config`: optional JSON5 (README, Config Flags).
//!
//! Each key is either honoured, or accepted only at the value this
//! implementation already behaves as. Anything else is an error naming the
//! key, never silently ignored: a setting that changes nothing would let the
//! operator believe a policy is in force.

use crate::digest::{Alg, Enc};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `Base64` and `Hex`: which encodings `resolve` accepts as input.
    pub base64: bool,
    pub hex: bool,
    /// `DefaultEnc`; `--hex` still overrides it.
    pub default_enc: Enc,
    /// `CompareCtimeInode`: false drops ctime and inode from the skip rule.
    pub compare_ctime_inode: bool,
    /// `UnregisterDeleted`: false makes a deleted root only reported.
    pub unregister_deleted: bool,
    /// ES-31 keys: sizes in bytes, the two timeouts in milliseconds.
    pub cache_capacity: u64,
    pub service_max_size: u64,
    pub service_timeout_ms: u64,
    pub service_idle_timeout_ms: u64,
    pub allow_http: bool,
    pub allow_local: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            base64: true,
            hex: true,
            default_enc: Enc::B64ut,
            compare_ctime_inode: true,
            unregister_deleted: true,
            cache_capacity: 1 << 30,
            service_max_size: 256 << 20,
            service_timeout_ms: 600_000,
            service_idle_timeout_ms: 30_000,
            allow_http: false,
            allow_local: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("not valid JSON5: {0}")]
    Syntax(String),
    #[error("not UTF-8")]
    NotUtf8,
    #[error("unknown key {0}")]
    UnknownKey(String),
    #[error("key {key} must be {expected}")]
    WrongType { key: String, expected: &'static str },
    #[error("key {key}: {value} is not supported, only {supported}")]
    Unsupported {
        key: String,
        value: String,
        supported: &'static str,
    },
    #[error("{0} input is disabled by the config (key {0} is false)")]
    InputDisabled(&'static str),
    #[error("ServiceMaxSize {max_size} is above CacheCapacity {capacity}: a fetched blob must fit the cache")]
    MaxSizeAboveCapacity { max_size: u64, capacity: u64 },
}

/// A value of any JSON5 type, so a wrong type can be reported against its key.
#[derive(Deserialize)]
#[serde(untagged)]
enum Val {
    Bool(bool),
    Num(u64),
    Str(String),
    Other(serde::de::IgnoredAny),
}

fn boolean(key: &str, v: &Val) -> Result<bool, ConfigError> {
    match v {
        Val::Bool(b) => Ok(*b),
        _ => Err(ConfigError::WrongType {
            key: key.into(),
            expected: "true or false",
        }),
    }
}

fn number(key: &str, v: &Val) -> Result<u64, ConfigError> {
    match v {
        Val::Num(n) => Ok(*n),
        _ => Err(ConfigError::WrongType {
            key: key.into(),
            expected: "a non-negative integer",
        }),
    }
}

fn string<'a>(key: &str, v: &'a Val) -> Result<&'a str, ConfigError> {
    match v {
        Val::Str(s) => Ok(s),
        _ => Err(ConfigError::WrongType {
            key: key.into(),
            expected: "a string",
        }),
    }
}

fn only(
    key: &str,
    got: impl std::fmt::Display,
    is_default: bool,
    supported: &'static str,
) -> Result<(), ConfigError> {
    if is_default {
        return Ok(());
    }
    Err(ConfigError::Unsupported {
        key: key.into(),
        value: got.to_string(),
        supported,
    })
}

pub fn parse(bytes: &[u8]) -> Result<Config, ConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8)?;
    let map: BTreeMap<String, Val> =
        json5::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
    let mut c = Config::default();
    for (key, v) in &map {
        match key.as_str() {
            "Aware" => {
                let b = boolean(key, v)?;
                only(key, b, b, "true")?;
            }
            "Truncation" | "Unlabeled" => {
                let b = boolean(key, v)?;
                only(key, b, !b, "false")?;
            }
            "Base64" => c.base64 = boolean(key, v)?,
            "Hex" => c.hex = boolean(key, v)?,
            "CompareCtimeInode" => c.compare_ctime_inode = boolean(key, v)?,
            "UnregisterDeleted" => c.unregister_deleted = boolean(key, v)?,
            "CacheCapacity" => c.cache_capacity = number(key, v)?,
            "ServiceMaxSize" => c.service_max_size = number(key, v)?,
            "ServiceTimeout" => c.service_timeout_ms = number(key, v)?,
            "ServiceIdleTimeout" => c.service_idle_timeout_ms = number(key, v)?,
            "AllowHTTP" => c.allow_http = boolean(key, v)?,
            "AllowLocal" => c.allow_local = boolean(key, v)?,
            "DefaultEnc" => {
                c.default_enc = match string(key, v)? {
                    "B64" => Enc::B64ut,
                    "Hex" => Enc::Hex,
                    other => {
                        return Err(ConfigError::Unsupported {
                            key: key.clone(),
                            value: other.into(),
                            supported: "B64 or Hex",
                        })
                    }
                }
            }
            "IndexEnc" => {
                let s = string(key, v)?;
                only(key, s, s == "B64", "B64")?;
            }
            "Hash" => {
                let s = string(key, v)?;
                only(key, s, s == Alg::Sha256.name(), "SHA-256")?;
            }
            "Directory" => {
                let s = string(key, v)?;
                only(key, s, s == "CWD", "CWD")?;
            }
            _ => return Err(ConfigError::UnknownKey(key.clone())),
        }
    }
    // ES-31: rejected, not clamped, so the operator sees which one to change.
    if c.service_max_size > c.cache_capacity {
        return Err(ConfigError::MaxSizeAboveCapacity {
            max_size: c.service_max_size,
            capacity: c.cache_capacity,
        });
    }
    Ok(c)
}

impl Config {
    /// Refuses a query written in an encoding the config disables; `enc` is
    /// what `Query::parse` found, so every query form is covered.
    pub fn check_input(&self, enc: Enc) -> Result<(), ConfigError> {
        match enc {
            Enc::Hex if !self.hex => Err(ConfigError::InputDisabled("Hex")),
            Enc::B64ut if !self.base64 => Err(ConfigError::InputDisabled("Base64")),
            _ => Ok(()),
        }
    }
}
