//! The `https` backend (ES-5, ES-9, ES-12 to ES-19, ES-23) on ureq 3,
//! synchronous, rustls, with a custom resolver and a constant allow-list.
//!
//! Contract skeleton: signatures only.

use crate::digest::Alg;
use crate::lookup::{Backend, Fetched, Limits};
use crate::cache::TmpFile;
use crate::services::{Fetchable, Scheme, ServiceUri};
use std::io;
use std::net::{IpAddr, SocketAddr};

/// The resolver hook (S2): consulted once per hop, including for IP literals.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// An allow-list of prefixes minus a deny-list (S3). Production passes
/// [`AddrTable::iana`].
#[derive(Clone, Debug)]
pub struct AddrTable {
    pub allow: Vec<(IpAddr, u8)>,
    pub deny: Vec<(IpAddr, u8)>,
}

impl AddrTable {
    /// The constant IANA special-purpose table of ES-15.
    pub fn iana() -> AddrTable {
        todo!("ES-15 table")
    }
}

/// ES-15: judged after `IpAddr::to_canonical()`; 6to4 by its embedded IPv4;
/// Teredo denied; everything outside the table denied.
pub fn permitted(ip: IpAddr, table: &AddrTable) -> bool {
    let _ = (ip, table);
    todo!("ES-15")
}

/// ES-14: the scheme may change only between https and http, and only when
/// `allow_http`; the same scheme is always fine.
pub fn redirect_scheme_allowed(from: Scheme, to: Scheme, allow_http: bool) -> bool {
    let _ = (from, to, allow_http);
    todo!("ES-14")
}

#[derive(Clone, Copy, Debug)]
pub struct HttpsConfig {
    pub allow_http: bool,
    pub allow_local: bool,
}

pub struct Client {
    _private: (),
}

impl Client {
    /// Loads trust roots lazily (ES-17): a failure is an `Error` outcome of
    /// the attempt, not a failure here.
    pub fn new(cfg: HttpsConfig, resolver: Box<dyn Resolver>, table: AddrTable) -> Client {
        let _ = (cfg, resolver, table);
        todo!("ES-17")
    }

    pub fn backend(&self, uri: ServiceUri) -> HttpsBackend<'_> {
        HttpsBackend { client: self, uri }
    }
}

pub struct HttpsBackend<'c> {
    client: &'c Client,
    uri: ServiceUri,
}

impl Backend for HttpsBackend<'_> {
    fn addresses(&self, alg: Alg) -> bool {
        let _ = (&self.client, &self.uri, alg);
        todo!("ES-4")
    }

    fn fetch(&self, d: &Fetchable, limits: &Limits, sink: TmpFile) -> Fetched {
        let _ = (d, limits, sink);
        todo!("ES-5")
    }
}
