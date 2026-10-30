//! Fake backend (FB): a hand-rolled HTTP/1.1 responder over `TcpListener`,
//! one thread per connection, one request per connection. Several "hosts"
//! exist because all of 127.0.0.0/8 is loopback on Linux.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// A deterministic hold: a response waits on it instead of on `sleep`.
#[derive(Clone, Default)]
pub struct Latch(Arc<(Mutex<bool>, Condvar)>);

impl Latch {
    pub fn fire(&self) {
        *self.0 .0.lock().unwrap() = true;
        self.0 .1.notify_all();
    }
    /// True once fired; false if `stop` was raised first.
    fn wait(&self, stop: &AtomicBool) -> bool {
        let mut g = self.0 .0.lock().unwrap();
        while !*g {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            g = self.0 .1.wait_timeout(g, Duration::from_millis(20)).unwrap().0;
        }
        true
    }
}

#[derive(Clone)]
pub enum Body {
    /// Content-Length framing with exactly these bytes.
    Bytes(Vec<u8>),
    /// Transfer-Encoding: chunked, one chunk per `n` bytes.
    Chunked(Vec<u8>, usize),
    /// Content-Length claims `claimed`, then `sent` bytes and a clean close.
    Lie { claimed: u64, sent: Vec<u8> },
    /// No length, bytes forever.
    Endless,
    /// No length; `byte` every `every`, forever (never idle, always late).
    Drip { byte: u8, every: Duration },
    /// Head, then nothing until released; then the bytes.
    HoldThen(Latch, Vec<u8>),
}

#[derive(Clone)]
pub struct Resp {
    pub interim: bool,
    pub status: u16,
    pub reason: Vec<u8>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Body,
    /// Do not answer at all: accept, read the request, hold the socket.
    pub hang: bool,
}

impl Resp {
    pub fn status(code: u16) -> Resp {
        Resp {
            interim: false,
            status: code,
            reason: b"X".to_vec(),
            headers: vec![],
            body: Body::Bytes(vec![]),
            hang: false,
        }
    }
    pub fn ok(blob: &[u8]) -> Resp {
        Resp {
            body: Body::Bytes(blob.to_vec()),
            ..Resp::status(200)
        }
    }
    pub fn hang() -> Resp {
        Resp {
            hang: true,
            ..Resp::status(200)
        }
    }
    pub fn redirect(code: u16, location: &str) -> Resp {
        Resp::status(code).header("Location", location.as_bytes())
    }
    pub fn header(mut self, k: &str, v: &[u8]) -> Resp {
        self.headers.push((k.as_bytes().to_vec(), v.to_vec()));
        self
    }
    pub fn reason(mut self, r: &[u8]) -> Resp {
        self.reason = r.to_vec();
        self
    }
    pub fn body(mut self, b: Body) -> Resp {
        self.body = b;
        self
    }
}

#[derive(Clone, Debug)]
pub struct Req {
    pub line: String,
    pub target: String,
    pub method: String,
    /// Header names as sent, in order.
    pub headers: Vec<(String, String)>,
    pub peer: SocketAddr,
    pub at: Instant,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

pub struct Fb {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
}

impl Fb {
    /// Serves `handler` on `ip:0`.
    pub fn start(ip: &str, handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Fb {
        Fb::start_on(ip, 0, handler)
    }

    /// As `start`, on a chosen port, so two addresses can share one port.
    pub fn start_on(ip: &str, port: u16, handler: impl Fn(&Req) -> Resp + Send + Sync + 'static) -> Fb {
        let l = TcpListener::bind((ip, port)).expect("bind loopback FB");
        let addr = l.local_addr().unwrap();
        let log: Arc<Mutex<Vec<Req>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let h: Handler = Arc::new(handler);
        let (log2, stop2) = (log.clone(), stop.clone());
        thread::spawn(move || {
            for conn in l.incoming() {
                if stop2.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(c) = conn else { continue };
                let (h, log, stop) = (h.clone(), log2.clone(), stop2.clone());
                thread::spawn(move || serve(c, &h, &log, &stop));
            }
        });
        Fb { addr, log, stop }
    }

    /// Serves the same honest blob for every request.
    pub fn blob(ip: &str, blob: &[u8]) -> Fb {
        let b = blob.to_vec();
        Fb::start(ip, move |_| Resp::ok(&b))
    }

    pub fn base(&self) -> String {
        format!("http://{}/", self.addr)
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Fb {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the accept loop so it can exit.
        let _ = TcpStream::connect(self.addr);
    }
}

fn read_request(c: &mut TcpStream) -> Option<(String, Vec<(String, String)>)> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).ok()? == 0 || buf.len() > 16 << 10 {
            return None;
        }
        buf.push(b[0]);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text.split("\r\n");
    let line = lines.next()?.to_string();
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect();
    Some((line, headers))
}

fn serve(mut c: TcpStream, h: &Handler, log: &Mutex<Vec<Req>>, stop: &AtomicBool) {
    let Ok(peer) = c.peer_addr() else { return };
    let Some((line, headers)) = read_request(&mut c) else {
        return;
    };
    let mut parts = line.split(' ');
    let (method, target) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let req = Req {
        line,
        target,
        method,
        headers,
        peer,
        at: Instant::now(),
    };
    log.lock().unwrap().push(req.clone());
    let r = h(&req);
    if r.hang {
        while !stop.load(Ordering::Relaxed) {
            // Detect the client giving up.
            let mut b = [0u8; 1];
            c.set_read_timeout(Some(Duration::from_millis(20))).ok();
            if matches!(c.read(&mut b), Ok(0)) {
                return;
            }
        }
        return;
    }
    let _ = respond(&mut c, &r, stop);
}

fn respond(c: &mut TcpStream, r: &Resp, stop: &AtomicBool) -> std::io::Result<()> {
    if r.interim {
        c.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let mut head = format!("HTTP/1.1 {} ", r.status).into_bytes();
    head.extend_from_slice(&r.reason);
    head.extend_from_slice(b"\r\nConnection: close\r\n");
    for (k, v) in &r.headers {
        head.extend_from_slice(k);
        head.extend_from_slice(b": ");
        head.extend_from_slice(v);
        head.extend_from_slice(b"\r\n");
    }
    match &r.body {
        Body::Bytes(b) => head.extend_from_slice(format!("Content-Length: {}\r\n", b.len()).as_bytes()),
        Body::Chunked(..) => head.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        Body::Lie { claimed, .. } => {
            head.extend_from_slice(format!("Content-Length: {claimed}\r\n").as_bytes())
        }
        Body::Endless | Body::Drip { .. } | Body::HoldThen(..) => {}
    }
    head.extend_from_slice(b"\r\n");
    c.write_all(&head)?;
    c.flush()?;
    match &r.body {
        Body::Bytes(b) => c.write_all(b)?,
        Body::Chunked(b, n) => {
            for ch in b.chunks((*n).max(1)) {
                write!(c, "{:x}\r\n", ch.len())?;
                c.write_all(ch)?;
                c.write_all(b"\r\n")?;
            }
            c.write_all(b"0\r\n\r\n")?;
        }
        Body::Lie { sent, .. } => c.write_all(sent)?,
        Body::Endless => {
            let chunk = vec![b'z'; 16 << 10];
            while !stop.load(Ordering::Relaxed) {
                c.write_all(&chunk)?;
            }
        }
        Body::Drip { byte, every } => {
            while !stop.load(Ordering::Relaxed) {
                c.write_all(&[*byte])?;
                c.flush()?;
                thread::sleep(*every);
            }
        }
        Body::HoldThen(latch, b) => {
            if latch.wait(stop) {
                c.write_all(b)?;
            }
        }
    }
    c.flush()
}
