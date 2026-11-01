//! Fixed stream workers. Each queued or running job owns global, peer and host leases.
use crate::{
    http::Transport,
    runtime::ServicePermit,
    streaming::{Live, Permit},
    tls::TlsTransport,
};
use pathward_config::ProxyLimits;
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(crate) const WORKERS: usize = 16;
pub(crate) enum Connection {
    Plain(TcpStream),
    Tls(Box<TlsTransport>),
}
impl Read for Connection {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(b),
            Self::Tls(s) => s.read(b),
        }
    }
}
impl Write for Connection {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(b),
            Self::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}
impl Transport for Connection {
    fn deadline(&mut self, d: Instant) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.deadline(d),
            Self::Tls(s) => s.deadline(d),
        }
    }
    fn local_port(&self) -> io::Result<u16> {
        match self {
            Self::Plain(s) => s.local_port(),
            Self::Tls(s) => s.local_port(),
        }
    }
    fn peer_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Plain(s) => s.peer_ip(),
            Self::Tls(s) => s.peer_ip(),
        }
    }
    fn nonblocking(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.nonblocking(),
            Self::Tls(s) => s.nonblocking(),
        }
    }
}
impl Connection {
    pub fn finish(&mut self) {
        match self {
            Self::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            Self::Tls(s) => {
                let _ = s.finish();
            }
        }
    }
}
pub(crate) struct Prepared {
    pub live: Live,
    pub limits: ProxyLimits,
    pub status: u16,
    pub _global: Permit,
    pub _service: ServicePermit,
}
pub(crate) struct Job {
    pub client: Connection,
    pub prepared: Prepared,
    pub generation: u64,
    pub started: Instant,
    pub _active: crate::observe::Active,
}
struct State {
    jobs: VecDeque<Job>,
    closed: bool,
}
pub(crate) struct Pool {
    state: Mutex<State>,
    changed: Condvar,
}
impl Pool {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                jobs: VecDeque::new(),
                closed: false,
            }),
            changed: Condvar::new(),
        })
    }
    pub fn push(&self, job: Job) -> Result<(), Box<Job>> {
        let Ok(mut state) = self.state.lock() else {
            return Err(Box::new(job));
        };
        if state.closed || state.jobs.len() >= WORKERS {
            return Err(Box::new(job));
        }
        state.jobs.push_back(job);
        self.changed.notify_one();
        Ok(())
    }
    pub fn take(&self, stop: &AtomicBool) -> Option<Job> {
        let mut state = self.state.lock().ok()?;
        loop {
            if state.closed || stop.load(Ordering::Acquire) {
                return None;
            }
            if let Some(job) = state.jobs.pop_front() {
                return Some(job);
            }
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(50))
                .ok()?
                .0;
        }
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            let jobs = std::mem::take(&mut state.jobs);
            drop(state);
            drop(jobs);
        }
        self.changed.notify_all();
    }
}
