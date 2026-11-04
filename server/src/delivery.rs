//! Bounded input collection and cooperative downstream writes. No new I/O runtime.
use crate::{
    admission,
    http::{self, Transport},
    observe,
    stream_pool::Connection,
    work,
};
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

pub const HEAD_BYTES: usize = 262144;
pub const FILE_CHUNK: usize = 16384;
pub const QUEUE_BUDGET: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Usage {
    global: u64,
    peers: HashMap<IpAddr, u64>,
}
#[derive(Clone, Default)]
pub struct Budget(Arc<Mutex<Usage>>);
pub struct Lease {
    budget: Budget,
    peer: IpAddr,
    amount: u64,
}
impl Budget {
    pub fn reserve(&self, peer: IpAddr, amount: u64, draining: bool) -> Option<Lease> {
        let mut s = self.0.lock().ok()?;
        let used = s.peers.get(&peer).copied().unwrap_or(0);
        if !pathward::delivery::reserve_allowed(s.global, used, amount, draining) {
            return None;
        }
        s.global += amount;
        s.peers.insert(peer, used + amount);
        Some(Lease {
            budget: self.clone(),
            peer,
            amount,
        })
    }
}
impl Lease {
    fn shrink(&mut self, amount: u64) -> io::Result<()> {
        if !pathward::delivery::shrink_allowed(self.amount, amount) {
            return Err(io::Error::other("delivery reservation exceeded"));
        }
        let mut s = self
            .budget
            .0
            .lock()
            .map_err(|_| io::Error::other("delivery budget"))?;
        let n = self.amount - amount;
        s.global -= n;
        *s.peers
            .get_mut(&self.peer)
            .ok_or_else(|| io::Error::other("delivery peer"))? -= n;
        self.amount = amount;
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut s) = self.budget.0.lock() {
            s.global = s.global.saturating_sub(self.amount);
            if let Some(p) = s.peers.get_mut(&self.peer) {
                *p = p.saturating_sub(self.amount);
                if *p == 0 {
                    s.peers.remove(&self.peer);
                }
            }
        }
    }
}

enum Body {
    Bytes {
        data: Box<[u8]>,
        at: usize,
    },
    File {
        file: File,
        left: u64,
        chunk: Box<[u8; FILE_CHUNK]>,
        at: usize,
        end: usize,
    },
}
pub struct Prepared {
    head: Box<[u8]>,
    head_at: usize,
    body: Body,
    pub status: u16,
    bytes: u64,
    deadline: Instant,
    idle: Instant,
    _lease: Option<Lease>,
}
impl Prepared {
    fn progress(&self) -> observe::DeliveryProgress {
        let phase = if self.head_at < self.head.len() {
            observe::DeliveryPhase::Head
        } else if match &self.body {
            Body::Bytes { data, at } => *at < data.len(),
            Body::File { left, .. } => *left > 0,
        } {
            observe::DeliveryPhase::Body
        } else {
            observe::DeliveryPhase::Finish
        };
        observe::DeliveryProgress {
            phase,
            status: self.status,
            head_bytes: self.head_at,
            body_bytes: self.bytes,
        }
    }
    pub fn buffered(
        head: String,
        body: Vec<u8>,
        status: u16,
        deadline: Instant,
        mut lease: Lease,
    ) -> io::Result<Self> {
        if head.len() > HEAD_BYTES {
            return Err(io::Error::other("response head too large"));
        }
        // The upstream builder reserves its complete bounded capacity once.
        // Shrinking here releases unused storage before the charge is reduced.
        let data = body.into_boxed_slice();
        let head = head.into_bytes().into_boxed_slice();
        lease.shrink((head.len() + data.len()) as u64)?;
        Ok(Self {
            head,
            head_at: 0,
            body: Body::Bytes { data, at: 0 },
            status,
            bytes: 0,
            deadline,
            idle: Instant::now() + Duration::from_secs(5),
            _lease: Some(lease),
        })
    }
    pub fn file(
        head: String,
        file: File,
        count: u64,
        status: u16,
        deadline: Instant,
        mut lease: Lease,
    ) -> io::Result<Self> {
        if head.len() > HEAD_BYTES {
            return Err(io::Error::other("response head too large"));
        }
        let head = head.into_bytes().into_boxed_slice();
        lease.shrink((head.len() + FILE_CHUNK) as u64)?;
        Ok(Self {
            head,
            head_at: 0,
            body: Body::File {
                file,
                left: count,
                chunk: Box::new([0; FILE_CHUNK]),
                at: 0,
                end: 0,
            },
            status,
            bytes: 0,
            deadline,
            idle: Instant::now() + Duration::from_secs(5),
            _lease: Some(lease),
        })
    }
    pub fn rejection(status: u16) -> Self {
        Self {
            head: http::response_head(status, 0, "text/plain")
                .into_bytes()
                .into_boxed_slice(),
            head_at: 0,
            body: Body::Bytes {
                data: Box::new([]),
                at: 0,
            },
            status,
            bytes: 0,
            deadline: Instant::now() + Duration::from_secs(1),
            idle: Instant::now() + Duration::from_secs(1),
            _lease: None,
        }
    }
    fn step(&mut self, c: &mut Connection, drain: Option<Instant>) -> io::Result<bool> {
        let deadline = self
            .deadline
            .min(self.idle)
            .min(drain.unwrap_or(self.deadline));
        c.deadline(deadline)?;
        if self.head_at < self.head.len() {
            let end = self.head.len().min(self.head_at + FILE_CHUNK);
            let n = c.write(&self.head[self.head_at..end])?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.head_at += n;
            self.idle = Instant::now() + Duration::from_secs(5);
            return Ok(false);
        }
        let n = match &mut self.body {
            Body::Bytes { data, at } if *at < data.len() => {
                let end = data.len().min(*at + FILE_CHUNK);
                let n = c.write(&data[*at..end])?;
                if n == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                *at += n;
                n
            }
            Body::File {
                file,
                left,
                chunk,
                at,
                end,
            } if *left > 0 => {
                if *at == *end {
                    let count = (*left).min(FILE_CHUNK as u64) as usize;
                    *end = file.read(&mut chunk[..count])?;
                    *at = 0;
                    if *end == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file changed"));
                    }
                }
                let n = c.write(&chunk[*at..*end])?;
                if n == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                *at += n;
                *left -= n as u64;
                n
            }
            _ => {
                c.flush()?;
                c.complete()?;
                return Ok(true);
            }
        };
        self.bytes += n as u64;
        self.idle = Instant::now() + Duration::from_secs(5);
        Ok(false)
    }
}

pub struct Input {
    pub client: Connection,
    pub prefix: Vec<u8>,
    pub started: Instant,
    pub redirect: bool,
    pub permit: admission::Permit,
    pub active: observe::Active,
}
pub enum Work {
    Handshake {
        stream: TcpStream,
        accepted: Instant,
        permit: admission::Permit,
        active: observe::Active,
    },
    Http {
        input: Input,
        queued: Instant,
    },
}
pub struct Output {
    pub client: Connection,
    pub prepared: Prepared,
    pub generation: u64,
    pub started: Instant,
    pub _permit: admission::Permit,
    pub _active: observe::Active,
}
enum Event {
    Head(Input),
    Output(Output),
}
#[derive(Clone)]
pub struct Sink(SyncSender<Event>);
pub struct Reactor {
    rx: Receiver<Event>,
    heads: VecDeque<Input>,
    outputs: VecDeque<Output>,
}
pub fn channel(capacity: usize) -> (Sink, Reactor) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    (
        Sink(tx),
        Reactor {
            rx,
            heads: VecDeque::new(),
            outputs: VecDeque::new(),
        },
    )
}
impl Sink {
    pub fn input(&self, mut input: Input) -> io::Result<()> {
        input.client.nonblocking()?;
        self.0
            .try_send(Event::Head(input))
            .map_err(|_| io::Error::other("input handoff full"))
    }
    pub fn output(&self, mut output: Output) -> io::Result<()> {
        output.client.nonblocking()?;
        self.0
            .try_send(Event::Output(output))
            .map_err(|_| io::Error::other("output handoff full"))
    }
}
fn blocked(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
impl Reactor {
    fn reject(&mut self, input: Input, status: u16, generation: u64) {
        self.outputs.push_back(Output {
            client: input.client,
            prepared: Prepared::rejection(status),
            generation,
            started: input.started,
            _permit: input.permit,
            _active: input.active,
        });
    }
    pub fn run(
        &mut self,
        queue: &Arc<work::Queue<Work>>,
        observe: &observe::Observability,
        shutdown: &AtomicBool,
        workers_done: &AtomicBool,
        generation: &dyn Fn() -> u64,
    ) {
        let mut drain = None;
        loop {
            if shutdown.load(Ordering::Acquire) && drain.is_none() {
                drain = Some(Instant::now() + Duration::from_secs(5));
            }
            for event in self.rx.try_iter() {
                match event {
                    Event::Head(i) => self.heads.push_back(i),
                    Event::Output(o) => self.outputs.push_back(o),
                }
            }
            for _ in 0..self.heads.len() {
                let Some(mut input) = self.heads.pop_front() else {
                    break;
                };
                let live = pathward::delivery::phase_live(
                    input.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    5000,
                    drain.is_some(),
                );
                if !live {
                    let status =
                        pathward::delivery::input_timeout_status(input.prefix.len() as u64);
                    if status != 0 {
                        self.reject(input, status, generation());
                    }
                    continue;
                }
                let mut buffer = [0u8; http::MAX_HEAD_BYTES];
                let left = http::MAX_HEAD_BYTES - input.prefix.len();
                let read = input
                    .client
                    .deadline(input.started + http::READ_BUDGET)
                    .and_then(|_| input.client.read(&mut buffer[..left]));
                match read {
                    Ok(0) => continue,
                    Ok(n) => input.prefix.extend_from_slice(&buffer[..n]),
                    Err(e) if blocked(&e) => {
                        self.heads.push_back(input);
                        continue;
                    }
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                        // The deadline can expire between the phase check and
                        // the transport read. Preserve the same timeout policy.
                        let status =
                            pathward::delivery::input_timeout_status(input.prefix.len() as u64);
                        if status != 0 {
                            self.reject(input, status, generation());
                        }
                        continue;
                    }
                    Err(_) => continue,
                }
                if input.prefix.windows(4).any(|w| w == b"\r\n\r\n") {
                    let peer = input.permit.peer();
                    if let Err(Work::Http { input, .. }) = queue.push(
                        peer,
                        Work::Http {
                            input,
                            queued: Instant::now(),
                        },
                    ) {
                        observe.overloaded.fetch_add(1, Ordering::Relaxed);
                        self.reject(input, 503, generation());
                    }
                } else if input.prefix.len() == http::MAX_HEAD_BYTES {
                    self.reject(input, 431, generation());
                } else {
                    self.heads.push_back(input);
                }
            }
            for _ in 0..self.outputs.len() {
                let Some(mut output) = self.outputs.pop_front() else {
                    break;
                };
                let result = output.prepared.step(&mut output.client, drain);
                match result {
                    Ok(false) => self.outputs.push_back(output),
                    Err(e) if blocked(&e) => self.outputs.push_back(output),
                    other => {
                        observe.delivery_request(
                            output.generation,
                            output.started.elapsed(),
                            &other.map(|_| (output.prepared.status, output.prepared.bytes)),
                            output.prepared.progress(),
                        );
                    }
                }
            }
            if workers_done.load(Ordering::Acquire)
                && self.heads.is_empty()
                && self.outputs.is_empty()
            {
                match self.rx.try_recv() {
                    Ok(Event::Head(i)) => self.heads.push_back(i),
                    Ok(Event::Output(o)) => self.outputs.push_back(o),
                    Err(_) => break,
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}

/// Header bytes collected before dispatch are consumed once by the strict parser.
pub struct Replay<'a> {
    pub client: &'a mut Connection,
    prefix: &'a [u8],
    at: usize,
}
impl<'a> Replay<'a> {
    pub fn new(client: &'a mut Connection, prefix: &'a [u8]) -> Self {
        Self {
            client,
            prefix,
            at: 0,
        }
    }
}
impl Read for Replay<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.at < self.prefix.len() {
            let n = b.len().min(self.prefix.len() - self.at);
            b[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        } else {
            self.client.read(b)
        }
    }
}
impl Write for Replay<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.client.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.client.flush()
    }
}
impl Transport for Replay<'_> {
    fn buffered_head(&mut self) -> Option<Vec<u8>> {
        if self.at != 0 {
            return None;
        }
        self.at = self.prefix.len();
        Some(self.prefix.to_vec())
    }
    fn deadline(&mut self, d: Instant) -> io::Result<()> {
        self.client.deadline(d)
    }
    fn local_port(&self) -> io::Result<u16> {
        self.client.local_port()
    }
    fn peer_ip(&self) -> Option<IpAddr> {
        self.client.peer_ip()
    }
    fn nonblocking(&mut self) -> io::Result<()> {
        self.client.nonblocking()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staged_head_preserves_large_prefetched_body_once() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut client = Connection::Plain(listener.accept().unwrap().0);
        let mut prefix =
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 8192\r\n\r\n".to_vec();
        prefix.extend_from_slice(&[42; 8192]);
        let mut replay = Replay::new(&mut client, &prefix);
        let head = http::read_head(&mut replay, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(head, prefix);
        sender.write_all(b"x").unwrap();
        let mut next = [0];
        replay.read_exact(&mut next).unwrap();
        assert_eq!(&next, b"x");
    }
    #[test]
    fn reservations_hold_peer_and_global_caps_until_shrink_or_drop() {
        let budget = Budget::default();
        let a = "127.0.0.1".parse().unwrap();
        let b = "127.0.0.2".parse().unwrap();
        let mut first = budget.reserve(a, 201326592, false).unwrap();
        assert!(budget.reserve(a, 1, false).is_none());
        let second = budget.reserve(b, 67108864, false).unwrap();
        assert!(budget.reserve(b, 1, false).is_none());
        assert!(first.shrink(201326593).is_err());
        first.shrink(7).unwrap();
        let replacement = budget.reserve(a, 201326585, false).unwrap();
        assert!(budget.reserve(b, 1, false).is_none());
        assert!(budget.reserve(a, 0, false).is_none());
        assert!(budget.reserve(a, 1, true).is_none());
        drop((first, second, replacement));
        let state = budget.0.lock().unwrap();
        assert_eq!(state.global, 0);
        assert!(state.peers.is_empty());
    }
}
