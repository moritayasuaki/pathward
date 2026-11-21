//! Local replica selection and the first application write. Probes carry no client data.
use crate::{async_http, http, proxy};
use pathward::upstream::{
    FirstIo, FirstWriteGate, FirstWriter, PoolHealth, first_write_report, fresh_health,
    guarded_first_write, healthy_response, pool_select, pool_tick, publish_health, publish_probe,
    retire_pool,
};
use std::{
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "backend_pool_io_tests.rs"]
mod io_tests;

const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

struct Member {
    address: SocketAddr,
    draining: bool,
    checking: AtomicBool,
    health: Mutex<PoolHealth>,
}

impl Member {
    fn cached(&self, now: u64) -> Option<bool> {
        let h = *self.health.lock().ok()?;
        if h.revision == u64::MAX {
            return Some(false);
        }
        fresh_health(h, now).then(|| healthy_response(h.status))
    }
}

struct SocketWrite<'a> {
    socket: &'a mut TcpStream,
    head: &'a [u8],
    error: Option<io::Error>,
}
impl FirstWriter for SocketWrite<'_> {
    fn write_once(&mut self) -> FirstIo {
        let (event, error) =
            first_write_report(async_http::write_report(self.socket.write(self.head)));
        self.error = error;
        event
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum WritePoint {
    BeforeDial,
    ProbeResponse(u16),
    Connected,
    ClockSampled(u64),
    Written,
    Waiting,
    Retiring,
}

struct ProbeGuard<'a>(&'a AtomicBool);
impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) struct Pool {
    members: Vec<Member>,
    /// Bit 16 selects IPv6 loopback. The low sixteen bits are a nonzero port.
    keys: Vec<u32>,
    probe: String,
    #[cfg(not(target_os = "linux"))]
    clock: Instant,
    next: AtomicUsize,
    /// Hold this and then member.health through one nonblocking write only.
    retired: Mutex<bool>,
    #[cfg(test)]
    pub(crate) at_write: std::sync::OnceLock<Box<dyn Fn(WritePoint) + Send + Sync>>,
}

fn key(addr: SocketAddr) -> u32 {
    (u32::from(addr.is_ipv6()) << 16) | u32::from(addr.port())
}

fn address(key: u32) -> Option<SocketAddr> {
    let port = key as u16;
    match (key >> 16, port) {
        (0, 1..) => Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        (1, 1..) => Some(SocketAddr::from((Ipv6Addr::LOCALHOST, port))),
        _ => None,
    }
}

impl Pool {
    pub fn new(host: &str, path: &str, addresses: &[SocketAddr], drains: &[SocketAddr]) -> Self {
        Self {
            keys: addresses.iter().copied().map(key).collect(),
            members: addresses
                .iter()
                .map(|&address| Member {
                    address,
                    draining: drains.contains(&address),
                    checking: AtomicBool::new(false),
                    health: Mutex::new(PoolHealth::default()),
                })
                .collect(),
            probe: format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nVia: 1.1 pathward\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            ),
            next: AtomicUsize::new(0),
            retired: Mutex::new(false),
            #[cfg(not(target_os = "linux"))]
            clock: Instant::now(),
            #[cfg(test)]
            at_write: Default::default(),
        }
    }

    #[cfg(target_os = "linux")]
    fn now(&self) -> u64 {
        // Health must age even while the machine is suspended. A failed or
        // unrepresentable clock sample closes the gate through pool_tick.
        use rustix::time::{DynamicClockId, clock_gettime_dynamic};
        let time = clock_gettime_dynamic(DynamicClockId::Boottime)
            .ok()
            .and_then(|t| Duration::try_from(t).ok());
        pool_tick(time.map(|d| d.as_nanos()))
    }

    #[cfg(not(target_os = "linux"))]
    fn now(&self) -> u64 {
        pool_tick(
            Instant::now()
                .checked_duration_since(self.clock)
                .map(|d| d.as_nanos()),
        )
    }

    #[cfg(test)]
    fn notify(&self, point: WritePoint) {
        if let Some(hook) = self.at_write.get() {
            hook(point);
        }
    }

    pub fn retire(&self) {
        #[cfg(test)]
        self.notify(WritePoint::Retiring);
        if let Ok(mut retired) = self.retired.lock() {
            retire_pool(&mut retired);
        }
    }

    async fn check(&self, member: &Member, deadline: Instant) -> io::Result<u16> {
        let mut socket = async_http::connect(member.address, http::remaining(deadline)?).await?;
        async_http::write_all(&mut socket, self.probe.as_bytes(), deadline).await?;
        proxy::probe_status(&mut socket, deadline).await
    }

    async fn ready(&self, member: &Member, deadline: Instant) -> bool {
        loop {
            if member.draining
                || Instant::now() >= deadline
                || self.retired.lock().map_or(true, |r| *r)
            {
                return false;
            }
            if let Some(ready) = member.cached(self.now()) {
                return ready;
            }
            if !member.checking.swap(true, Ordering::AcqRel) {
                let _guard = ProbeGuard(&member.checking);
                if let Some(ready) = member.cached(self.now()) {
                    return ready;
                }
                let Ok(expected) = member.health.lock().map(|h| h.revision) else {
                    return false;
                };
                let probe_deadline = Instant::now() + PROBE_TIMEOUT;
                let probe_started = self.now();
                let status = self
                    .check(member, deadline.min(probe_deadline))
                    .await
                    .unwrap_or(0);
                #[cfg(test)]
                self.notify(WritePoint::ProbeResponse(status));
                // A short client deadline must not poison the health of a replica.
                if (healthy_response(status)
                    || Instant::now() < deadline
                    || probe_deadline <= deadline)
                    && let Ok(mut h) = member.health.lock()
                {
                    *h = publish_probe(*h, expected, probe_started, self.now(), status);
                }
                return member.cached(self.now()) == Some(true);
            }
            async_http::pause().await;
        }
    }

    pub(crate) async fn refresh(&self, local_ports: &[u16], shutdown: &AtomicBool) {
        for member in &self.members {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            if !local_ports.contains(&member.address.port())
                && proxy::allowed_endpoint(member.address, 0)
            {
                self.ready(member, Instant::now() + PROBE_TIMEOUT).await;
            }
            // One member per poll, including cached/drained members of a large config.
            futures_lite::future::yield_now().await;
        }
    }

    async fn write_first(
        &self,
        index: usize,
        socket: &mut TcpStream,
        head: &[u8],
        deadline: Instant,
        sent: &mut bool,
    ) -> Result<Option<usize>, http::Rejection> {
        let member = &self.members[index];
        let peer = socket.peer_addr().map_err(|_| http::Rejection(502))?;
        if peer != member.address {
            return Err(http::Rejection(502));
        }
        #[cfg(test)]
        self.notify(WritePoint::Connected);
        loop {
            let outcome = crate::pool_locks::with_snapshot(
                &self.retired,
                &member.health,
                |retired, health| {
                    http::remaining(deadline).map_err(|_| http::Rejection(504))?;
                    // Take a fresh lease even after WouldBlock. Its destructor
                    // runs only after the synchronous write returns or unwinds.
                    #[cfg(target_os = "linux")]
                    let Ok(_lease) = crate::sleep_fence::first_write_lease() else {
                        return Ok(None);
                    };
                    let gate = FirstWriteGate {
                        peer: key(peer),
                        health: *health,
                        now: self.now(),
                        draining: member.draining,
                        retired: *retired,
                    };
                    #[cfg(test)]
                    self.notify(WritePoint::ClockSampled(gate.now));
                    let mut writer = SocketWrite {
                        socket,
                        head,
                        error: None,
                    };
                    let outcome = guarded_first_write(&self.keys, index, &gate, sent, &mut writer);
                    if let Some(error) = writer.error {
                        return Err(proxy::failure(error));
                    }
                    #[cfg(test)]
                    if matches!(outcome, Some(FirstIo::Written(_))) {
                        self.notify(WritePoint::Written);
                    }
                    Ok(outcome)
                },
            )
            .ok_or(http::Rejection(503))??;
            match outcome {
                None => return Ok(None),
                Some(FirstIo::Written(count)) => return Ok(Some(count)),
                Some(FirstIo::Failed) => return Err(http::Rejection(502)),
                Some(FirstIo::Wait) => {
                    #[cfg(test)]
                    self.notify(WritePoint::Waiting);
                    async_http::pause().await;
                }
            }
        }
    }

    pub(crate) async fn start(
        &self,
        local_port: u16,
        deadline: Instant,
        connect_timeout: Duration,
        head: &[u8],
        sent: &mut bool,
    ) -> Result<(TcpStream, usize), http::Rejection> {
        let count = self.members.len();
        if count == 0 || *sent {
            return Err(http::Rejection(503));
        }
        let first = self.next.fetch_add(1, Ordering::Relaxed) % count;
        let mut dials = 0;
        for offset in 0..count {
            let i = (first + offset) % count;
            let member = &self.members[i];
            if !proxy::allowed_endpoint(member.address, local_port) {
                continue;
            }
            let ready = self.ready(member, deadline).await;
            if *self.retired.lock().map_err(|_| http::Rejection(503))? {
                return Err(http::Rejection(503));
            }
            let selected = pool_select(&self.keys, i, ready, member.draining, *sent);
            let Some(addr) = address(selected) else {
                continue;
            };
            if addr != member.address {
                return Err(http::Rejection(503));
            }
            let timeout = http::remaining(deadline)
                .map_err(|_| http::Rejection(504))?
                .min(connect_timeout);
            dials += 1;
            #[cfg(test)]
            self.notify(WritePoint::BeforeDial);
            match async_http::connect(addr, timeout).await {
                Ok(mut socket) => {
                    if let Some(count) = self
                        .write_first(i, &mut socket, head, deadline, sent)
                        .await?
                    {
                        return Ok((socket, count));
                    }
                }
                Err(_) => {
                    let mut h = member.health.lock().map_err(|_| http::Rejection(503))?;
                    *h = publish_health(*h, h.revision, self.now(), 0);
                }
            }
            if dials == 2 {
                break;
            }
        }
        Err(http::Rejection(503))
    }
}

impl crate::Server {
    pub(crate) async fn refresh_backend_pools(&self, local_ports: [u16; 2], shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Acquire) {
            let snapshot = match self.state.read() {
                Ok(state) => state.snapshot.clone(),
                Err(_) => return,
            };
            for route in snapshot.sites.iter().flat_map(|site| &site.proxy_routes) {
                if let Some(pool) = &route.pool {
                    pool.refresh(&local_ports, shutdown).await;
                }
            }
            drop(snapshot);
            async_io::Timer::after(Duration::from_secs(1)).await;
        }
    }
}
