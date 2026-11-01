//! Fixed-space admission before TLS/HTTP work. Transport peers only; no forwarded headers.
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const PEERS: usize = 256;
struct Bucket {
    credit: u64,
    updated: Instant,
    rate: u64,
    burst: u64,
}
impl Bucket {
    fn new(now: Instant, rate: u64, burst: u64) -> Self {
        Self {
            credit: burst * 1000,
            updated: now,
            rate,
            burst,
        }
    }
    fn refill(&mut self, now: Instant) {
        let ms = now
            .saturating_duration_since(self.updated)
            .as_millis()
            .min(60_000) as u64;
        if ms > 0 {
            self.credit = self
                .credit
                .saturating_add(ms * self.rate)
                .min(self.burst * 1000);
            self.updated = now;
        }
    }
}
struct Peer {
    active: u64,
    bucket: Bucket,
    seen: Instant,
}
struct State {
    active: u64,
    global: Bucket,
    peers: HashMap<IpAddr, Peer>,
}
pub(crate) struct Admission(Mutex<State>);
pub(crate) struct Permit {
    admission: Arc<Admission>,
    peer: IpAddr,
}
pub(crate) fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut b = ip.octets();
                b[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(b))
            }
        },
        ip => ip,
    }
}
impl Admission {
    pub fn new() -> Self {
        Self(Mutex::new(State {
            active: 0,
            global: Bucket::new(Instant::now(), 64, 128),
            peers: HashMap::new(),
        }))
    }
    pub fn acquire(self: &Arc<Self>, ip: IpAddr, draining: bool) -> Option<Permit> {
        self.at(ip, draining, Instant::now())
    }
    fn at(self: &Arc<Self>, ip: IpAddr, draining: bool, now: Instant) -> Option<Permit> {
        let ip = key(ip);
        let mut state = self.0.lock().ok()?;
        state.global.refill(now);
        if !pathward::release::admission_allowed(
            state.active,
            0,
            state.global.credit / 1000,
            draining,
        ) {
            return None;
        }
        if !state.peers.contains_key(&ip) {
            if state.peers.len() == PEERS {
                state.peers.retain(|_, p| {
                    p.active != 0 || now.saturating_duration_since(p.seen) < Duration::from_secs(60)
                });
            }
            if state.peers.len() == PEERS {
                return None;
            }
            state.peers.insert(
                ip,
                Peer {
                    active: 0,
                    bucket: Bucket::new(now, 8, 16),
                    seen: now,
                },
            );
        }
        let global = state.active;
        let peer = state.peers.get_mut(&ip)?;
        peer.bucket.refill(now);
        peer.seen = now;
        if !pathward::release::admission_allowed(
            global,
            peer.active,
            peer.bucket.credit / 1000,
            draining,
        ) {
            return None;
        }
        peer.active += 1;
        peer.bucket.credit -= 1000;
        state.active += 1;
        state.global.credit -= 1000;
        Some(Permit {
            admission: self.clone(),
            peer: ip,
        })
    }
}
impl Permit {
    pub fn peer(&self) -> IpAddr {
        self.peer
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.admission.0.lock() {
            state.active = state.active.saturating_sub(1);
            if let Some(peer) = state.peers.get_mut(&self.peer) {
                peer.active = peer.active.saturating_sub(1);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_global_rate_limits_refill_and_leases() {
        let a = Arc::new(Admission::new());
        let now = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        let leases: Vec<_> = (0..6).map(|_| a.at(ip, false, now).unwrap()).collect();
        assert!(a.at(ip, false, now).is_none());
        drop(leases);
        for _ in 0..10 {
            drop(a.at(ip, false, now).unwrap());
        }
        assert!(a.at(ip, false, now).is_none());
        assert!(a.at(ip, false, now + Duration::from_secs(1)).is_some());
        assert!(a.at(ip, true, now).is_none());
        let mut leases = Vec::new();
        for i in 2..14 {
            leases.push(a.at(IpAddr::from([127, 0, 0, i]), false, now).unwrap());
        }
        assert!(a.at(IpAddr::from([127, 0, 0, 20]), false, now).is_none());
        drop(leases);
        assert_eq!(a.0.lock().unwrap().active, 0);
    }

    #[test]
    fn denied_new_peers_cannot_fill_the_table_while_all_slots_are_in_use() {
        let a = Arc::new(Admission::new());
        let now = Instant::now();
        let held: Vec<_> = (0..12)
            .map(|i| a.at(IpAddr::from([10, 0, 0, i]), false, now).unwrap())
            .collect();
        for i in 0..255 {
            assert!(a.at(IpAddr::from([10, 0, 1, i]), false, now).is_none());
        }
        assert_eq!(a.0.lock().unwrap().peers.len(), 12);
        drop(held);
        assert!(a.at(IpAddr::from([10, 0, 2, 1]), false, now).is_some());
    }
    #[test]
    fn ipv6_prefix_and_mapped_v4_share_a_limit_and_table_is_bounded() {
        assert_eq!(
            key("::ffff:127.0.0.1".parse().unwrap()),
            key("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            key("2001:db8::1".parse().unwrap()),
            key("2001:db8::2".parse().unwrap())
        );
        let a = Arc::new(Admission::new());
        let now = Instant::now();
        for i in 0..256 {
            drop(
                a.at(
                    IpAddr::from([10, 0, 0, i as u8]),
                    false,
                    now + Duration::from_millis(i * 20),
                )
                .unwrap(),
            );
        }
        assert!(
            a.at(
                IpAddr::from([10, 0, 1, 1]),
                false,
                now + Duration::from_secs(6)
            )
            .is_none()
        );
        assert_eq!(a.0.lock().unwrap().peers.len(), 256);
        assert!(
            a.at(
                IpAddr::from([10, 0, 1, 1]),
                false,
                now + Duration::from_secs(66)
            )
            .is_some()
        );
    }
}
