//! Bounded dispatch: an admitted slow peer cannot occupy all serving workers.
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
struct State<T> {
    pending: VecDeque<(IpAddr, T)>,
    running: Vec<IpAddr>,
    closed: bool,
}
pub(crate) struct Queue<T> {
    capacity: usize,
    state: Mutex<State<T>>,
    changed: Condvar,
}
pub(crate) struct Running<T> {
    queue: Arc<Queue<T>>,
    peer: IpAddr,
}
impl<T> Queue<T> {
    pub fn new(shared_nat: bool) -> Arc<Self> {
        Arc::new(Self {
            capacity: pathward::release::capacity_queue(shared_nat) as usize,
            state: Mutex::new(State {
                pending: VecDeque::new(),
                running: Vec::new(),
                closed: false,
            }),
            changed: Condvar::new(),
        })
    }
    pub fn push(&self, peer: IpAddr, job: T) -> Result<(), T> {
        let Ok(mut state) = self.state.lock() else {
            return Err(job);
        };
        if state.closed || state.pending.len() >= self.capacity {
            return Err(job);
        }
        state.pending.push_back((peer, job));
        self.changed.notify_all();
        Ok(())
    }
    pub fn take(self: &Arc<Self>, shutdown: &AtomicBool) -> Option<(T, Running<T>)> {
        let mut state = self.state.lock().ok()?;
        loop {
            if state.closed || shutdown.load(Ordering::Acquire) {
                return None;
            }
            // Skip an ineligible peer, retaining FIFO order within each peer.
            let position = state.pending.iter().position(|(peer, _)| {
                pathward::release::dispatch_allowed(
                    state.running.len() as u64,
                    state.running.iter().filter(|p| *p == peer).count() as u64,
                    false,
                )
            });
            if let Some(position) = position {
                let (peer, job) = state.pending.remove(position)?;
                state.running.push(peer);
                return Some((
                    job,
                    Running {
                        queue: self.clone(),
                        peer,
                    },
                ));
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
            let pending = std::mem::take(&mut state.pending);
            drop(state);
            drop(pending);
        }
        self.changed.notify_all();
    }
}
impl<T> Drop for Running<T> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.queue.state.lock()
            && let Some(i) = state.running.iter().position(|p| *p == self.peer)
        {
            state.running.swap_remove(i);
        }
        self.queue.changed.notify_all();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bypasses_busy_peer_without_rejecting_its_queued_work_and_releases_slots() {
        let q = Queue::new(false);
        let a = "127.0.0.1".parse().unwrap();
        let b = "127.0.0.2".parse().unwrap();
        let stop = AtomicBool::new(false);
        for value in 0..6 {
            q.push(a, value).unwrap();
        }
        q.push(b, 10).unwrap();
        let (first, x) = q.take(&stop).unwrap();
        let (second, y) = q.take(&stop).unwrap();
        let (other, z) = q.take(&stop).unwrap();
        assert_eq!((first, second, other), (0, 1, 10));
        assert_eq!(q.state.lock().unwrap().running.len(), 3);
        drop(x);
        let (third, x) = q.take(&stop).unwrap();
        assert_eq!(third, 2);
        q.close();
        assert!(q.take(&stop).is_none());
        assert!(q.push(b, 99).is_err());
        drop((x, y, z));
        assert!(q.state.lock().unwrap().running.is_empty());
        assert!(q.state.lock().unwrap().pending.is_empty());
    }
    #[test]
    fn queue_capacity_and_shutdown_are_fail_closed() {
        let q = Queue::new(false);
        let peer = "::1".parse().unwrap();
        for i in 0..crate::QUEUE_CAPACITY {
            q.push(peer, i).unwrap();
        }
        assert_eq!(q.push(peer, 100), Err(100));
        assert!(q.take(&AtomicBool::new(true)).is_none());
        q.close();
    }
    #[test]
    fn larger_queue_preserves_worker_fairness_and_bounded_storage() {
        let q = Queue::new(true);
        let peer = "127.0.0.20".parse().unwrap();
        let other = "127.0.0.1".parse().unwrap();
        let stop = AtomicBool::new(false);
        for i in 0..144 {
            q.push(peer, i).unwrap();
        }
        q.push(other, 999).unwrap();
        let (_, a) = q.take(&stop).unwrap();
        let (_, b) = q.take(&stop).unwrap();
        let (value, c) = q.take(&stop).unwrap();
        assert_eq!(value, 999);
        for i in 0..46 {
            q.push(peer, i).unwrap();
        }
        assert_eq!(q.state.lock().unwrap().pending.len(), 188);
        assert!(q.push(peer, 1000).is_err());
        q.close();
        drop((a, b, c));
        assert!(q.state.lock().unwrap().running.is_empty());
        assert!(q.state.lock().unwrap().pending.is_empty());
    }
}
