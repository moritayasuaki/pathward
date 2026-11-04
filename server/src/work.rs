//! Fixed-space queue. Waiting I/O is a cooperative task, not an occupied worker.
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{Arc, Mutex},
};
struct State<T> {
    pending: VecDeque<T>,
    closed: bool,
}
pub(crate) struct Queue<T> {
    capacity: usize,
    state: Mutex<State<T>>,
}
impl<T> Queue<T> {
    pub fn new(shared_nat: bool) -> Arc<Self> {
        Arc::new(Self {
            capacity: pathward::release::capacity_queue(shared_nat) as usize,
            state: Mutex::new(State {
                pending: VecDeque::new(),
                closed: false,
            }),
        })
    }
    pub fn push(&self, _peer: IpAddr, job: T) -> Result<(), T> {
        let Ok(mut s) = self.state.lock() else {
            return Err(job);
        };
        if s.closed || s.pending.len() >= self.capacity {
            return Err(job);
        }
        s.pending.push_back(job);
        Ok(())
    }
    pub fn try_take(&self) -> Option<T> {
        let mut s = self.state.lock().ok()?;
        if s.closed {
            None
        } else {
            s.pending.pop_front()
        }
    }
    pub fn close(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.closed = true;
            let pending = std::mem::take(&mut s.pending);
            drop(s);
            drop(pending);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_fifo_and_close() {
        for shared in [false, true] {
            let q = Queue::new(shared);
            let peer = "127.0.0.1".parse().unwrap();
            for i in 0..q.capacity {
                q.push(peer, i).unwrap();
            }
            assert!(q.push(peer, 9999).is_err());
            for i in 0..q.capacity {
                assert_eq!(q.try_take(), Some(i));
            }
            assert_eq!(q.try_take(), None);
            q.push(peer, 1).unwrap();
            q.close();
            assert!(q.try_take().is_none());
            assert!(q.push(peer, 1).is_err());
        }
    }
}
