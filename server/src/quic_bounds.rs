//! Bound raw HTTP/3 bytes before QPACK/frame buffering in the protocol library.
use bytes::{Buf, Bytes};
use h3::quic::{self, RecvStream as _};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};
const HEAD: u64 = 32768;
#[derive(Default)]
struct Count {
    used: u64,
    limit: u64,
}
#[derive(Clone, Default)]
pub struct Budgets(Arc<Mutex<HashMap<quic::StreamId, Arc<Mutex<Count>>>>>);
impl Budgets {
    pub fn body(&self, id: quic::StreamId, limit: u64) -> bool {
        let Ok(map) = self.0.lock() else { return false };
        let Some(count) = map.get(&id) else {
            return false;
        };
        let Ok(mut c) = count.lock() else {
            return false;
        };
        if limit > 67108864 {
            return false;
        }
        let limit = 2 * limit + HEAD;
        if !pathward::delivery::wire_fits(c.used, 0, limit) {
            return false;
        }
        c.limit = limit;
        true
    }
    pub fn release(&self, id: quic::StreamId) {
        if let Ok(mut map) = self.0.lock() {
            map.remove(&id);
        }
    }
}
fn fail() -> quic::StreamErrorIncoming {
    quic::StreamErrorIncoming::StreamTerminated {
        error_code: h3::error::Code::H3_EXCESSIVE_LOAD.value(),
    }
}
pub struct Bound<S> {
    inner: S,
    count: Arc<Mutex<Count>>,
}
impl<S: quic::RecvStream> quic::RecvStream for Bound<S> {
    type Buf = S::Buf;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, quic::StreamErrorIncoming>> {
        let data = ready!(self.inner.poll_data(cx))?;
        if let Some(data) = &data {
            let Ok(mut c) = self.count.lock() else {
                return Poll::Ready(Err(fail()));
            };
            if !pathward::delivery::wire_fits(c.used, data.remaining() as u64, c.limit) {
                self.inner
                    .stop_sending(h3::error::Code::H3_EXCESSIVE_LOAD.value());
                return Poll::Ready(Err(fail()));
            }
            c.used += data.remaining() as u64;
        }
        Poll::Ready(Ok(data))
    }
    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code)
    }
    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}
impl<S: quic::SendStream<Bytes>> quic::SendStream<Bytes> for Bound<S> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code)
    }
    fn send_data<D: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: D,
    ) -> Result<(), quic::StreamErrorIncoming> {
        self.inner.send_data(data)
    }
    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}
pub type Bidi = Bound<h3_quinn::BidiStream<Bytes>>;
pub struct Connection {
    inner: h3_quinn::Connection,
    budgets: Budgets,
    uni: u64,
}
pub struct Opener(h3_quinn::OpenStreams);
impl Connection {
    pub fn new(quic: quinn::Connection, budgets: Budgets) -> Self {
        Self {
            inner: h3_quinn::Connection::new(quic),
            budgets,
            uni: 0,
        }
    }
}
impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = Bidi;
    type SendStream = h3_quinn::SendStream<Bytes>;
    fn poll_open_bidi(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Bidi, quic::StreamErrorIncoming>> {
        Poll::Ready(Err(fail()))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason)
    }
}
impl quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Bidi;
    type SendStream = h3_quinn::SendStream<Bytes>;
    fn poll_open_bidi(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Bidi, quic::StreamErrorIncoming>> {
        Poll::Ready(Err(fail()))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.0.poll_open_send(cx)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::close(&mut self.0, code, reason)
    }
}
impl quic::Connection<Bytes> for Connection {
    type RecvStream = Bound<h3_quinn::RecvStream>;
    type OpenStreams = Opener;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        let recv = ready!(
            <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(
                &mut self.inner,
                cx
            )
        )?;
        if self.uni >= 8 {
            return Poll::Ready(Err(quic::ConnectionErrorIncoming::ApplicationClose {
                error_code: h3::error::Code::H3_EXCESSIVE_LOAD.value(),
            }));
        }
        self.uni += 1;
        Poll::Ready(Ok(Bound {
            inner: recv,
            count: Arc::new(Mutex::new(Count {
                used: 0,
                limit: 65536,
            })),
        }))
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, quic::ConnectionErrorIncoming>> {
        let recv = ready!(self.inner.poll_accept_bidi(cx))?;
        let count = Arc::new(Mutex::new(Count {
            used: 0,
            limit: HEAD,
        }));
        let error = || quic::ConnectionErrorIncoming::ApplicationClose {
            error_code: h3::error::Code::H3_EXCESSIVE_LOAD.value(),
        };
        let Ok(mut map) = self.budgets.0.lock() else {
            return Poll::Ready(Err(error()));
        };
        if map.len() >= 100 {
            return Poll::Ready(Err(error()));
        }
        map.insert(recv.recv_id(), count.clone());
        Poll::Ready(Ok(Bound { inner: recv, count }))
    }
    fn opener(&self) -> Opener {
        Opener(<h3_quinn::Connection as quic::Connection<Bytes>>::opener(
            &self.inner,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Input {
        chunks: VecDeque<Bytes>,
        stopped: bool,
    }
    impl quic::RecvStream for Input {
        type Buf = Bytes;
        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
            Poll::Ready(Ok(self.chunks.pop_front()))
        }
        fn stop_sending(&mut self, _: u64) {
            self.stopped = true;
        }
        fn recv_id(&self) -> quic::StreamId {
            0u64.try_into().unwrap()
        }
    }
    #[test]
    fn raw_limit_precedes_frame_decoder_and_body_limit_can_only_extend_within_cap() {
        let budgets = Budgets::default();
        let count = Arc::new(Mutex::new(Count {
            used: 0,
            limit: HEAD,
        }));
        let id = 0u64.try_into().unwrap();
        budgets.0.lock().unwrap().insert(id, count.clone());
        let mut input = Bound {
            inner: Input {
                chunks: VecDeque::from([
                    Bytes::from(vec![0; 32768]),
                    Bytes::from(vec![0; 1024]),
                    Bytes::from(vec![0; 1025]),
                ]),
                stopped: false,
            },
            count: count.clone(),
        };
        futures_lite::future::block_on(async {
            let first = futures_lite::future::poll_fn(|cx| input.poll_data(cx))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.len(), 32768);
            assert!(!budgets.body(id, u64::MAX));
            assert_eq!(count.lock().unwrap().limit, HEAD);
            assert!(budgets.body(id, 1024));
            assert_eq!(
                futures_lite::future::poll_fn(|cx| input.poll_data(cx))
                    .await
                    .unwrap()
                    .unwrap()
                    .len(),
                1024
            );
            assert!(
                futures_lite::future::poll_fn(|cx| input.poll_data(cx))
                    .await
                    .is_err()
            );
        });
        assert!(input.inner.stopped);
        assert_eq!(count.lock().unwrap().used, 33792);
        budgets.release(id);
        assert!(!budgets.body(id, 1024));
    }
}
