//! Cooperative operations over nonblocking transports; each wait yields its task.
use crate::http::{self, Transport};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub async fn pause() {
    async_io::Timer::after(Duration::from_millis(2)).await;
}
pub async fn operation<T>(
    deadline: Instant,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    loop {
        http::remaining(deadline)?;
        match op() {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                pause().await
            }
            result => return result,
        }
    }
}
pub async fn read(s: &mut impl Transport, b: &mut [u8], d: Instant) -> io::Result<usize> {
    s.deadline(d)?;
    operation(d, || s.read(b)).await
}
pub async fn read_head(s: &mut impl Transport, d: Instant) -> io::Result<Vec<u8>> {
    if let Some(head) = s.buffered_head() {
        http::remaining(d)?;
        if head.len() > http::MAX_HEAD_BYTES || !head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(head);
    }
    let mut data = Vec::with_capacity(http::MAX_HEAD_BYTES);
    let mut chunk = [0; 1024];
    loop {
        let count = chunk.len().min(http::MAX_HEAD_BYTES - data.len());
        if count == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let n = read(s, &mut chunk[..count], d).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let start = data.len().saturating_sub(3);
        data.extend_from_slice(&chunk[..n]);
        if data[start..].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(data);
        }
    }
}
pub async fn write_all(s: &mut impl Transport, mut bytes: &[u8], d: Instant) -> io::Result<()> {
    s.deadline(d)?;
    while !bytes.is_empty() {
        let n = operation(d, || s.write(bytes)).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[n..];
    }
    operation(d, || s.flush()).await
}
pub async fn connect(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let socket =
        futures_lite::future::race(async_io::Async::<TcpStream>::connect(address), async {
            async_io::Timer::after(timeout).await;
            Err(io::ErrorKind::TimedOut.into())
        })
        .await?
        .into_inner()?;
    // Requests, WebSocket frames and SSE records should not acquire a delayed
    // ACK dependency merely because the caller writes them in small chunks.
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}
