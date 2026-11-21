use super::*;
use crate::pool_locks::with_snapshot;
use rustix::net::sockopt::{set_socket_linger, set_socket_send_buffer_size, socket_cookie};
use rustix::time::{ClockId, clock_gettime};
use std::{fs, os::fd::AsRawFd, panic::catch_unwind, path::PathBuf};

#[test]
fn mutex_handoff_publishes_the_whole_health_observation() {
    let pool = Pool::new(
        "app.example",
        "/ready",
        &["127.0.0.1:1".parse().unwrap()],
        &[],
    );
    let member = &pool.members[0];
    let (start, read) = mpsc::channel();
    let (contended, proceed) = mpsc::channel();
    thread::scope(|scope| {
        let observer = scope.spawn(move || {
            read.recv_timeout(WAIT).unwrap();
            assert!(matches!(
                member.health.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            contended.send(()).unwrap();
            with_snapshot(&pool.retired, &member.health, |retired, h| {
                (*retired, h.revision, h.at, h.status)
            })
            .unwrap()
        });
        let mut h = member.health.lock().unwrap();
        start.send(()).unwrap();
        proceed.recv_timeout(WAIT).unwrap();
        // All channel handshakes precede this publication. Its visibility to
        // the observer is carried by releasing and reacquiring this mutex.
        *h = publish_health(*h, h.revision, 421, 204);
        drop(h);
        assert_eq!(observer.join().unwrap(), (false, 1, 421, 204));
    });
}

#[test]
fn callback_unwind_drops_both_guards_and_poison_skips_the_callback() {
    let generation = Mutex::new(false);
    let health = Mutex::new(204u16);
    let unwind = catch_unwind(|| with_snapshot(&generation, &health, |_, _| panic!("fixture")));
    assert!(unwind.is_err());
    assert!(matches!(
        generation.try_lock(),
        Err(TryLockError::Poisoned(_))
    ));
    assert!(matches!(health.try_lock(), Err(TryLockError::Poisoned(_))));
    assert_eq!(
        with_snapshot(&generation, &health, |_, _| unreachable!()),
        None::<()>
    );
    let live = Mutex::new(false);
    assert_eq!(
        with_snapshot(&live, &health, |_, _| unreachable!()),
        None::<()>
    );
    assert!(live.try_lock().is_ok());
}

#[test]
fn reset_after_partial_write_preserves_errno_and_spends_the_grant() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new("app.example", "/ready", &[addr], &[]);
    assert!(probe(&pool, &listener, 204));
    let mut client = TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    set_socket_send_buffer_size(&client, 32768).unwrap();
    let cookie = socket_cookie(&client).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    set_socket_linger(&peer, Some(Duration::ZERO)).unwrap();
    let bytes = vec![0x45; 4 << 20];
    let deadline = Instant::now() + WAIT;
    let mut sent = false;
    let first = futures_lite::future::block_on(pool.write_first(
        0,
        &mut client,
        &bytes,
        deadline,
        &mut sent,
    ))
    .unwrap()
    .unwrap();
    assert!(sent && first > 0 && first < bytes.len());
    let mut received = [0; 128];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, [0x45; 128]);
    drop(peer);
    let error = futures_lite::future::block_on(async_http::write_all_from(
        &mut client,
        &bytes,
        first,
        deadline,
    ))
    .unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    ));
    assert_eq!(socket_cookie(&client).unwrap(), cookie);
    assert_eq!(
        futures_lite::future::block_on(pool.start(0, deadline, WAIT, &bytes, &mut sent))
            .unwrap_err()
            .0,
        503
    );
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    println!(
        "RESET first={first} offered={} errno={} same_cookie=true alternate_dials=0",
        bytes.len(),
        error.raw_os_error().unwrap()
    );
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(
        std::env::var_os("PATHWARD_POOL_LAB").expect("requires the isolated guest driver"),
    )
}

fn nanos(clock: ClockId) -> u128 {
    let t = clock_gettime(clock);
    t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
}

// Compare production reads with the kernel's boot and active time in the same guest.
fn sample(pool: &Pool) -> (u128, u128, u128, u128) {
    let lo = nanos(ClockId::Boottime);
    let tick = u128::from(pool.now());
    let hi = nanos(ClockId::Boottime);
    assert!((lo..=hi).contains(&tick));
    (lo, tick, hi, nanos(ClockId::Monotonic))
}

fn wait_for_resume() {
    let dir = fixture_dir();
    fs::write(dir.join("sampled"), b"ready").unwrap();
    wait_for_signal("resumed");
}

fn wait_for_signal(name: &str) {
    let path = fixture_dir().join(name);
    let limit = Instant::now() + WAIT;
    while !path.exists() {
        assert!(Instant::now() < limit);
        thread::sleep(Duration::from_millis(5));
    }
}

fn suspend_and_measure(pool: &Pool) {
    let h = *pool.members[0].health.lock().unwrap();
    let before = sample(pool);
    assert!(fresh_health(h, u64::try_from(before.1).unwrap()));
    wait_for_resume();
    let after = sample(pool);
    let tick = after.1 - before.1;
    let lower = after.0 - before.2;
    let upper = after.2 - before.0;
    let active = after.3 - before.3;
    assert!((lower..=upper).contains(&tick));
    assert!(lower > active + 5_000_000_000);
    assert!(!fresh_health(h, u64::try_from(after.1).unwrap()));
    println!(
        "SUSPEND boot_lower_ns={lower} pool_ns={tick} boot_upper_ns={upper} active_ns={active}"
    );
}

fn dispatch(pool: &Pool) -> (Result<(TcpStream, usize), http::Rejection>, bool) {
    let mut sent = false;
    let result =
        futures_lite::future::block_on(pool.start(0, Instant::now() + WAIT, WAIT, HEAD, &mut sent));
    (result, sent)
}

#[test]
#[ignore = "guest administrator closes or removes the production fence"]
fn unhealthy_fence_rejects_even_a_fresh_member() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pool = Pool::new(
        "app.example",
        "/ready",
        &[listener.local_addr().unwrap()],
        &[],
    );
    assert!(probe(&pool, &listener, 204));
    let (result, sent) = dispatch(&pool);
    assert_eq!((result.unwrap_err().0, sent), (503, false));
    listener.set_nonblocking(true).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
#[ignore = "guest supervisor suspends and resumes this process"]
fn suspended_pool_samples_expire_and_require_a_successful_recheck() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pool = Pool::new(
        "app.example",
        "/ready",
        &[listener.local_addr().unwrap()],
        &[],
    );
    assert!(probe(&pool, &listener, 204));

    // Park a connected dispatch and a second pool's already parsed 204 across sleep.
    let (pause, connected, release_socket) = rendezvous();
    let first = AtomicBool::new(true);
    assert!(
        pool.at_write
            .set(Box::new(move |point| {
                if point == WritePoint::Connected && first.swap(false, Ordering::Relaxed) {
                    pause();
                }
            }))
            .is_ok()
    );
    let delayed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let delayed = Pool::new(
        "other.example",
        "/ready",
        &[delayed_listener.local_addr().unwrap()],
        &[],
    );
    let (parsed, release_probe) = pause_on(&delayed, WritePoint::ProbeResponse(204));
    thread::scope(|s| {
        let request = s.spawn(|| dispatch(&pool));
        connected.recv_timeout(WAIT).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(WAIT)).unwrap();
        let old_probe = s.spawn(|| probe(&delayed, &delayed_listener, 204));
        parsed.recv_timeout(WAIT).unwrap();
        suspend_and_measure(&pool);
        release_socket.send(()).unwrap();
        release_probe.send(()).unwrap();
        let (result, sent) = request.join().unwrap();
        assert_eq!((result.unwrap_err().0, sent), (503, false));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert!(!old_probe.join().unwrap());
        assert_eq!(delayed.members[0].health.lock().unwrap().revision, 0);
    });
    thread::scope(|s| {
        let failed = s.spawn(|| dispatch(&pool));
        let mut health = accept_probe(&listener);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        health
            .write_all(b"HTTP/1.1 503 Down\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let (result, sent) = failed.join().unwrap();
        assert_eq!((result.unwrap_err().0, sent), (503, false));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        listener.set_nonblocking(false).unwrap();
    });
    assert_eq!(pool.members[0].health.lock().unwrap().status, 503);
    wait_for_expiry(&pool);
    thread::scope(|s| {
        let recovered = s.spawn(|| dispatch(&pool));
        accept_probe(&listener)
            .write_all(b"HTTP/1.1 204 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let (result, sent) = recovered.join().unwrap();
        let (mut socket, accepted) = result.unwrap();
        assert!(sent && accepted > 0);
        futures_lite::future::block_on(async_http::write_all_from(
            &mut socket,
            HEAD,
            accepted,
            Instant::now() + WAIT,
        ))
        .unwrap();
        drop(socket);
        let mut bytes = Vec::new();
        listener
            .accept()
            .unwrap()
            .0
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, HEAD);
    });
    println!(
        "RESUME expired_request_bytes=0 delayed_204_published=false failed_recheck_dials=0 recovered_requests=1"
    );
}

#[test]
#[ignore = "guest supervisor requests managed sleep after the final clock sample"]
fn sleep_contends_with_the_sampled_first_write() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pool = Pool::new(
        "app.example",
        "/ready",
        &[listener.local_addr().unwrap()],
        &[],
    );
    assert!(probe(&pool, &listener, 204));
    let health = *pool.members[0].health.lock().unwrap();
    let (timestamp, sampled) = mpsc::channel();
    let (pause, parked, resume_writer) = rendezvous();
    let (hold_lease, written, release_lease) = rendezvous();
    let first = AtomicBool::new(true);
    assert!(
        pool.at_write
            .set(Box::new(move |point| {
                match point {
                    WritePoint::ClockSampled(tick) if first.swap(false, Ordering::Relaxed) => {
                        timestamp.send(tick).unwrap();
                        pause();
                    }
                    WritePoint::Written => hold_lease(),
                    _ => {}
                }
            }))
            .is_ok()
    );
    thread::scope(|s| {
        let request = s.spawn(|| dispatch(&pool));
        let tick = sampled.recv_timeout(WAIT).unwrap();
        parked.recv_timeout(WAIT).unwrap();
        assert!(fresh_health(health, tick));
        let (mut peer, _) = listener.accept().unwrap();
        let cookie = socket_cookie(&peer).unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        fs::write(fixture_dir().join("sampled"), b"ready").unwrap();
        wait_for_signal("contended");
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(WAIT)).unwrap();
        resume_writer.send(()).unwrap();
        written.recv_timeout(WAIT).unwrap();
        let mut received = vec![0; HEAD.len()];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, HEAD);
        let at_peer = pool.now();
        assert!(fresh_health(health, at_peer));
        // Only now can the waiting power manager acquire its exclusive lock.
        release_lease.send(()).unwrap();
        let (result, sent) = request.join().unwrap();
        let (socket, accepted) = result.unwrap();
        assert!(sent && accepted == received.len());
        drop(socket);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        wait_for_signal("resumed");
        let later = pool.now();
        assert!(later != u64::MAX && later - tick >= 5_000_000_000);
        assert!(!fresh_health(health, later));
        assert_eq!(socket_cookie(&peer).unwrap(), cookie);
        let mut next = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        next.set_nonblocking(true).unwrap();
        let (mut second_peer, _) = listener.accept().unwrap();
        let mut spent = false;
        let denied = futures_lite::future::block_on(pool.write_first(
            0,
            &mut next,
            HEAD,
            Instant::now() + WAIT,
            &mut spent,
        ))
        .unwrap();
        assert_eq!((denied, spent), (None, false));
        drop(next);
        assert_eq!(second_peer.read(&mut [0]).unwrap(), 0);
        println!(
            "FENCED_SAMPLE age_at_read_ns={} age_at_peer_ns={} age_after_resume_ns={} peer_bytes_before_sleep={accepted} expired_peer_bytes_after_resume=0",
            tick - health.at,
            at_peer - health.at,
            later - health.at
        );
    });
}

#[test]
#[ignore = "guest supervisor stops and resumes a thread in a blocking send"]
fn interrupted_send_preserves_the_same_socket_and_unsent_byte() {
    let dir = fixture_dir();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    let cookie = socket_cookie(&socket).unwrap();
    set_socket_send_buffer_size(&socket, 32768).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut filled = 0;
    let mut last = Instant::now();
    while last.elapsed() < Duration::from_millis(250) {
        match async_http::write_report(socket.write(&[0x76; 16384])).unwrap() {
            Some(n) => {
                assert!(n > 0);
                filled += n;
                assert!(filled < 32 << 20);
                last = Instant::now();
            }
            None => thread::sleep(Duration::from_millis(2)),
        }
    }
    // A timed blocking send makes EINTR observable with STOP/CONT on Linux.
    socket.set_nonblocking(false).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    let thread_path = fs::read_link("/proc/thread-self").unwrap();
    let tid = thread_path.file_name().unwrap().to_str().unwrap();
    fs::write(
        dir.join("sending.tmp"),
        format!("{tid} {}\n", socket.as_raw_fd()),
    )
    .unwrap();
    fs::rename(dir.join("sending.tmp"), dir.join("sending")).unwrap();
    let error = socket.write(b"!").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    let errno = error.raw_os_error().unwrap();
    let (first, cause) = first_write_report(async_http::write_report(Err(error)));
    assert_eq!(first, FirstIo::Wait);
    assert!(cause.is_none());
    socket.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(WAIT)).unwrap();
    thread::scope(|scope| {
        let reader = scope.spawn(move || {
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).unwrap();
            bytes
        });
        futures_lite::future::block_on(async_http::write_all(
            &mut socket,
            b"!",
            Instant::now() + WAIT,
        ))
        .unwrap();
        assert_eq!(socket_cookie(&socket).unwrap(), cookie);
        drop(socket);
        let bytes = reader.join().unwrap();
        assert_eq!(bytes.len(), filled + 1);
        assert!(bytes[..filled].iter().all(|b| *b == 0x76));
        assert_eq!(bytes[filled], b'!');
    });
    println!("INTERRUPT prefill={filled} errno={errno} same_cookie=true marker_bytes=1");
}
