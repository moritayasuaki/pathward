# Local pool writes on Linux

Suppose a POST begins on replica A and its first nonblocking write accepts only part of the request head. PathWard spends the request's dispatch permission at that point. On the same connection it offers the remaining bytes. If the socket fills up, the offset stays put. Retiring A during this wait still permits this exchange to finish. If the first call had returned `WouldBlock` before accepting any bytes, retirement would instead prevent A from starting the exchange. [Rust driver](../src/upstream.rs) · [socket adapter](../server/src/backend_pool.rs) · [continuation](../server/src/async_http.rs)

| Boundary | What Lean checks | What the runtime supplies |
| --- | --- | --- |
| Generation and member health | In the lock model the writer acquires generation then health and releases in reverse order. While it owns both, any finite sequence of competing events leaves the snapshot intact. A successful first-write effect requires the owning actor, a live generation and a fresh 2xx observation. | All mutations use the same mutex instances. Acquiring excludes another guard, makes earlier protected writes visible and dropping releases the lock. A health publication in the model stands for a completed protected update. The adapter declines dispatch if either lock reports poison. [Rust mutex contract](https://doc.rust-lang.org/std/sync/struct.Mutex.html) |
| Health age | A probe result uses its start timestamp. Publication and first-write authorization both require an ordered age strictly below five seconds. An expired record leaves the writer and dispatch permission untouched. Every later authorized write has a timely 2xx in its history. | On Linux, the fallible `CLOCK_BOOTTIME` read includes suspend in the same boot. Each attempt reads it after acquiring both mutexes and a shared sleep fence. Other targets use a pool-relative `Instant`. Clock errors or out-of-range samples deny authorization. Ordinary CPU scheduling can delay the socket call. [Linux clocks](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) · [Rust Instant](https://doc.rust-lang.org/std/time/struct.Instant.html) |
| Managed S3/S4 | From the final clock read through the first local socket write, every permitted interleaving retains the reader and excludes sleep. If sleep wins first, a post-resume sample at expiry leaves the writer and its unused grant intact. Only a timely successful recheck can authorize a subsequent effect. | Independent opens of the same boot-scoped inode use Linux shared/exclusive `flock`. The manager holds exclusive ownership around the synchronous sleep operation. The kernel restores the inode, locks and boot clock on S4. [Linux flock](https://man7.org/linux/man-pages/man2/flock.2.html) · [sleep adapter](../server/src/sleep_fence.rs) |
| Nonblocking TCP | A reported positive count consumes exactly that prefix. A retryable error preserves the entire remaining slice. Zero success or an excessive count terminates the transfer. Across any finite successful sequence, accepted bytes followed by the remaining suffix equal the original buffer. A positive first count consumes the grant for every alternate writer. | A successful `write` of length `n` accepts the first `n` offered bytes in order. An error accepts zero. The adapter maps `WouldBlock` and `Interrupted` to no progress, returns other errors, and keeps exclusive use of the same connected stream. The kernel can report a short write and later refuse further progress. [Rust Write](https://doc.rust-lang.org/std/io/trait.Write.html) · [Linux write](https://man7.org/linux/man-pages/man2/write.2.html) · [Linux TCP](https://man7.org/linux/man-pages/man7/tcp.7.html) |

The byte and clock gates are extracted from production Rust. The lock and finite-transfer histories are Lean models over explicit events. Their premises are visible in the theorem statements. The [theorem registry](../proofs/registry.json) records the logical axioms for each proof. The [proof module](../proofs/PlatformProofs.lean) and [roadmap](../proofs/roadmap.json) identify the remaining verification of the Rust standard library and OS adapter.

## Isolated reproduction

Run the following in an isolated Linux environment with the project's pinned server toolchain, reviewed crate cache and sleep fence readable by the test user. The tests open only guest loopback sockets. The VM launcher provisions its own fence.

```sh
cargo +1.99.1 test --offline --locked --manifest-path server/Cargo.toml --lib backend_pool -- --test-threads=1 --nocapture
```

The partial-write fixture offers a position-dependent 16 MiB transport buffer to the same first-write and continuation functions the proxy uses. It holds the reader back until the kernel actually returns `WouldBlock`, retires the pool, then compares every received byte. The reader's socket pair is checked at both ends of the write. A separate prefill test retires the pool after the first application attempt returns `WouldBlock`; the peer compares the prefill and observes zero request bytes. The clock test orders 4,096 observations from four threads and waits for a real health sample to expire. Exact counts and the binary digest are in the [Linux run record](pool-platform-validation.json).

## Remaining guarantees

A missing clock sample at either end discards that probe. A failed application connect records a negative observation directly. If its sample is unavailable, the reserved timestamp quarantines that member for the rest of the generation. Reloading creates a cold generation with fresh probes.

The mutex contract gives no fairness bound for scheduling a waiter. The five-second threshold applies at the protected clock read. Progress after send-buffer exhaustion depends on the reader, the network and scheduling. The proof covers finite histories, including ones which stop early. Success at the socket reports local acceptance. Determining whether a remote application committed after a lost reply still requires an application receipt or an idempotency protocol. [Linux send semantics](https://man7.org/linux/man-pages/man2/send.2.html)

## Pinned Linux verification

The verification target is Rust 1.99.1, `x86_64-unknown-linux-musl`, on the Ubuntu 24.04.5 kernel `6.8.0-147.147-generic`. The pin includes the full rustc commit, twelve Rust standard library source hashes, the MIR digest, the guest image and the boot kernel digest. The guest driver checks the running kernel signature and the boot image. [Target manifest](../audit/pool-linux-target.json) · [measured results](pool-linux-refinement.json)

| Boundary | Verification and evidence |
| --- | --- |
| Guard lifetime | The production first-write path passes a synchronous callback to `with_snapshot`. CI compiles that same function to Rust's mid-level intermediate representation (MIR) with unwinding enabled. The checker follows normal and cleanup edges and emits seven distinct sequences of guard events. Lean checks every sequence. Both callback paths acquire generation then health, invoke once, drop health then generation, and finish by returning or unwinding. A Linux test makes the callback unwind, checks both mutexes for poison, and checks that a poisoned second acquisition releases its first guard. [Rust guard](../server/src/pool_locks.rs) · [emitted paths](../proofs/Generated/GuardPaths.lean) |
| Visibility | The pinned futex implementation uses acquire operations to lock and a release operation to unlock. In the Lean model, acquiring after the last completed publication observes its entire revision, timestamp and status. In the Linux test, the reader first proves contention and signals the publisher. The publisher then updates all three fields and drops the guard. The only synchronization from that publication to the read is the mutex handoff. [Atomic ordering](https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html) |
| Suspend | The guest enters ACPI S3 and wakes on its RTC. Two direct boot-clock reads bracket each production sample, with `CLOCK_MONOTONIC` as the active-time control. A connected request and a separately parsed 204 are held across sleep. After wake, the old socket receives zero bytes, the delayed result is discarded, a 503 leaves the member closed and a new 204 admits one POST. [S3 verification record](pool-suspend-ttl-validation.json) · [Linux sleep states](https://docs.kernel.org/6.8/admin-guide/pm/sleep-states.html) |
| Socket and errno | Both adapters use the same Rust error mapping. A Linux `SO_COOKIE` identifies the socket across individual continuation calls. The fixtures exercise a short nonblocking first write, backpressure, and a peer reset with local bytes outstanding. A separate fixture makes a timed, full-buffer send block on the same socket and uses STOP/CONT to obtain a real `EINTR`. It restores nonblocking mode, retries, and compares the entire stream at the peer. Lean checks that a wait retains the pending bytes, a terminal error retains its cause and suffix, and an event from a different socket is rejected by the trace model. [Linux signal interruption](https://man7.org/linux/man-pages/man7/signal.7.html) · [Rust/Linux theorems](../proofs/LinuxProofs.lean) |

The MIR reader covers the pinned guard function and projects compiler blocks onto guard events. It excludes unreachable blocks and process termination during a second panic. The Rust compiler, the meaning of MIR and library operations, the CPU memory model, kernel clocks and the TCP implementation remain trusted. The power tests exercise the pinned x86 Linux guest. Physical hardware, other kernel builds and architectures remain separate verification targets. [Assumptions and remaining work](../proofs/roadmap.json)

### Hibernation at the first-write boundary

Linux restores the hibernated process, its locked state and its connected sockets from a disk image. In the test, one request parks just before the protected clock read. Another parks just after reading a fresh timestamp under both locks, before evaluating the gate and invoking the socket writer. After power-off the host checks the `S1SUSPEND` marker on a dedicated swap disk. A fresh QEMU process boots the same kernel and runs early software resume before mounting the root filesystem. Each test continues from its original stack. The host keeps both disks intact throughout the powered-off interval. [Linux hibernation](https://docs.kernel.org/6.8/power/swsusp.html) · [S4 measurements](pool-s4-validation.json)

Before sleep coordination, the resumed clock read at the first stop point detected expiry. At the second stop point the old adapter still held its saved timestamp and sent 62 bytes after resume in both S4 trials. This provides the regression baseline. [Pre-coordination S4 measurements](pool-s4-validation.json)

With the fence installed the VM parks a writer immediately after its final clock read. The supervisor observes actual exclusive lock contention. The peer receives the request while the writer still owns the shared lock, then the guest enters sleep. On resume, a new first write using expired health delivers zero bytes. Separately, a connection parked before admission and a pre-sleep 204 both fail after resume. A 503 recheck keeps the gate closed and a new 204 permits one POST. The guest exercises both the direct coordinated kernel entry and the installed systemd unit for each power state. [Socket fixture](../server/src/pool_linux_tests.rs) · [coordinated S3 and S4 measurements](pool-sleep-fence-validation.json)

For an ordered, representable boot clock, the Lean proof gives an exact condition. An observation used to authorize an attempt stays fresh at local socket acceptance if and only if the delay since the protected read is **strictly less** than the TTL remaining at that read. A one-member pool at the exact five-second boundary demonstrates that a saved sample can authorize one byte while a fresh sample refuses the write. A retry after `WouldBlock` re-enters the gate with a new clock sample and retains its unused grant on refusal. Applying the time bound to a real syscall requires an OS guarantee on scheduling and suspend. [Linux proof module](../proofs/LinuxProofs.lean)

For an ordinary proof run, `make setup` installs the pinned target libraries and Rust source. `make proof-check` regenerates and compares the MIR paths before checking Lean. The power and signal tests run separately inside a disposable guest. On a host with Node, QEMU, xorriso, the pinned image and a working Rust/C toolchain for the musl target, use an unused output directory.

```sh
node scripts/pool_linux_stage.mjs /path/to/ubuntu-noble-20261105.img /path/to/new-lab-run
node scripts/pool_linux_stage.mjs /path/to/ubuntu-noble-20261105.img /path/to/new-hibernation-run s4
```

The launcher builds the test executable with the pinned rustc, hashes the guest image, boots a new overlay with no network device, and saves the serial transcript. Only the guest supervisor controls guest power and the test process. Socket and clock observations run as `nobody`.

## Installing the Linux sleep coordinator

On an administrator-managed systemd host, install the coordinator from the same server build. Complete the unit changes before creating the awake file or starting the new pooled server. The example uses the existing service group `pathward` and systemd's Ubuntu path `/usr/lib/systemd/systemd-sleep`. Use a root-owned executable and directories. Run the following as administrator during the initial installation with all four sleep services idle.

```sh
install -Dm0755 server/target/release/pathward-server /usr/local/libexec/pathward-server
for mode in suspend hibernate hybrid-sleep suspend-then-hibernate; do
    install -Dm0644 deploy/pathward-sleep.conf "/etc/systemd/system/systemd-$mode.service.d/50-pathward.conf"
done
systemctl daemon-reload
for mode in suspend hibernate hybrid-sleep suspend-then-hibernate; do
    systemctl show "systemd-$mode.service" -p ExecStart --value |
        grep -F "/usr/local/libexec/pathward-server coordinated-sleep systemd-$mode" || exit 1
done
install -Dm0644 deploy/pathward-sleep.tmpfiles /etc/tmpfiles.d/pathward-sleep.conf
systemd-tmpfiles --create /etc/tmpfiles.d/pathward-sleep.conf
```

The service user needs read access to the fence. Each first-write attempt opens its own descriptor, takes a nonblocking shared flock and reads the one-byte marker. It holds the descriptor through one synchronous nonblocking application write. No lease spans a probe, network wait or response. The manager takes an exclusive lock, writes `S`, calls the real sleep backend, and writes `A` only after synchronous success. The four unit overrides preserve systemd's sleep preparation and post-resume hooks. For administrators using the kernel interface directly, the matching coordinator modes are `kernel-mem` and `kernel-disk`; provision the usual kernel sleep mode, wake source and resume device beforehand. [systemd sleep services](https://www.freedesktop.org/software/systemd/man/255/systemd-suspend.service.html)

Use a local root-controlled `/run` shared by the service and the manager. Keep the same fence inode for the whole boot, including S4 restoration. A missing, malformed, orphaned or contended fence denies application bytes. A failed or killed coordinator can leave the marker at `S`; pooled routes then return 503. Inspect the journal and perform a normal cold reboot to create a fresh fence after diagnosing the failure. Re-running the supplied tmpfiles rule preserves an existing marker. [tmpfiles creation semantics](https://www.freedesktop.org/software/systemd/man/255/tmpfiles.d.html)

The operating contract requires every host sleep path to use the coordinator. Direct root writes to `/sys/power/state`, kernel autosleep, out-of-band VM pause and snapshot rollback can bypass the file lock. Containers need the host's fence and participating host power manager. The host must also supply an ordered suspend-inclusive clock, the documented flock semantics, and the same restored inode and descriptors. Time spent descheduled while the system is awake can still exceed the remaining TTL. The proof and the measurements apply at first local socket acceptance; application commit time remains a separate event. [Linux power states](https://docs.kernel.org/6.8/admin-guide/pm/sleep-states.html) · [Lean proof](../proofs/LinuxProofs.lean)
