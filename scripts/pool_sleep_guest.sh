# Sourced only by the pinned, root-owned, NIC-less disposable guest driver.
fence=/run/pathward-sleep.gate
coordinator=/usr/local/libexec/pathward-server
prefix=backend_pool::io_tests::platform::linux::
install -Dm0755 "$seed/pathward-server" "$coordinator"
for mode in suspend hibernate hybrid-sleep suspend-then-hibernate; do
    install -Dm0644 "$seed/sleep.conf" "/etc/systemd/system/systemd-$mode.service.d/50-pathward.conf"
done
systemctl daemon-reload
for mode in suspend hibernate hybrid-sleep suspend-then-hibernate; do
    systemctl show "systemd-$mode.service" -p ExecStart --value | grep -Fq "$coordinator coordinated-sleep systemd-$mode"
done
sed 's/ root pathward / root nogroup /' "$seed/sleep.tmpfiles" > /run/pathward-lab-tmpfiles.conf
closed_test() {
    run "$bin" "${prefix}unhealthy_fence_rejects_even_a_fresh_member" --ignored --exact --test-threads=1
}
test ! -e "$fence"
closed_test
systemd-tmpfiles --create /run/pathward-lab-tmpfiles.conf
test "$(cat "$fence")" = A
inode=$(stat -c %i "$fence")
for invalid in S AA ''; do
    printf %s "$invalid" > "$fence"
    systemd-tmpfiles --create /run/pathward-lab-tmpfiles.conf
    test "$(cat "$fence")" = "$invalid"
    closed_test
    # An orphaned S cannot be reopened by a subsequent supervisor.
    if "$coordinator" coordinated-sleep kernel-mem; then exit 1; fi
done
printf A > "$fence"
chmod 0666 "$fence"
closed_test
chmod 0640 "$fence"
(
    flock -x 9
    closed_test
) 9<"$fence"
test "$(stat -c %i "$fence")" = "$inode"
echo 'FENCE_FAILURES missing=denied closed=denied malformed=denied writable=denied exclusive=denied tmpfiles_preserved=true'

# In a private mount namespace substitute a waiting child for systemd-sleep.
# Kill the real supervisor while the child still exists and the marker is S.
stub=$(mktemp)
cat > "$stub" <<'STUB'
#!/bin/sh
echo "$$" > /run/pathward-lab-sleeper.pid
exec /bin/sleep 60
STUB
chmod 0700 "$stub"
unshare --mount --propagation private /bin/sh -eu -c '
    mount --bind "$1" /usr/lib/systemd/systemd-sleep
    exec "$2" coordinated-sleep systemd-suspend
' sh "$stub" "$coordinator" &
supervisor=$!
for _ in $(seq 1 300); do
    test ! -s /run/pathward-lab-sleeper.pid || break
    kill -0 "$supervisor"
    sleep 0.02
done
child=$(cat /run/pathward-lab-sleeper.pid)
test "$(readlink "/proc/$supervisor/exe")" = "$coordinator"
test "$(cat "$fence")" = S
kill -KILL "$supervisor"
if wait "$supervisor"; then exit 1; fi
kill -0 "$child"
closed_test
if "$coordinator" coordinated-sleep kernel-mem; then exit 1; fi
test "$(cat "$fence")" = S
kill "$child"
# No real power transition was started by the fixture.
printf A > "$fence"
echo 'ORPHAN_FENCE supervisor_killed=true child_alive=true peer_bytes=0 second_supervisor=denied'

sleep_workers() {
    pre=$(mktemp -d)
    post=$(mktemp -d)
    chown nobody:nogroup "$pre" "$post"
    PATHWARD_POOL_LAB="$pre" run "$bin" "${prefix}suspended_pool_samples_expire_and_require_a_successful_recheck" --ignored --exact --test-threads=1 --nocapture &
    pre_pid=$!
    PATHWARD_POOL_LAB="$post" run "$bin" "${prefix}sleep_contends_with_the_sampled_first_write" --ignored --exact --test-threads=1 --nocapture &
    post_pid=$!
    for dir in "$pre" "$post"; do
        for _ in $(seq 1 650); do
            test ! -s "$dir/sampled" || break
            kill -0 "$pre_pid" "$post_pid"
            sleep 0.02
        done
        test -s "$dir/sampled"
    done
}

# Wait for an actual failed LOCK_EX|LOCK_NB on the sampled writer's inode.
# Only then let the peer acknowledge the bytes and the writer release its lease.
contended_sleep() {
    entry=$1
    log=$(mktemp)
    evidence=$log
    case "$entry" in
        kernel-*) "$coordinator" coordinated-sleep "$entry" 2>"$log" & ;;
        systemd-*) evidence=$log.journal; systemctl start "$entry.service" >"$log" 2>&1 & ;;
        *) return 1 ;;
    esac
    power_pid=$!
    for _ in $(seq 1 500); do
        if test "${entry#systemd-}" != "$entry"; then
            invocation=$(systemctl show "$entry.service" -p InvocationID --value)
            if test -n "$invocation"; then
                journalctl -b "_SYSTEMD_INVOCATION_ID=$invocation" -o cat --no-pager > "$evidence"
            fi
        fi
        if test -s "$evidence" && grep -Fq 'Waiting for the PathWard sleep fence' "$evidence"; then break; fi
        kill -0 "$power_pid" || { cat "$log"; return 1; }
        sleep 0.02
    done
    grep -Fq 'Waiting for the PathWard sleep fence' "$evidence"
    touch "$post/contended"
    wait "$power_pid" || { cat "$log"; journalctl -b -u "$entry.service" -n 20 --no-pager; return 1; }
    test "$(cat "$fence")" = A
    echo "POWER_FENCE entry=$entry exclusive_contended=true reopened=true"
}

resume_workers() {
    kill -0 "$pre_pid" "$post_pid"
    touch "$pre/resumed" "$post/resumed"
    wait "$pre_pid"
    wait "$post_pid"
}
