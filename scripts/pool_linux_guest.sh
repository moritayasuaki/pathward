#!/bin/sh
# Invoked only by the disposable pool_linux_stage.mjs guest.
set -eu
seed=/mnt/pool-lab
test "$(id -u)" = 0
test "$(cat /sys/devices/virtual/dmi/id/product_name)" = PathWardPoolLab
test "$(ls /sys/class/net)" = lo
test "$(uname -m)" = x86_64
test "$(uname -r)" = "$(cat "$seed/release")"
test "$(cat /proc/version_signature)" = "$(cat "$seed/version-signature")"
sha256sum -c "$seed/kernel.sha256"
cd "$seed"
sha256sum -c binary.sha256
install -m 0755 pool-tests /tmp/pathward-pool-tests
bin=/tmp/pathward-pool-tests
run() { setpriv --reuid=nobody --regid=nogroup --clear-groups "$@"; }
run id
uname -srvmo
cat /proc/version_signature
. "$seed/sleep-guest"
if test -f "$seed/run-s4"; then
    . "$seed/run-s4"
    exit 0
fi
run "$bin" backend_pool --test-threads=1 --nocapture

wait_file() {
    for i in $(seq 1 500); do
        test ! -s "$1" || return 0
        kill -0 "$worker" || return 1
        sleep 0.02
    done
    return 1
}

for trial in 1 2; do
    stage=$(mktemp -d)
    chown nobody:nogroup "$stage"
    export PATHWARD_POOL_LAB="$stage"
    before=$(cat /sys/power/suspend_stats/success)
    echo deep > /sys/power/mem_sleep
    cat /sys/power/mem_sleep
    sleep_workers
    rtcwake --utc -m no -s 12
    if test "$trial" = 1; then contended_sleep kernel-mem; else contended_sleep systemd-suspend; fi
    after=$(cat /sys/power/suspend_stats/success)
    test "$after" -eq "$((before + 1))"
    resume_workers
    echo "S3 trial=$trial kernel_success_before=$before kernel_success_after=$after"

    setpriv --reuid=nobody --regid=nogroup --clear-groups "$bin" interrupted_send_preserves --ignored --test-threads=1 --nocapture &
    worker=$!
    wait_file "$stage/sending"
    read -r tid fd < "$stage/sending"
    # Match this child thread and its specific socket fd before delivering STOP.
    task=/proc/$worker/task/$tid
    matched=false
    for i in $(seq 1 500); do
        if read -r nr arg rest < "$task/syscall" && { test "$nr" = 44 || test "$nr" = 1; } && test "$((arg))" = "$fd"; then
            matched=true
            break
        fi
        sleep 0.02
    done
    test "$matched" = true
    kill -STOP "$worker"
    for i in $(seq 1 200); do
        grep -q '^State:.*T (stopped)' "$task/status" && break
        sleep 0.01
    done
    grep -q '^State:.*T (stopped)' "$task/status"
    kill -CONT "$worker"
    wait "$worker"
    echo "SIGNAL trial=$trial observed_blocked_syscall=$nr fd=$fd"
done
echo POOL_LINUX_REFINEMENT_PASSED
