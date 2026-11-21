#!/bin/sh
# Runs only on the fresh, pinned, NIC-less lab guest, with an extra disposable swap disk.
set -eu
test "$(id -u)" = 0
test "$(cat /sys/devices/virtual/dmi/id/product_name)" = PathWardPoolLab
test "$(ls /sys/class/net)" = lo
test "$(cat /sys/class/block/vdb/serial)" = PathWardS4Swap
test "$(getconf PAGESIZE)" = 4096
grep -qw disk /sys/power/state
grep -qw platform /sys/power/disk
test -z "$(lsblk -nro FSTYPE /dev/vdb)"
mkswap -L PathWardS4 /dev/vdb
swapon /dev/vdb
cat /sys/class/block/vdb/dev > /sys/power/resume
echo platform > /sys/power/disk
grep -F '[platform]' /sys/power/disk
# The pinned kernel has built-in virtio block and early software resume.
# Boot it from the private overlay with no mountable root on a failed restore.
kernel=/boot/vmlinuz-$(uname -r)
boot_uuid=$(findmnt -n -o UUID -T "$kernel")
test -n "$boot_uuid"
case "$(findmnt -n -o TARGET -T "$kernel")" in
    /boot) kernel_path=/vmlinuz-$(uname -r) ;;
    /) kernel_path=$kernel ;;
    *) exit 1 ;;
esac
mkswap --version
cat > /boot/grub/grub.cfg <<GRUB
set default=0
set timeout=0
menuentry 'PathWard S4 restore' {
    search --no-floppy --fs-uuid --set=root $boot_uuid
    linux $kernel_path resume=/dev/vdb resumewait root=/dev/pathward-no-root ro console=ttyS0 panic=-1
}
GRUB
sync

boot_id=$(cat /proc/sys/kernel/random/boot_id)
for trial in 1 2; do
    sleep_workers
    printf '\nS4_HIBERNATE trial=%s\n' "$trial"
    if test "$trial" = 1; then contended_sleep kernel-disk; else contended_sleep systemd-hibernate; fi
    test "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id"
    kill -0 "$pre_pid" "$post_pid"
    echo "S4_CONTINUITY trial=$trial same_boot_id=true both_workers_alive=true"
    resume_workers
    echo "S4_RESTORED trial=$trial"
done
echo POOL_LINUX_S4_PASSED
