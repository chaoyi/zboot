#!/bin/sh
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mkdir -p /proc /sys /dev /run /fixtures /evidence
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mount -t tmpfs -o mode=0755 tmpfs /run
echo NATIVE_READERS_GUEST_START
for module in virtio_pci virtio_blk 9pnet_virtio 9p zfs; do
    modprobe "$module" || { echo "module failed: $module"; poweroff -f; }
done
mount -t 9p -o trans=virtio,version=9p2000.L,ro fixtures /fixtures || poweroff -f
mount -t 9p -o trans=virtio,version=9p2000.L evidence /evidence || poweroff -f
run_proof() {
    set -e
    for name in sleep uname cat mkdir chown chmod id setsid flock touch cmp find stat sort timeout cp cut awk grep readlink rm ln wc; do
        test -e "/usr/bin/$name" || /bin/busybox ln -s /bin/busybox "/usr/bin/$name"
    done
    mkdir -p /sys/fs/cgroup /etc /home/test /proof /tmp /dev/pts
    mount -t devpts -o mode=0620,ptmxmode=0666 devpts /dev/pts
    chmod 1777 /tmp
    mount -t cgroup2 none /sys/fs/cgroup
    chmod 0755 / /run /sys /sys/fs /sys/fs/cgroup /proof
    printf 'ee401eaa5dc94fdf9a739a6bcfd87a81\n' >/etc/machine-id
    printf 'root:x:0:0:root:/root:/bin/sh\ntest:x:1000:1000:Native proof reader:/home/test:/bin/sh\n' >/etc/passwd
    printf 'root:x:0:\ntest:x:1000:test\nreader-extra:x:1001:test\n' >/etc/group
    printf 'passwd: files\ngroup: files\nshadow: files\n' >/etc/nsswitch.conf
    chown 1000:1000 /home/test
    /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never
    udevadm trigger --type=devices --action=add
    udevadm settle
    test -b /dev/vda
    test ! -b /dev/vdb
    test ! -b /dev/sda
    test "$(cat /sys/class/block/vda/size)" = 4194304
    test -z "$(zpool list -H -o name 2>/dev/null)"
    cp /fixtures/zsnap /usr/bin/zsnap
    chmod 0755 /usr/bin/zsnap
    cp /fixtures/fault-zfs.sh /usr/bin/zfs
    chmod 0755 /usr/bin/zfs
    /bin/busybox ln -sf /sbin/zfs /usr/sbin/zfs
    /bin/busybox ln -sf /sbin/zpool /usr/sbin/zpool
    zpool create -f -o cachefile=none -O mountpoint=none readerproof /dev/vda
    zfs create -o mountpoint=/proof/state readerproof/state
    zfs create -o mountpoint=/proof/data readerproof/data
    zfs create -o mountpoint=/proof/other readerproof/other
    zfs create -o mountpoint=/proof/data/child readerproof/data/child
    zfs create -o mountpoint=/proof/control readerproof/control
    chmod 0755 /proof/state
    chmod 0777 /proof/control
    printf 'first-content\n' >/proof/data/token
    printf 'other-content\n' >/proof/other/token
    printf 'child-content\n' >/proof/data/child/token
    chown 1000:1000 /proof/data/token /proof/other/token
    zfs snapshot readerproof/data@first
    printf 'second-content\n' >/proof/data/token
    zfs snapshot readerproof/data@second
    zfs snapshot readerproof/other@first
    uname -a >/evidence/guest-runtime.txt
    zfs version >>/evidence/guest-runtime.txt
    /fixtures/python3 /fixtures/cases.py
    zpool status -P readerproof >/evidence/pool-status.txt
    zpool export readerproof
}
(run_proof) >"/evidence/guest.log" 2>&1
result=$?
printf '%s\n' "$result" >"/evidence/exit-code"
cat /proc/self/mountinfo >"/evidence/terminal-mountinfo.txt"
for group in /sys/fs/cgroup/zsnap-protect/*; do
    if [ -d "$group" ]; then
        printf '%s\n' "$group"
        cat "$group/cgroup.procs" "$group/cgroup.type" "$group/cgroup.events" "$group/cgroup.stat"
    fi
done >"/evidence/terminal-cgroups.txt" 2>&1
/sbin/zfs list -H -p -r -t filesystem,snapshot -o name,type,guid,createtxg,objsetid readerproof >"/evidence/terminal-inventory.tsv" 2>/dev/null || :
if [ -d /proof/state/jobs ]; then
    /bin/busybox cp -a /proof/state/jobs "/evidence/terminal-jobs"
fi
if [ "$result" != 0 ]; then
    printf 'failed:%s\n' "$result" >/evidence/status
    cat "/evidence/guest.log"
fi
echo "NATIVE_READERS_GUEST FINISHED=$result"
sync
poweroff -f
