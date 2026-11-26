# Actual background Menu imports and inherited writer-lock custody. The only
# interposition is an exact, one-shot read-only import of this case's slow GUID.
MD_DIR=/run/menu-discovery-native
MD_MENU_PID= MD_SNAPSHOT_PID= MD_SLOW_PID= MD_REAL= MD_ZPOOL=

md_now() { busybox awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime; }
md_starttime() { busybox awk '{print $22}' "/proc/$1/stat" 2>/dev/null; }
md_kill_owned() {
    [ -n "$1" ] && [ -n "$2" ] || return 0
    [ "$(md_starttime "$1")" = "$2" ] || return 0
    kill -KILL "$1" 2>/dev/null || :
}
md_restore() {
    if [ -n "$MD_REAL" ] && [ -f "$MD_REAL" ]; then
        mv "$MD_REAL" "$MD_ZPOOL" || return 1
    fi
}
md_cleanup() {
    md_kill_owned "$MD_MENU_PID" "$MD_MENU_START"
    md_kill_owned "$MD_SNAPSHOT_PID" "$MD_SNAPSHOT_START"
    if [ -f "$MD_DIR/slow.pid" ]; then
        md_kill_owned "$(cat "$MD_DIR/slow.pid")" "$(cat "$MD_DIR/slow.start")"
    fi
    if [ -n "$MD_MENU_PID" ]; then
        md_collect "$MD_MENU_PID" menu "$MD_MENU_BASE" || :
        MD_MENU_PID=
    fi
    if [ -n "$MD_SNAPSHOT_PID" ]; then
        md_collect "$MD_SNAPSHOT_PID" snapshot "$MD_SNAPSHOT_BASE" || :
        MD_SNAPSHOT_PID=
    fi
    mkdir -p "$ZT_OUT/custody"
    for md_evidence in slow.pid slow.start slow.argv released.ms gate.failed started.ms listed.ms; do
        [ ! -f "$MD_DIR/$md_evidence" ] || cp "$MD_DIR/$md_evidence" "$ZT_OUT/custody/$md_evidence"
    done
    md_restore
    exec 7>&-
}
md_fail() { md_cleanup; fail "$*"; }
md_must() { step "$@" || md_fail "$1 exited $(cat "$ZT_LAST.rc")"; }
md_refuse() { if step "$@"; then md_fail "$1 unexpectedly succeeded"; fi; }
md_wait() {
    md_attempt=0
    while ! "$@"; do
        md_attempt=$((md_attempt + 1))
        [ "$md_attempt" -lt 900 ] || return 1
        busybox sleep 0.1
    done
}
md_gated() { [ -s "$MD_DIR/slow.pid" ] && [ -s "$MD_DIR/slow.start" ]; }
md_listed() {
    grep -Eq '^[0-9]+: e2efast/root$' "$MD_DIR/menu.out" &&
        grep -q "Pool e2eslow guid=$MD_SLOW_GUID  importing" "$MD_DIR/menu.out" &&
        grep -q 'zboot> ' "$MD_DIR/menu.out" &&
        [ "$(zfs get -H -o value mounted e2efast/root 2>/dev/null)" = no ] &&
        ! grep -q ' - zfs ' "/proc/$MD_MENU_PID/mountinfo"
}
md_waiting() { grep -q 'waiting for the ZFS writer lock' "$MD_DIR/snapshot.err"; }
md_dead() { [ ! -d "/proc/$1" ]; }
md_facts() {
    cat "/proc/$1/stat" "/proc/$1/status" || return 1
    printf '\nCOMMAND\n'
    tr '\000' '\n' < "/proc/$1/cmdline" || return 1
    printf '\nEXECUTABLE\n'
    readlink "/proc/$1/exe" || return 1
    for md_fd in /proc/"$1"/fd/*; do
        printf '\nFD %s ' "${md_fd##*/}"
        readlink "$md_fd" || continue
        cat "/proc/$1/fdinfo/${md_fd##*/}" || :
    done
    printf '\nMOUNTS\n'
    cat "/proc/$1/mountinfo" || return 1
}
# Standard step records for a real background command; logs stay private in RAM
# until explicit checkpoints and final collection. The shell owns/reaps $!.
md_spawn() {
    md_name=$1 md_input=$2; shift 2
    ZT_N=$((ZT_N + 1))
    MD_BASE=$(printf '%s/%02d-%s' "$ZT_OUT" "$ZT_N" "$md_name")
    printf '%s\n' "$@" > "$MD_BASE.argv"
    "$@" < "$md_input" > "$MD_DIR/$md_name.out" 2> "$MD_DIR/$md_name.err" &
    MD_PID=$!
    printf '%s\n' "$MD_PID" > "$MD_BASE.pid"
}
md_collect() {
    md_pid=$1 md_name=$2 md_base=$3
    wait "$md_pid"; md_rc=$?
    cp "$MD_DIR/$md_name.out" "$md_base.out"
    cp "$MD_DIR/$md_name.err" "$md_base.err"
    printf '%s\n' "$md_rc" > "$md_base.rc"
    return "$md_rc"
}
md_install() {
    MD_ZPOOL=$(readlink -f /sbin/zpool) || return 1
    MD_REAL=$MD_ZPOOL.menu-discovery-native-real
    [ -f "$MD_ZPOOL" ] && [ ! -e "$MD_REAL" ] || return 1
    cp -p "$MD_ZPOOL" "$MD_REAL" || return 1
    printf '%s\n' "$MD_REAL" > "$MD_DIR/real.path"
    cat > "$MD_ZPOOL" <<'WRAPPER'
#!/bin/sh
md_dir=/run/menu-discovery-native
md_real=$(/bin/busybox cat "$md_dir/real.path")
md_guid=$(/bin/busybox cat "$md_dir/slow.guid")
if [ "$#" -eq 7 ] && [ "$1" = import ] && [ "$2" = -N ] &&
    [ "$3" = -o ] && [ "$4" = readonly=on ] && [ "$5" = -o ] &&
    [ "$6" = cachefile=none ] && [ "$7" = "$md_guid" ] &&
    /bin/busybox mkdir "$md_dir/fired" 2>/dev/null; then
    printf '%s\n' /sbin/zpool "$@" > "$md_dir/slow.argv"
    /bin/busybox awk '{print $22}' "/proc/$$/stat" > "$md_dir/slow.start"
    printf '%s\n' "$$" > "$md_dir/slow.pid"
    md_i=0
    while [ ! -e "$md_dir/release" ]; do
        md_i=$((md_i + 1))
        if [ "$md_i" -ge 1800 ]; then
            printf '%s\n' timed-out > "$md_dir/gate.failed"
            exit 98
        fi
        /bin/busybox sleep 0.1
    done
    /bin/busybox awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime > "$md_dir/released.ms"
fi
exec "$md_real" "$@"
WRAPPER
    chmod 0755 "$MD_ZPOOL"
}

stage_1() {
    umask 077
    md_must private mkdir -m 0700 "$MD_DIR"
    trap 'md_cleanup' EXIT HUP INT TERM
    fixture_hostid
    md_must versions sh -c 'uname -a; zfs version; cat /sys/module/zfs/version'
    for md_pair in e2efast:A e2eslow:B; do
        md_pool=${md_pair%:*} md_disk=$(disk "${md_pair#*:}")
        md_must "partition-$md_pool" sgdisk -n 1:0:0 -t 1:BF01 "$md_disk"
        md_must "probe-$md_pool" partprobe "$md_disk"
        mdev -s
        md_must "create-$md_pool" zpool create -f -o cachefile=none -O mountpoint=none -O canmount=off "$md_pool" "${md_disk}1"
        md_must "root-$md_pool" zfs create -o mountpoint=/ -o canmount=noauto "$md_pool/root"
        md_must "mountpoint-$md_pool" mkdir "$MD_DIR/$md_pool"
        md_must "mount-$md_pool" mount -t zfs -o zfsutil "$md_pool/root" "$MD_DIR/$md_pool"
        md_must "assets-$md_pool" sh -e -c 'mkdir "$1/boot"; printf "kernel-pair-evidence\n" > "$1/boot/vmlinuz-proof"; printf "initrd-pair-evidence\n" > "$1/boot/initrd.img-proof"; ln -s boot/vmlinuz-proof "$1/vmlinuz"; ln -s boot/initrd.img-proof "$1/initrd.img"; sha256sum "$1/boot/"*' assets "$MD_DIR/$md_pool"
        md_must "unmount-$md_pool" umount "$MD_DIR/$md_pool"
        md_must "guid-$md_pool" zpool get -H -p -o value guid "$md_pool"
        md_must "topology-$md_pool" zpool status -j -P "$md_pool"
    done
    MD_SLOW_GUID=$(zpool get -H -p -o value guid e2eslow)
    printf '%s\n' "$MD_SLOW_GUID" > "$MD_DIR/slow.guid"
    observe created
    md_must export-fast zpool export e2efast
    md_must export-slow zpool export e2eslow
    md_must writer-directory mkdir -p /run/zfs-tools
    md_must writer-initial-free flock -n /run/zfs-tools/writer.lock /bin/busybox true
    md_must writer-inode-before busybox stat -c %i /run/zfs-tools/writer.lock
    md_must native-before sha256sum /sbin/zpool
    md_must install-wrapper md_install
    md_must menu-fifo mkfifo "$MD_DIR/menu.stdin"
    exec 7<> "$MD_DIR/menu.stdin"
    md_now > "$MD_DIR/started.ms"
    md_spawn menu "$MD_DIR/menu.stdin" zboot menu --no-autoboot
    MD_MENU_PID=$MD_PID MD_MENU_BASE=$MD_BASE
    MD_MENU_START=$(md_starttime "$MD_MENU_PID")
    md_must slow-entered md_wait md_gated
    MD_SLOW_PID=$(cat "$MD_DIR/slow.pid")
    md_must slow-identity cat "$MD_DIR/slow.pid" "$MD_DIR/slow.start"
    md_must fast-listed md_wait md_listed
    md_now > "$MD_DIR/listed.ms"
    md_must listing-before-release cat "$MD_DIR/menu.out"
    md_must slow-import-argv cat "$MD_DIR/slow.argv"
    md_must menu-process md_facts "$MD_MENU_PID"
    md_must slow-before-death md_facts "$MD_SLOW_PID"
    md_refuse writer-held-before-death flock -n /run/zfs-tools/writer.lock /bin/busybox true
    observe blocked
    md_refuse proof-absent-before zfs list -H -p -t snapshot -o name,guid e2efast/root@proof

    md_spawn snapshot /dev/null zboot snapshot e2efast/root@proof --json
    MD_SNAPSHOT_PID=$MD_PID MD_SNAPSHOT_BASE=$MD_BASE
    MD_SNAPSHOT_START=$(md_starttime "$MD_SNAPSHOT_PID")
    md_must foreground-waiting md_wait md_waiting
    md_must foreground-before-death md_facts "$MD_SNAPSHOT_PID"
    md_must waiting-before-death cat "$MD_DIR/snapshot.err"
    md_must kill-menu kill -KILL "$MD_MENU_PID"
    md_collect "$MD_MENU_PID" menu "$MD_MENU_BASE"; md_menu_rc=$?
    MD_MENU_PID=
    [ "$md_menu_rc" -eq 137 ] || md_fail "Menu did not end by the recorded SIGKILL"
    md_must menu-gone busybox test ! -d "/proc/$(cat "$MD_MENU_BASE.pid")"
    md_must slow-after-death md_facts "$MD_SLOW_PID"
    md_must foreground-after-death md_facts "$MD_SNAPSHOT_PID"
    md_refuse writer-held-after-death flock -n /run/zfs-tools/writer.lock /bin/busybox true
    md_must writer-inode-after busybox stat -c %i /run/zfs-tools/writer.lock
    md_refuse proof-absent-after-death zfs list -H -p -t snapshot -o name,guid e2efast/root@proof
    observe parent-dead
    md_refuse premature-release busybox test -e "$MD_DIR/released.ms"
    md_refuse gate-timeout busybox test -e "$MD_DIR/gate.failed"

    md_must release-gate touch "$MD_DIR/release"
    # The ordinary foreground command has its own native writer-lock timeout;
    # case/VM SECONDS is the outer bound. A timeout never becomes a PASS.
    md_collect "$MD_SNAPSHOT_PID" snapshot "$MD_SNAPSHOT_BASE" || md_fail 'foreground snapshot failed'
    MD_SNAPSHOT_PID=
    md_must slow-child-gone md_wait md_dead "$MD_SLOW_PID"
    md_refuse gate-timeout-final busybox test -e "$MD_DIR/gate.failed"
    md_must release-time cat "$MD_DIR/released.ms"
    md_must timing sh -c 'printf "started "; cat "$1/started.ms"; printf "listed "; cat "$1/listed.ms"; printf "released "; cat "$1/released.ms"' timing "$MD_DIR"
    md_must restore-native md_restore
    md_must native-after sha256sum /sbin/zpool
    md_must writer-final-free flock -n /run/zfs-tools/writer.lock /bin/busybox true
    observe completed
    md_must proof-native zfs list -H -p -t snapshot -o name,guid e2efast/root@proof
    md_must readonly-native zpool get -H -p -o name,property,value guid,readonly e2efast e2eslow
    md_must mounted-native zfs get -H -o name,value mounted e2efast/root e2eslow/root
    md_must export-fast-final zpool export e2efast
    md_must export-slow-final zpool export e2eslow
    observe cleaned
    md_cleanup
    trap - EXIT HUP INT TERM
}
