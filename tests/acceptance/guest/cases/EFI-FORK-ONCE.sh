# Deploy the real factory root. Its systemd service arms the fork from the
# running default on the first visit and reports the actual root on every boot.
stage_1() {
    overlay=/run/fork-once-overlay
    unitdir=$overlay/rootfs/etc/systemd/system
    probe=$overlay/rootfs/usr/local/libexec/zt-fork-once
    must overlay mkdir -p "${probe%/*}" "$unitdir/multi-user.target.wants"
    cat > "$probe" <<'PROBE'
#!/bin/sh
set -eu
trap 'rc=$?; [ "$rc" = 0 ] || echo "ZT_FORK_ONCE_FAILED rc=$rc"' EXIT
source=e2ea/ROOT/proof
fork=e2ea/ROOT/try
root=$(findmnt -rn -o SOURCE --target /)
echo "ZT_ONCE root=$root"
echo "ZT_ONCE pid1=$(cat /proc/1/comm)"
echo "ZT_ONCE binary=$(sha256sum /usr/bin/zboot | cut -d' ' -f1)"
if ! zfs list -H "$fork" >/dev/null 2>&1; then
    test "$root" = "$source"
    zboot fork try --boot
    echo ZT_ONCE_ARMED
fi
echo "ZT_ONCE default=$(zpool get -H -o value bootfs e2ea)"
echo "ZT_ONCE root_guid=$(zfs get -Hp -o value guid "$root")"
echo "ZT_ONCE fork_guid=$(zfs get -Hp -o value guid "$fork")"
echo "ZT_ONCE origin=$(zfs get -H -o value origin "$fork")"
zpool sync e2ea
echo ZT_FORK_ONCE_BOOT_OK
systemctl --no-block poweroff
PROBE
    must probe-executable chmod 0755 "$probe"
    cat > "$unitdir/zt-fork-once.service" <<'UNIT'
[Unit]
Description=Disposable one-time fork boot proof
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/zt-fork-once
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
[Install]
WantedBy=multi-user.target
UNIT
    must probe-enable ln -s ../zt-fork-once.service "$unitdir/multi-user.target.wants/"
    a=$(disk A)
    set -- "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --overlay "$overlay" --pool e2ea \
        --be proof --esp 512M --hostid 0174627a --json
    must preview zboot deploy "$@" --dry-run
    token=$(json .token) || fail 'no deploy token'
    must deploy zboot deploy "$@" --confirm "$token"
    must binary sha256sum /usr/bin/zboot
}
