# DEPLOY-NATIVE: fresh whole-disk `zboot deploy` of a `zboot factory` root
# tar with a host overlay onto D, confirmed by one reviewed token; refusals
# leave D's plan and ends unchanged; the result is read back natively (GPT,
# readonly import by guid, @factory/@deployed, overlays, identity, BE contents).
POOL=e2ed BE=e2ed/ROOT/os VIEW=/mnt/zfs-e2e/deploy-proof OVERLAY=/run/e2e-overlay
WRONG=0123456789abcdef0123456789abcdef

deploy() { # NAME ESP [ARG...]: one `zboot deploy` of D
    name=$1 esp=$2; shift 2
    step "$name" zboot deploy "$d" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi --tar /fixtures/e2e-factory.tar.zst \
        --overlay "$OVERLAY" --be os --pool "$POOL" --esp "$esp" --json "$@"
}

# The host overlay: one file, and a post-install that records what it saw
# (the factory identity state and its environment) and then
# clobbers /etc/hostid, which deploy must put back.
host_overlay() {
    must overlay-mkdir mkdir -p "$OVERLAY/rootfs/etc/zboot-e2e"
    printf 'ZFS-E2E-OVERLAY\n' > "$OVERLAY/rootfs/etc/zboot-e2e/marker"
    chmod 0640 "$OVERLAY/rootfs/etc/zboot-e2e/marker"
    cat > "$OVERLAY/post-install" <<'HOOK'
#!/bin/sh
set -eu
if [ -f /etc/hostid ]; then od -An -tx1 /etc/hostid | tr -d ' \n'; else printf absent; fi > /etc/zboot-e2e/hostid-seen
printf '%s %s %s\n' "$ZBOOT_HOSTID" "$ZBOOT_POOL" "$ZBOOT_BE" > /etc/zboot-e2e/env
if [ -x /usr/sbin/sshd ]; then test -f /etc/systemd/system/zboot-ssh-keygen.service; else test ! -e /etc/systemd/system/zboot-ssh-keygen.service; fi
test -x /usr/sbin/policy-rc.d
printf 'XXXX' > /etc/hostid
HOOK
    chmod 0755 "$OVERLAY/post-install"
    deploy_boot_overlay "$OVERLAY" "$BE" B
}

. /acceptance/share.sh
. /acceptance/deploy_boot.sh

stage_1() {
    fixture_hostid
    fixture_pools
    fixtures_mount
    d=$(disk D)
    must mkdir mkdir -p /mnt/zfs-e2e
    host_overlay
    must wipe-before zboot wipe "$d" --dry-run --json
    must disk-before disk_ends "$d"
    deploy esp-32m 32M --dry-run
    deploy preview 512M --dry-run || fail 'deploy preview failed'
    token=$(json .token) || fail 'deploy preview has no token'
    deploy preview-again 512M --dry-run
    deploy unattended 512M
    deploy wrong-token 512M --confirm "$WRONG"
    must wipe-refused zboot wipe "$d" --dry-run --json
    must disk-refused disk_ends "$d"
    if ! deploy apply 512M --confirm "$token"; then
        step failed-inventory zboot status --json --snapshots
        fail 'confirmed deploy failed'
    fi
    applied=$ZT_LAST.out
    must inventory-after zboot status --json --snapshots
    observe after-apply
    must gpt sfdisk --json "$d"
    part=$(json '.partitiontable.partitions[-1].node') || fail 'GPT names no pool partition'
    guid=$(jq -er .result.outcome.pool.identity.pool_guid < "$applied") || fail 'outcome has no pool guid'
    must import zpool import -N -o readonly=on -d "$part" "$guid"
    must inventory-imported zboot status --json --snapshots
    observe imported
    must view-mkdir mkdir -p "$VIEW"
    must view-mount mount -t zfs -o ro,zfsutil "$BE" "$VIEW"
    must be-hostid busybox xxd -p "$VIEW/etc/hostid"
    # shellcheck disable=SC2046
    must boot-files sha256sum $(jq -r --arg v "$VIEW" '.result.review.factory.kernels[] | "\($v)/boot/initrd.img-\(.)", "\($v)/boot/vmlinuz-\(.)"' < "$applied")
    must userspace ls -l "$VIEW/usr/bin/zboot" "$VIEW/usr/bin/zsnap"
    must overlay-file busybox stat -c '%a %u %g' "$VIEW/etc/zboot-e2e/marker"
    must overlay-marker cat "$VIEW/etc/zboot-e2e/marker"
    must hook-env cat "$VIEW/etc/zboot-e2e/env"
    must hook-hostid cat "$VIEW/etc/zboot-e2e/hostid-seen"
    step base-unit cat "$VIEW/etc/systemd/system/zboot-ssh-keygen.service"
    step base-link readlink "$VIEW/etc/systemd/system/ssh.service.wants/zboot-ssh-keygen.service"
    step sshd-installed test -x "$VIEW/usr/sbin/sshd"
    step policy-rc ls "$VIEW/usr/sbin/policy-rc.d"
    log=$(jq -er '.result.outcome | "\(.journal_directory)/deploy-\(.operation_id)-post-install-0.log"' < "$applied") ||
        fail 'deploy outcome names no attempt directory'
    must hook-log ls -l "$log"
    # Stock mounting: deploy seeds no zfs-mount-generator list cache.
    step list-cache find "$VIEW/etc/zfs/zfs-list.cache" -type f
    must view-umount umount "$VIEW"
    must export zpool export "$POOL"
    must mountinfo-final cat /proc/self/mountinfo
}
