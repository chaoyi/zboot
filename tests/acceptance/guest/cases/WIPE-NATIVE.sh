# WIPE: the imported-pool guard, then reviewed, confirmed metadata clearing of
# the disposable virtio disk D (an exported pool on its partition) and the
# QEMU NVMe disk N (no Sanitize command), verified by small probes. Nothing
# reads the whole disk.
. /acceptance/identity.sh
# D's partition 1: start and size in bytes, and a sentinel inside it that the
# clearing leaves in place (metadata clearing does not erase data).
P1=1048576 P1_BYTES=134217728 SENTINEL_AT=68157440
# labels DISK: per ZFS label of D's partition 1, the count of non-zero bytes in
# its nvlist and uberblock ring (16-256 KiB). The boot-environment block
# before them keeps its checksum tail after labelclear.
LABELS='for off in 0 262144 $(($2 - 524288)) $(($2 - 262144)); do
    dd if="$1" bs=16384 skip=$((($3 + off) / 16384 + 1)) count=15 2>/dev/null | busybox tr -d "\000" | busybox wc -c
done'
# gpt DISK: the primary and backup GPT headers (LBA 1 and the last LBA), "EFI PART" or not.
GPT='last=$(($(busybox blockdev --getsize64 "$1") / 512 - 1))
for lba in 1 $last; do
    if dd if="$1" bs=512 skip=$lba count=1 2>/dev/null | grep -q "EFI PART"; then echo present; else echo absent; fi
done'
stage_1() {
    fixture_pools
    must disks sh -c 'for d in /sys/block/vd* /sys/block/nvme*n*; do s=; read -r s 2>/dev/null < $d/serial || read -r s < $d/device/serial; printf "%s\t/dev/%s\n" "$s" "${d##*/}"; done'
    A=$(disk A) D=$(disk D) N=$(disk N)
    observe before
    step membership sh -c 'zpool status -LP; lsblk --json --bytes --tree --output PATH,TYPE,MAJ:MIN,PKNAME,SERIAL,FSTYPE,MOUNTPOINTS "$1"' m "$A"
    must a-head sh -c 'dd if="$1" bs=4096 count=8 2>/dev/null | sha256sum' h "$A"
    refuse wipe-imported zboot wipe "$A"
    must a-head-after sh -c 'dd if="$1" bs=4096 count=8 2>/dev/null | sha256sum' h "$A"
    observe after-imported
    must d-setup sh -e -c 'sgdisk -n 1:2048:+128M -t 1:BF01 "$1"; partprobe "$1"; mdev -s
        zpool create -o cachefile=none -O mountpoint=none e2ewipe "${1}1"
        zpool export e2ewipe
        printf ZFS-E2E-WIPE-SENTINEL > /run/wipe-sentinel
        dd if=/run/wipe-sentinel of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null' d "$D" "$SENTINEL_AT"
    must d-labels-before sh -c "$LABELS" l "$D" "$P1_BYTES" "$P1"
    must review zboot wipe "$D" --dry-run --json
    refuse wrong-token zboot wipe "$D" --confirm not-the-reviewed-loss-token --json
    must sentinel dd if="$D" bs=1 skip="$SENTINEL_AT" count=21
    must preview zboot wipe "$D" --dry-run --json
    token=$(json .token) || fail 'wipe preview carries no token'
    step unattended zboot wipe "$D" --json
    must sentinel-unattended dd if="$D" bs=1 skip="$SENTINEL_AT" count=21
    must wipe zboot wipe "$D" --confirm "$token" --json
    must bare-review zboot wipe "$D" --dry-run --json
    step blkid blkid -p "$D"
    must d-labels sh -c "$LABELS" l "$D" "$P1_BYTES" "$P1"
    must d-gpt sh -c "$GPT" g "$D"
    must sentinel-after dd if="$D" bs=1 skip="$SENTINEL_AT" count=21
    must n-setup sh -e -c 'sgdisk -n 1:0:0 -t 1:8300 "$1"; partprobe "$1"; mdev -s' n "$N"
    must n-preview zboot wipe "$N" --dry-run --json
    token=$(json .token) || fail 'NVMe wipe preview carries no token'
    must n-wipe zboot wipe "$N" --confirm "$token" --json
    must n-bare-review zboot wipe "$N" --dry-run --json
    step n-blkid blkid -p "$N"
    must n-gpt sh -c "$GPT" g "$N"
}
