# WIPE-SANITIZE-NATIVE: zboot's native NVMe sanitize path on the QEMU NVMe
# disk N. QEMU has no Sanitize command, so /acceptance/fake-nvme.sh is bind
# mounted over every `nvme` on PATH (zboot runs `nvme` by name) and answers
# as a consumer drive; its sanitize zeroes N. Three parts on the same disk:
# a plain sanitize, one already running when wipe starts (after a power
# loss), and one the controller reports failed.
FAKE=/run/zt-fake-nvme
# gpt DISK: the primary and backup GPT headers (LBA 1 and the last LBA), "EFI PART" or not.
GPT='last=$(($(busybox blockdev --getsize64 "$1") / 512 - 1))
for lba in 1 $last; do
    if dd if="$1" bs=512 skip=$lba count=1 2>/dev/null | grep -q "EFI PART"; then echo present; else echo absent; fi
done'
# ends DISK: non-zero bytes in the first and the last MiB.
ENDS='mib=$(($(busybox blockdev --getsize64 "$1") / 1048576))
for skip in 0 $((mib - 1)); do
    dd if="$1" bs=1048576 skip=$skip count=1 2>/dev/null | busybox tr -d "\000" | busybox wc -c
done'
SENTINEL=ZFS-E2E-SANITIZE-SENTINEL SENTINEL_AT=68157440

# n_part NAME STATE: give N a GPT partition and a sentinel inside it, set the
# fake controller's sanitize log to STATE, and empty its call record.
n_part() {
    must "$1-setup" sh -e -c 'sgdisk -o -n 1:0:0 -t 1:8300 "$1"; partprobe "$1"; mdev -s
        printf %s "$2" | dd of="$1" bs=1 seek="$3" conv=notrunc 2>/dev/null' p "$N" "$SENTINEL" "$SENTINEL_AT"
    must "$1-state" sh -e -c 'printf "%s\n" "$2" > "$1/state"; : > "$1/calls"' s "$FAKE" "$2"
}

# n_wipe NAME: the reviewed, confirmed wipe of N by its token, then the
# fake's call record and independent probes of N.
n_wipe() {
    must "$1-preview" zboot wipe "$N" --dry-run --json
    token=$(json .token) || fail "$1 preview carries no token"
    step "$1" zboot wipe "$N" --confirm "$token" --json
    must "$1-calls" cat "$FAKE/calls"
    step "$1-blkid" blkid -p "$N"
    must "$1-gpt" sh -c "$GPT" g "$N"
    must "$1-ends" sh -c "$ENDS" e "$N"
    must "$1-sentinel" dd if="$N" bs=1 skip="$SENTINEL_AT" count=${#SENTINEL}
}

stage_1() {
    must disks sh -c 'for d in /sys/block/vd* /sys/block/nvme*n*; do s=; read -r s 2>/dev/null < $d/serial || read -r s < $d/device/serial; printf "%s\t/dev/%s\n" "$s" "${d##*/}"; done'
    N=$(disk N)
    # The kernel's view zboot reads: the namespace and its controller.
    must kernel sh -e -c 'ns=$(readlink -f "/sys/block/${1##*/}"); parent=${ns%/*}
        case ${parent##*/} in
        nvme-subsys*) for c in "$parent"/*; do case ${c##*/} in nvme[0-9]|nvme[0-9][0-9]) echo "${c##*/} $(cat "$c/dev")";; esac; done ;;
        *) echo "${parent##*/} $(cat "$parent/dev")" ;;
        esac
        echo "$ns"; cat "$ns/nsid"' k "$N"
    read -r ctrl _ < "$ZT_LAST.out"
    must fake-install sh -e -c 'mkdir -p "$1"
        cp /acceptance/fake-nvme.sh "$1/nvme"; chmod 0755 "$1/nvme"
        sys=/sys/class/nvme/$2; read -r serial < "$sys/serial"; read -r nqn < "$sys/subsysnqn"
        printf "CONTROLLER=/dev/%s NAMESPACE=%s BYTES=%s CNTLID=%s SERIAL=%s SUBNQN=%s RUN_READS=2 OUTCOME=success\n" \
            "$2" "$3" "$(busybox blockdev --getsize64 "$3")" "$(cat "$sys/cntlid")" "$serial" "$nqn" > "$1/config"
        printf "STATUS=1 CDW10=4 ERASED=0 RUNNING=0 ENDS=\n" > "$1/state"
        for d in $(echo "$PATH" | tr : " "); do
            [ -e "$d/nvme" ] && readlink -f "$d/nvme"
        done | sort -u | while read -r real; do
            mount --bind "$1/nvme" "$real"; echo "$real"
        done
        cat "$1/config"' f "$FAKE" "$ctrl" "$N"
    must fake-active nvme version

    # 1. A consumer drive's log: its last crypto erase succeeded, data was
    # written since. The sanitize runs for two log reads, then zeroes N.
    n_part plain 'STATUS=1 CDW10=4 ERASED=0 RUNNING=0 ENDS='
    n_wipe plain
    must plain-bare zboot wipe "$N" --dry-run --json

    # 2. After a power loss: a crypto erase is already running when wipe
    # starts. It is waited out, then wipe submits its own.
    n_part resumed 'STATUS=1 CDW10=4 ERASED=0 RUNNING=2 ENDS=success'
    n_wipe resumed

    # 3. The controller reports the sanitize failed: wipe refuses, clears
    # nothing else; a second wipe meets failure mode and submits nothing.
    must failing-config sh -e -c 'sed -i "s/OUTCOME=success/OUTCOME=failure/" "$1/config"; cat "$1/config"' c "$FAKE"
    n_part failed 'STATUS=1 CDW10=4 ERASED=0 RUNNING=0 ENDS='
    n_wipe failed
    must failure-mode-state sh -c ': > "$1/calls"; cat "$1/state"' s "$FAKE"
    n_wipe failure-mode
    must fake-errors sh -c 'cat "$1/errors" 2>/dev/null; true' e "$FAKE"
}
