#!/bin/sh
# A fake `nvme` (nvme-cli 2.x JSON) for WIPE-SANITIZE-NATIVE. QEMU's emulated
# NVMe has no Sanitize command, so the case bind-mounts this over the real
# program and zboot's native path runs against it. It answers for one
# controller as the captured consumer drives do (crates/zboot/src/device/
# wipe/fixtures): crypto and block erase, CMIC 0, no namespace
# management (list-ctrl and list-ns --all are rejected), NN 1. A sanitize
# reports "in progress" for RUN_READS log reads, then really zeroes the
# namespace and reports success, or reports failure without touching it.
#
# $ZT_FAKE_NVME (default /run/zt-fake-nvme) holds:
#   config  shell assignments: CONTROLLER=/dev/nvmeN NAMESPACE=/dev/nvmeNn1
#           BYTES (namespace size), CNTLID, SERIAL and SUBNQN (as sysfs shows
#           them, which zboot checks id-ctrl against), RUN_READS, OUTCOME
#           (success|failure: how the next submitted sanitize ends)
#   state   shell assignments: STATUS (SSTAT 0-4), CDW10, ERASED (global
#           erased), RUNNING (log reads still "in progress"), ENDS (empty, or
#           success|failure: how the running sanitize ends)
#   calls   one line per call: its arguments, and the reply it got
# POSIX sh; runs on the guest's busybox.
set -u
dir=${ZT_FAKE_NVME:-/run/zt-fake-nvme}
. "$dir/config"
. "$dir/state"

record() { printf '%s => %s\n' "$*" "$reply" >> "$dir/calls"; }
unexpected() {
    reply='exit 2'; record "$@"
    echo "zt-fake-nvme: unexpected arguments: $*" >&2
    exit 2
}
save() {
    printf 'STATUS=%s CDW10=%s ERASED=%s RUNNING=%s ENDS=%s\n' \
        "$STATUS" "$CDW10" "$ERASED" "$RUNNING" "$ENDS" > "$dir/state.new" &&
        mv "$dir/state.new" "$dir/state"
}
# What nvme-cli prints, exiting 1, for an Identify CNS the drives lack.
reject() {
    reply='exit 1'; record "$@"
    echo '{"error": "Invalid Field in Command: A reserved coded value or an unsupported value in a defined field", "type": "nvme"}'
    exit 1
}
# end: the running sanitize ends as ENDS. Success zeroes the namespace first,
# through the guest's page cache, which zboot's reads and probes share.
# (util-linux blkdiscard -z cannot: zboot holds the disk exclusively.)
end() {
    if [ "$ENDS" = success ] &&
        dd if=/dev/zero of="$NAMESPACE" bs=1048576 count=$((BYTES / 1048576)) conv=notrunc status=none 2>> "$dir/errors"; then
        STATUS=1 ERASED=1
    else
        STATUS=3 ERASED=0
    fi
    ENDS=
}
log() {
    sprog=65535 sans='(0) Idle state' failure=
    if [ "$RUNNING" -gt 0 ]; then
        RUNNING=$((RUNNING - 1)) sprog=32768 reported=2 erased=0
        sans='(1) Restricted Processing State'
    else
        [ -z "$ENDS" ] || end
        reported=$STATUS erased=$ERASED
    fi
    save
    case $reported in
        0) text='NVM Subsystem has never been sanitized.' ;;
        1) text='Most Recent Sanitize Command Completed Successfully.' ;;
        2) text='Sanitize in Progress.' ;;
        3) text='Most Recent Sanitize Command Failed.'
           sans='(2) Restricted Failure State'
           failure=', "failure_state": "(1) Restricted Processing State"' ;;
        *) text='Unknown' ;;
    esac
    reply="status $reported"; record "$@"
    cat <<EOF
{
  "${CONTROLLER##*/}": {
    "sprog": $sprog,
    "sstat": {"media_verification_canceled": 0, "global_erased": $erased, "no_cmplted_passes": 0, "status": "($reported) $text"},
    "cdw10_info": $CDW10,
    "time_over_write": 4294967295, "time_block_erase": 4294967295, "time_crypto_erase": 4294967295,
    "time_over_write_no_dealloc": 0, "time_block_erase_no_dealloc": 0, "time_crypto_erase_no_dealloc": 0,
    "time_post_verification_dealloc": 0,
    "sanitize_state_information": {"sanitize_state": "$sans"$failure}
  }
}
EOF
}

reply='exit 0'
[ $# -ge 1 ] || unexpected "$@"
if [ "$1" = version ] && [ $# -eq 1 ]; then
    record "$@"; echo 'nvme version zt-fake'; exit 0
fi
[ $# -ge 2 ] && [ "$2" = "$CONTROLLER" ] || unexpected "$@"
blocks=$((BYTES / 512))
case "$1|$#|${3-}|${4-}" in
    'id-ctrl|3|--output-format=json|')
        record "$@"
        printf '{"vid": 6966, "ssvid": 6900, "sn": "%-20s", "mn": "QEMU NVMe Ctrl (zt-fake)", "fr": "zt-fake", "cmic": 0, "cntlid": %s, "oacs": 22, "sanicap": 3, "nn": 1, "subnqn": "%s"}\n' "$SERIAL" "$CNTLID" "$SUBNQN" ;;
    'list-ns|3|--output-format=json|')
        record "$@"; echo '{"nsid_list": [{"nsid": 1}]}' ;;
    'id-ns|4|--namespace-id=1|--output-format=json')
        record "$@"
        printf '{"nsze": %s, "ncap": %s, "nuse": %s, "nsfeat": 0, "nlbaf": 0, "flbas": 0, "mc": 0, "dpc": 0, "dps": 0, "nmic": 0, "rescap": 0}\n' "$blocks" "$blocks" "$blocks" ;;
    list-ctrl\|*) reject "$@" ;;
    'list-ns|4|--all|--output-format=json') reject "$@" ;;
    'sanitize-log|3|--output-format=json|') log "$@" ;;
    'sanitize|3|--sanact=2|' | 'sanitize|3|--sanact=4|')
        if [ "$RUNNING" -gt 0 ] || [ -n "$ENDS" ] || [ "$STATUS" = 3 ]; then
            reply='exit 1'; record "$@"
            echo 'NVMe status: Sanitize In Progress or Failed' >&2
            exit 1
        fi
        CDW10=${3#--sanact=} RUNNING=$RUN_READS ENDS=$OUTCOME
        save
        record "$@" ;;
    *) unexpected "$@" ;;
esac
