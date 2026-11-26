# Guest helpers for acceptance cases. Sourced by init.sh; POSIX sh (busybox).
#
# A case is /acceptance/cases/ID.sh defining stage_1, stage_2, ... Each stage
# runs product commands through `step`/`must`/`refuse` and records native
# state with `observe`. Every command's argv, stdout, stderr and status land in
# /out/STAGE/ (the host's writable 9p share). The host owns the verdict: it
# reads those files after the boot. A stage only stops early on a step that
# cannot be meaningfully continued (`must`, `refuse`, `fail`).

# The runtime initrd links only some busybox applets. The rest fill gaps from
# the END of PATH, so a real tool the product runs (lsblk, zfs) always wins.
mkdir -p /run/zt-busybox && /bin/busybox --install -s /run/zt-busybox
PATH=$PATH:/run/zt-busybox
# Bulk fixtures, when the host attaches them, on a read-only share.
if ! grep -qs ' /fixtures ' /proc/mounts &&
    grep -qs zt-fixtures /sys/bus/virtio/drivers/9pnet_virtio/*/mount_tag; then
    mkdir -p /fixtures
    mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-fixtures /fixtures
fi

ZT_N=0

zt_emit() { echo "ZT1 $*" > /dev/ttyS1; }

# step NAME CMD [ARG...]: run CMD, record it as /out/S/NN-NAME.{argv,out,err,rc}.
step() {
    name=$1; shift
    ZT_N=$((ZT_N + 1))
    base=$(printf '%s/%02d-%s' "$ZT_OUT" "$ZT_N" "$name")
    printf '%s\n' "$@" > "$base.argv"
    "$@" > "$base.out" 2> "$base.err" < /dev/null
    rc=$?
    echo "$rc" > "$base.rc"
    ZT_LAST=$base
    return "$rc"
}

# must NAME CMD...: the command has to succeed.
must() { step "$@" || fail "$1 exited $(cat "$ZT_LAST.rc")"; }

# refuse NAME CMD...: the command has to fail; the host checks its message
# and that state is unchanged (observe before and after).
refuse() { if step "$@"; then fail "$1 succeeded but must refuse"; fi; }

# json FILTER: apply jq FILTER to the last step's stdout (e.g. a --json envelope).
json() { jq -er "$1" < "$ZT_LAST.out"; }

# observe NAME: independent native evidence, never through zboot.
observe() {
    ZT_N=$((ZT_N + 1))
    dir=$(printf '%s/%02d-%s.observe' "$ZT_OUT" "$ZT_N" "$1")
    mkdir -p "$dir"
    zpool list -Hp -o name,guid,health,readonly > "$dir/pools" 2>&1
    zpool get -Hp all > "$dir/pool-properties" 2>&1
    zfs list -Hp -t all -o name,guid,createtxg,type > "$dir/datasets" 2>&1
    zfs get -Hp -t all all > "$dir/properties" 2>&1
    zfs list -Hp -t snapshot -o name | while read -r s; do
        zfs holds -Hp "$s"
    done > "$dir/holds" 2>&1
    cat /proc/self/mountinfo > "$dir/mountinfo"
    for p in $(zpool list -Ho name 2>/dev/null); do
        zpool status -p "$p"
    done > "$dir/status" 2>&1
    true
}

# payload NAME DIR: content hashes of every regular file under DIR.
payload() {
    ZT_N=$((ZT_N + 1))
    (cd "$2" && find . -xdev -type f -exec sha256sum {} + | sort -k2) \
        > "$(printf '%s/%02d-%s.payload' "$ZT_OUT" "$ZT_N" "$1")" 2>&1
}

# scrub NAME POOL: wait for a full scrub and record its status.
scrub() { must "$1" sh -c 'zpool scrub -w "$1" && zpool status -p "$1"' scrub "$2"; }

# arm NAME TOOL MATCHER [after]: the next TOOL call whose argv satisfies the
# shell MATCHER (evaluated with the call's "$@") emits `CUT NAME` and blocks
# forever, before the real call, or after it with `after`. The host then
# power-cuts the VM. The cut call's argv lands in /out/STAGE/cut-NAME.argv.
# See fault.sh.
arm() {
    mkdir -p /run/zt-fault
    printf '%s\n' "$1" > "/run/zt-fault/$2.name"
    printf '%s\n' "$3" > "/run/zt-fault/$2.match"
    printf '%s\n' "${4:-before}" > "/run/zt-fault/$2.when"
    printf '%s\n' "$ZT_OUT/cut-$1.argv" > "/run/zt-fault/$2.record"
}

fail() {
    printf '%s\n' "$*" > "$ZT_OUT/FAILED"
    zt_emit DONE failed
    sync
    poweroff -f
}

. /acceptance/fixture.sh

zt_run() {
    ZT_OUT=/out/$2
    mkdir -p "$ZT_OUT" || { zt_emit DONE no-output; poweroff -f; }
    . "/acceptance/cases/$1.sh" || fail "no case $1"
    command -v "stage_$2" > /dev/null || fail "case $1 has no stage $2"
    zt_emit BEGIN "$1:$2"
    "stage_$2"
    sync
    zt_emit DONE ok
    poweroff -f
}
