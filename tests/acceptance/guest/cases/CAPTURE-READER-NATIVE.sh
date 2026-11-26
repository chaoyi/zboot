# CAPTURE-READER: INV-01, then shared recursive capture, supervised readers with
# native holds and deferred destroy, IV-set and written@ native semantics.
. /acceptance/identity.sh
. /acceptance/cases/INV-01-NATIVE.sh
READER_STATE=/var/lib/zsnap/protect
IO=/mnt/zfs-e2e/io
# Each reader is the real complete task. The barrier only keeps its supervised
# child alive while this independent guest shell observes native protection.
start_reader() {
    reader_label=$1; shift
    reader_control=/run/zt-reader-$reader_label
    mkdir -m 0700 "$reader_control"
    ZT_N=$((ZT_N + 1))
    reader_base=$(printf '%s/%02d-%s' "$ZT_OUT" "$ZT_N" "$reader_label")
    printf '%s\n' zsnap protect "$@" --state-dir "$READER_STATE" --result "$reader_control/result" \
        -- /bin/sh /acceptance/reader-wait.sh "$reader_control" > "$reader_base.argv"
    zsnap protect "$@" --state-dir "$READER_STATE" --result "$reader_control/result" \
        -- /bin/sh /acceptance/reader-wait.sh "$reader_control" \
        > "$reader_base.out" 2> "$reader_base.err" < /dev/null &
    reader_pid=$!
    i=0
    while [ ! -f "$reader_control/ready" ]; do
        kill -0 "$reader_pid" 2>/dev/null || fail "$reader_label ended before the reader barrier"
        [ "$i" -lt 300 ] || fail "$reader_label reader barrier timed out"
        /bin/busybox sleep 0.1; i=$((i + 1))
    done
    must "$reader_label-manifest" cat "$reader_control/manifest"
}
end_reader() {
    expected=$1
    : > "$reader_control/end"
    wait "$reader_pid"; reader_rc=$?
    printf '%s\n' "$reader_rc" > "$reader_base.rc"
    [ "$reader_rc" = "$expected" ] || fail "$reader_label exited $reader_rc instead of $expected"
    must "$reader_label-result" cat "$reader_control/result"
}
# Deferred destruction is only accepted after mounted snapshot views end.
# Interrupt our exact supervisor, then let authenticated recovery stop its owned
# subtree. This leaves the native hold for the subsequent policy check.
stop_reader() {
    reader_job=$(jq -er .job "$reader_control/manifest") || fail 'reader manifest has no job'
    must "$reader_label-stop-owner" kill -KILL "$reader_pid"
    wait "$reader_pid"; reader_rc=$?
    printf '%s\n' "$reader_rc" > "$reader_base.rc"
    [ "$reader_rc" != 0 ] || fail 'interrupted supervisor exited successfully'
    must "$reader_label-stop-preview" zsnap recover "$reader_job" --state-dir "$READER_STATE" --stop --dry-run --json
    stop_token=$(json .token) || fail 'orphan stop review has no token'
    step "$reader_label-stop" zsnap recover "$reader_job" --state-dir "$READER_STATE" --stop --confirm "$stop_token" --json
    [ "$(cat "$ZT_LAST.rc")" = 3 ] || fail 'orphan stop did not require a fresh release review'
}
written_case() {
    c=$1
    must $c-base sh -e -c 'i=0; while [ $i -lt 256 ]; do printf "snapshot-fixture-data\n"; i=$((i + 1)); done > "$1"
        zfs snapshot "$2"' w $IO/$c e2ea/io@${c}_base
    must $c-fresh zfs get -H -p -o value written@${c}_base e2ea/io
    case $c in
    delete) must delete-mutate rm $IO/delete ;;
    truncate) must truncate-mutate busybox truncate -s 0 $IO/truncate ;;
    xattr)
        must xattr-mutate setfattr -n user.zfs-e2e -v changed $IO/xattr
        must xattr-read getfattr --only-values -n user.zfs-e2e $IO/xattr ;;
    metadata)
        must metadata-mutate chmod 0640 $IO/metadata
        must metadata-read busybox stat -c %a $IO/metadata ;;
    esac
    must $c-seal sh -e -c 'zfs set readonly=on e2ea/io; zpool sync e2ea'
    must $c-written zfs get -H -p -o value written@${c}_base e2ea/io
    must $c-unseal zfs set readonly=off e2ea/io
}
stage_1() {
    fixture_pools
    inventory_part
    # Shared recursive capture.
    must capture zboot snapshot e2ea/renamed@captured --json
    capture_result=$ZT_LAST.out
    observe captured
    must markers zfs get -H -o name,value zboot:capture e2ea/renamed@captured e2ea/renamed/child@captured
    refuse collision zboot snapshot e2ea/renamed@captured --json
    observe after-collision
    must readonly-child zfs set readonly=on e2ea/renamed/child
    observe readonly-before
    refuse readonly zboot snapshot e2ea/renamed@forbidden --json
    observe readonly-after
    must readwrite-child zfs set readonly=off e2ea/renamed/child
    # Complete readers use persistent fixture state outside every protected
    # source. Mount cgroup v2 and provide this disposable guest's machine ID.
    must reader-environment sh -e -c 'mkdir -p /sys/fs/cgroup /var/lib/zsnap
        mount -t cgroup2 none /sys/fs/cgroup
        printf "ee401eaa5dc94fdf9a739a6bcfd87a81\n" > /etc/machine-id
        zfs create -o mountpoint=/var/lib/zsnap e2ea/reader-state'
    # Nested datasets need disjoint aliases. Build the supported task request
    # from zboot's exact capture references, without private receipt plumbing.
    must reader-request jq '{schema_version:1,sources:[.result[0].points[] |
        {snapshot:.,alias:(if .name | contains("/child@") then "child" else "root" end)}]}' "$capture_result"
    cp "$ZT_LAST.out" /run/zt-reader-request.json
    start_reader protect-capture --consumer e2e-capture --request-json /run/zt-reader-request.json
    refuse destroy-root zfs destroy e2ea/renamed@captured
    refuse destroy-child zfs destroy e2ea/renamed/child@captured
    observe pinned
    end_reader 0
    observe after-reader
    must destroy-released-root zfs destroy e2ea/renamed@captured
    must destroy-released-child zfs destroy e2ea/renamed/child@captured
    # Default recovery cannot complete deferred destruction after the
    # authenticated orphan stop has ended all reader/view custody.
    must preserve-fixture zfs snapshot e2ea/renamed@preserve-deferred
    start_reader protect-preserve --consumer e2e-preserve e2ea/renamed@preserve-deferred
    observe preserve-pinned
    stop_reader
    preserve_job=$reader_job
    observe preserve-stopped
    must destroy-preserve zfs destroy -d e2ea/renamed@preserve-deferred
    observe preserve-deferred
    must recover-preserve zsnap recover "$preserve_job" --state-dir "$READER_STATE" --dry-run --json
    preserve_token=$(json .token) || fail 'recovery preview has no token'
    refuse recover-preserve-apply zsnap recover "$preserve_job" --state-dir "$READER_STATE" --confirm "$preserve_token" --json
    observe after-preserve-recovery
    # The original EndProtection decision permits deferred completion through
    # reviewed recovery, after the same authenticated reader/view teardown.
    start_reader protect-deferred --consumer e2e-deferred --end-protection e2ea/renamed@first
    observe deferred-pinned
    stop_reader
    observe deferred-stopped
    must destroy-deferred zfs destroy -d e2ea/renamed@first
    observe deferred
    must recover-deferred zsnap recover "$reader_job" --state-dir "$READER_STATE" --dry-run --json
    deferred_token=$(json .token) || fail 'deferred recovery preview has no token'
    must recover-deferred-apply zsnap recover "$reader_job" --state-dir "$READER_STATE" --confirm "$deferred_token" --json
    observe after-deferred
    must hold-foreign zfs hold foreign-reader e2ea/renamed@second
    start_reader protect-foreign --consumer e2e-foreign e2ea/renamed@second
    observe foreign-pinned
    end_reader 0
    observe after-foreign
    refuse destroy-foreign zfs destroy e2ea/renamed@second
    must release-foreign zfs release foreign-reader e2ea/renamed@second
    # Native control: only the foreign hold prevented that destroy.
    # IV sets: the native hidden property (the old library observer's source).
    must ivset zfs get -H -p -o value ivsetguid e2eb/encrypted@secret
    must all-properties zfs get -H -p -o property all e2eb/encrypted@secret
    must ivset-plain zfs get -H -p -o value ivsetguid e2ea/renamed@second
    must destroy-foreign-released zfs destroy e2ea/renamed@second
    # written@ semantics.
    must io sh -e -c 'mkdir -p /mnt/zfs-e2e; zfs create -o mountpoint=/mnt/zfs-e2e/io e2ea/io'
    step absent-latest zfs get -H -p -o value written@latest e2ea/io
    for c in delete truncate xattr metadata; do written_case $c; done
    must latest-snapshot zfs snapshot e2ea/io@latest
    must latest-written zfs get -H -p -o value written@latest e2ea/io
}
