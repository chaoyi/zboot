# Cut before the step-7 (erasing) record write. After the restart, a new
# snapshot, a new child and a write on the kept tree of A each make resume
# refuse the erase: nothing of A is lost.
. /acceptance/restore.sh

stage_1() {
    restore_base
    restore_source
    restore_scratch
    RESTORE_KEEP='--keep e2ea/scratch'
    restore_cut 7
}

# attempt NAME: full consent for resume, then the confirmed resume is refused.
attempt() {
    reviewed "$1" zb resume "$RECORD_ID"
    if zb "$1-confirmed" resume "$RECORD_ID" --confirm "$TOKEN"; then fail "$1: resume erased A"; fi
    restore_record "$1-record"
    must "$1-pools" zpool list -H -o name
    step "$1-first" zfs list -H -o name e2ea/plain@first
}

stage_2() {
    restore_hostid
    must import-b zpool import -N -o cachefile=none -d /dev e2eb
    must import-a zpool import -N -o cachefile=none -d /dev e2ea
    restore_record record
    [ -n "$RECORD_ID" ] || fail 'no restore record on B after the cut'
    must a-before zfs list -H -r -t all -o name,guid e2ea
    observe before
    must later zfs snapshot e2ea/scratch@later
    attempt snapshot
    must later-destroy zfs destroy e2ea/scratch@later
    must new zfs create -o mountpoint=none e2ea/scratch/new
    attempt child
    must new-destroy zfs destroy e2ea/scratch/new
    # Staging fenced the kept tree; the operator makes it writable and writes.
    must fence zfs get -H -o value readonly e2ea/scratch
    must writable zfs set readonly=off e2ea/scratch
    must scratch-mount zfs mount e2ea/scratch
    put "$SETUP_MOUNT/scratch/restore-token" ZFS-E2E-RESTORE-CHANGED
    must scratch-unmount zfs unmount e2ea/scratch
    must sync-a zpool sync e2ea
    attempt written
    must a-after zfs list -H -r -t all -o name,guid e2ea
    observe after
    scrub scrub-b e2eb
}
