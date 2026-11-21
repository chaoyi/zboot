# Shared guest helpers for the identity and tree cases. POSIX sh (busybox).
# Source from a case script: . /acceptance/identity.sh

# readat NAME SOURCE FILE [OPTIONS]: mount the dataset or snapshot SOURCE at a
# private path (default options ro), record FILE's bytes as step NAME, unmount.
readat() {
    must "$1" sh -e -c 'mkdir -p "$1"; mount -t zfs -o "$4" "$2" "$1"
        trap "umount \"$1\"" EXIT; cat "$1/$3"' readat "/mnt/zt-read/$1" "$2" "$3" "${4:-ro}"
}

# operation NAME POOL: record the pool's zboot:operation value (`-` when none).
operation() { must "$1" zfs get -H -o value zboot:operation "$2"; }

# confirmed NAME VERB ARG...: the consent sequence of a zboot verb that needs a
# token. Records NAME-preview (--dry-run), NAME-unattended (no --confirm; the
# host checks it exits 3), NAME-wrong (a wrong token; refused) and NAME
# (--confirm with the reviewed token), observing native state after the
# unattended and the wrong-token runs (NAME-unattended, NAME-wrong).
confirmed() {
    zt_c=$1; shift
    must "$zt_c-preview" zboot "$@" --dry-run --json
    zt_token=$(json .token) || fail "$zt_c preview carries no token"
    step "$zt_c-unattended" zboot "$@" --json
    observe "$zt_c-unattended"
    refuse "$zt_c-wrong" zboot "$@" --confirm not-the-reviewed-token --json
    observe "$zt_c-wrong"
    must "$zt_c" zboot "$@" --confirm "$zt_token" --json
}

# snapmap NAME DATASET: the native (name, guid) map of every snapshot under DATASET.
snapmap() { must "$1" zfs list -H -p -t snapshot -o name,guid -r "$2"; }

# rawpipe NAME 'SEND ARGS' 'RECEIVE ARGS': a fixture `zfs send | zfs receive`
# pipeline (not product code); stdout records send_exit=N receive_exit=M and
# the step fails unless both are 0.
rawpipe() {
    must "$1" sh -c '{ zfs send $1; echo $? > /run/zt-send.rc; } | zfs receive $2; r=$?
        s=$(cat /run/zt-send.rc); echo "send_exit=$s receive_exit=$r"; [ "$s" = 0 ] && [ "$r" = 0 ]' \
        rawpipe "$2" "$3"
}
