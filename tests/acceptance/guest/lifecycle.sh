# Shared guest helpers for the pair/primary/transfer/loss cases. POSIX sh;
# sourced by their case scripts after lib.sh. Variables are lc_-prefixed so
# they never clobber lib.sh's (step uses name/base/rc).

# put NAME FILE CONTENT: write CONTENT (no newline) to FILE and fsync it.
put() { must "$1" sh -c 'printf %s "$2" > "$1" && sync' put "$2" "$3"; }

# replicate NAME SNAPSHOT TARGET [RECEIVE-OPTION...]: the native raw fixture
# pipeline `zfs send -w -R SNAPSHOT | zfs receive -u OPTIONS TARGET`; the step
# fails unless both the send and the receive exit 0.
replicate() {
    lc_n=$1 lc_snap=$2 lc_target=$3; shift 3
    must "$lc_n" sh -e -c 'snap=$1 target=$2; shift 2
        { zfs send -w -R "$snap"; echo $? > /run/lc-send.rc; } | zfs receive -u "$@" "$target"
        echo "receive_exit=0 send_exit=$(cat /run/lc-send.rc)"
        [ "$(cat /run/lc-send.rc)" = 0 ]' replicate "$lc_snap" "$lc_target" "$@"
}

# consent NAME ZBOOT-ARG...: the consent sequence for a verb that needs a
# reviewed token: NAME-preview (--dry-run --json), NAME-unattended (--json;
# the host checks exit 3), NAME-wrong (a wrong token, refused) and
# NAME-confirm (the reviewed token, applied). Native state is observed as
# NAME-before and NAME-refused around the three runs that must change nothing.
consent() {
    lc_n=$1; shift
    observe "$lc_n-before"
    must "$lc_n-preview" zboot "$@" --dry-run --json
    lc_token=$(json .token) || fail "$lc_n preview carries no token"
    step "$lc_n-unattended" zboot "$@" --json
    refuse "$lc_n-wrong" zboot "$@" --confirm not-the-reviewed-token --json
    observe "$lc_n-refused"
    must "$lc_n-confirm" zboot "$@" --confirm "$lc_token" --json
}
