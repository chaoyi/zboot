#!/bin/sh
# Native-call boundary for power cuts. Installed only in the disposable
# acceptance initrd as /usr/bin/TOOL -> `fault.sh TOOL REAL "$@"`. An unarmed
# or unmatched call runs REAL unchanged (same argv, stdin, stdout, stderr).
# An armed match fires once: it records the call's argv on the out share
# (the host checks where the cut landed), writes `ZT1 CUT NAME` on the
# test channel, syncs, and blocks forever; the host then SIGKILLs QEMU, so the
# disks hold exactly what the guest wrote up to that boundary.
# Opt-in error-before/error-after instead return status 97, recording mode,
# test ID and the real child status beside the argv. Existing cuts are unchanged.
tool=$1 real=$2; shift 2
dir=/run/zt-fault
if [ -f "$dir/$tool.match" ] && [ ! -e "$dir/$tool.fired" ] &&
    ( eval "$(cat "$dir/$tool.match")" ) < /dev/null > /dev/null 2>&1 &&
    mkdir "$dir/$tool.fired" 2> /dev/null; then
    record=$(cat "$dir/$tool.record")
    printf '%s\n' "$@" > "$record"
    when=$(cat "$dir/$tool.when")
    case "$when" in
        error-before|error-after)
            # Opt-in returned errors do not emit CUT, sync, or block QEMU.
            # Keep the real child's result distinct from the injected status.
            printf '%s\n' "$when" > "$record.mode"
            cat "$dir/$tool.name" > "$record.test-id"
            if [ "$when" = error-after ]; then
                "$real" "$@"
                real_rc=$?
                printf '%s\n' "$real_rc" > "$record.real-rc"
                [ "$real_rc" -eq 0 ] || exit "$real_rc"
            else
                printf '%s\n' not-run > "$record.real-rc"
            fi
            printf '%s\n' 97 > "$record.injected-rc"
            echo "acceptance injected $when: $(cat "$dir/$tool.name")" >&2
            exit 97
            ;;
    esac
    cut() { sync; echo "ZT1 CUT $(cat "$dir/$tool.name")" > /dev/ttyS1; exec sleep 2147483647; }
    if [ "$when" = after ]; then
        "$real" "$@"
        cut
    fi
    cut
fi
exec "$real" "$@"
