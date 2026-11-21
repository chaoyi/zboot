#!/bin/sh
# fault.sh matcher for a restore cut (armed by restore_cut in restore.sh):
#   restore-cut.sh STEP OUT ARG...   with ARG... the argv of one `zfs` call.
# Matches only `zfs set zboot:operation=<record> e2eb` whose record has
# kind "restore" and step STEP. On a match it saves the mount tables at that
# instant, while the paused engine still holds the pools: its own mount
# namespace (OUT/cut-mounts) and init's (OUT/cut-mounts-init). The host
# checks the cut argv itself, including the record's operation id.
step=$1 out=$2
shift 2
[ $# -eq 3 ] && [ "$1" = set ] && [ "$3" = e2eb ] || exit 1
record=${2#zboot:operation=}
[ "$record" != "$2" ] || exit 1
printf '%s' "$record" |
    /usr/bin/jq -e --argjson step "$step" '.kind == "restore" and .step == $step' > /dev/null || exit 1
cat /proc/self/mountinfo > "$out/cut-mounts"
cat /proc/1/mountinfo > "$out/cut-mounts-init"
