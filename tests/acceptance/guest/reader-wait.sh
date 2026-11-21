#!/bin/sh
# Supervised acceptance reader: prove every published alias is available, then
# wait for the native observer. No protection is acquired/released by this child.
set -eu
control=$1
/bin/busybox cat "/proc/self/fd/$ZSNAP_MANIFEST_FD" > "$control/manifest"
jq -er '.sources | if type == "array" and length > 0 then .[].alias
    else error("reader manifest has no sources") end' "$control/manifest" > "$control/aliases"
while IFS= read -r alias; do
    test -n "$alias"
    test -d "$ZSNAP_VIEW/$alias"
done < "$control/aliases"
: > "$control/ready"
i=0
while [ ! -f "$control/end" ]; do
    [ "$i" -lt 1200 ] || exit 1
    /bin/busybox sleep 0.1
    i=$((i + 1))
done
