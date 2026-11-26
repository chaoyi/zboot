#!/bin/sh
# BusyBox udhcpc callback for the attended Menu only. Lease fields are
# untrusted data; Rust validates them before configuring any address.
set -eu
[ "$#" -eq 1 ] || exit 1
case "$1" in
    bound) ;;
    deconfig|renew) exit 0 ;;
    *) exit 1 ;;
esac
umask 077
printf '%s\n%s\n%s\n%s\n%s\n' "${interface-}" "${ip-}" "${subnet-}" "${router-}" "${lease-}" > /run/zboot-connect/dhcp-lease
