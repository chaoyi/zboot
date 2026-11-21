#!/bin/sh
# Guest-only native fault fixture. Product source contains no fault hooks.
mode=$(/bin/busybox cat /proof/control/fault-mode 2>/dev/null || :)
if [ "$1" = hold ]; then
    case "$mode" in
        pause-hold)
            /sbin/zfs "$@" || exit $?
            printf '%s\n' "$$" >/proof/control/fault-native-pid
            /bin/busybox touch /proof/control/fault-reached
            while [ -e /proof/control/fault-mode ]; do /bin/busybox sleep 0.02; done
            exit 0 ;;
        lost-hold)
            /bin/busybox rm /proof/control/fault-mode
            /sbin/zfs "$@" || exit $?
            exit 73 ;;
        fail-second-hold)
            if [ -e /proof/control/fault-first-hold ]; then
                /bin/busybox rm /proof/control/fault-mode
                exit 74
            fi
            /bin/busybox touch /proof/control/fault-first-hold ;;
    esac
fi
exec /sbin/zfs "$@"
