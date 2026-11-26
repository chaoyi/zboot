#!/bin/sh
# One interactive console. Only an explicit QEMU firmware value selects serial.
# The argument is a sysfs entry directory; production callers use the fixed path.
zboot_console_from_firmware() {
    ZBOOT_CONSOLE=tty0
    [ -r "$1/raw" ] || return 0
    # Read bounded metadata and payload. The exact size rejects suffixes, NULs,
    # whitespace and arbitrary paths; fw_cfg entries are immutable during boot.
    # QEMU -fw_cfg string= excludes its terminating NUL (documented CLI contract),
    # so ttyS0 is exactly five bytes, unlike an arbitrary binary file= payload.
    size=$(/bin/busybox dd if="$1/size" bs=1 count=2 2>/dev/null) || size=
    if [ "$size" = 5 ]; then
        value=$(/bin/busybox dd if="$1/raw" bs=1 count=5 2>/dev/null) || value=
        if [ "$value" = ttyS0 ]; then
            ZBOOT_CONSOLE=ttyS0
            return 0
        fi
    fi
    echo 'zboot: invalid firmware console selection; using tty0' >&2
}

zboot_select_console() {
    modprobe qemu_fw_cfg 2>/dev/null || :
    zboot_console_from_firmware /sys/firmware/qemu_fw_cfg/by_name/opt/zboot/console
}
