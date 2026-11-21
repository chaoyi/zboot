#!/usr/bin/env bash
# Populate a new initramfs root from explicitly named, trusted runtime files:
#
#   stage-runtime.sh --NAME FILE... --udev-rules DIR --firmware-root DIR
#       --firmware RELATIVE... --module-dir DIR --output NEW_DIRECTORY
#
# Every NAME in `programs` is required. Each program goes to its fixed
# destination with its loader closure; ldd runs only on these caller-supplied
# installed executables. usr/share/zfs-tools/runtime-sources.sha256 records
# every source file for the licence collector. NEW_DIRECTORY appears only when
# the whole root is staged.
set -euo pipefail
umask 022

# NAME DESTINATION [ram]. `ram` also lists the program and its libraries in
# usr/lib/zboot/ram-boot.files: `zboot boot --tar` copies those into the
# initramfs it builds around a root tar.
programs=(
    'udevd /usr/lib/systemd/systemd-udevd'
    'udevadm /usr/bin/udevadm'
    'ata-id /usr/lib/udev/ata_id'
    'scsi-id /usr/lib/udev/scsi_id'
    'busybox /bin/busybox ram'
    'zfs /sbin/zfs'
    'zpool /sbin/zpool'
    'zdb /sbin/zdb'
    'signature-probe /sbin/zboot-probe-signatures'
    # restore relinks encryption keys through the host's libzfs_core.
    'change-key /sbin/zboot-change-key'
    'mount-zfs /sbin/mount.zfs'
    'kexec /sbin/kexec'
    'kmod /sbin/kmod'
    'lsblk /bin/lsblk'
    'findmnt /bin/findmnt'
    'losetup /usr/sbin/losetup'
    'sfdisk /sbin/sfdisk'
    'sgdisk /sbin/sgdisk'
    'wipefs /sbin/wipefs'
    # wipe sanitizes NVMe through nvme-cli.
    'nvme /sbin/nvme'
    'partprobe /sbin/partprobe'
    'mkfs-vfat /sbin/mkfs.vfat'
    'blkid /sbin/blkid'
    'tar /bin/tar ram'
    'zstd /bin/zstd ram'
    'sshd /usr/sbin/sshd'
    'sshd-auth /usr/lib/openssh/sshd-auth'
    'sshd-session /usr/lib/openssh/sshd-session'
    'ssh-keygen /usr/bin/ssh-keygen'
    'ip /bin/ip'
)
names=()
declare -A destination=() ram=() given=()
for row in "${programs[@]}"; do
    read -r name path flag <<< "$row"
    names+=("$name")
    destination[$name]=$path
    ram[$name]=$flag
done

udev_rules='' firmware_root='' modules='' output=''
firmware_files=()
firmware_sources=()
while (( $# )); do
    case "$1" in
        --help)
            printf 'usage: stage-runtime.sh'
            printf ' --%s FILE' "${names[@]}"
            printf ' --udev-rules DIR --firmware-root DIR --firmware RELATIVE... --module-dir DIR --output NEW_DIRECTORY\n'
            exit 0 ;;
        --udev-rules) udev_rules=$2 ;;
        --firmware-root) firmware_root=$2 ;;
        --firmware) firmware_files+=("$2") ;;
        --module-dir) modules=$2 ;;
        --output) output=$2 ;;
        --?*)
            name=${1#--}
            [[ -n "${destination[$name]+known}" ]] || { echo "unknown argument: $1" >&2; exit 2; }
            given[$name]=$2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift 2
done
[[ -n "$output" && "$output" == /* && ! -e "$output" && ! -L "$output" ]] || { echo 'output must be a new absolute directory' >&2; exit 2; }
for name in "${names[@]}"; do
    file=${given[$name]-}
    [[ -f "$file" && -x "$file" ]] || { echo "required trusted executable missing: --$name $file" >&2; exit 2; }
done
[[ -n "$firmware_root" && -d "$firmware_root" ]] || { echo 'firmware root directory is required' >&2; exit 2; }
firmware_root=$(realpath -e -- "$firmware_root")
(( ${#firmware_files[@]} )) || { echo 'at least one --firmware selection is required' >&2; exit 2; }
for firmware in "${firmware_files[@]}"; do
    # Names are kernel lookup paths relative to /lib/firmware. Reject traversal
    # and ambiguous components before resolving packaged symlinks.
    [[ "$firmware" =~ ^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$ && "/$firmware/" != */./* && "/$firmware/" != */../* ]] || { echo "unsafe firmware path: $firmware" >&2; exit 2; }
    source=$(realpath -e -- "$firmware_root/$firmware") || { echo "required firmware missing: $firmware" >&2; exit 2; }
    [[ "$source" == "${firmware_root%/}/"* && -f "$source" && -s "$source" ]] || { echo "firmware must be a nonempty file within firmware root: $firmware" >&2; exit 2; }
    firmware_sources+=("$source")
done
for rule in 60-block.rules 60-persistent-storage.rules; do
    [[ -n "$udev_rules" && -f "$udev_rules/$rule" && -s "$udev_rules/$rule" ]] || { echo "required packaged udev rule missing: $udev_rules/$rule" >&2; exit 2; }
done
[[ -d "$modules" && -s "$modules/modules.dep" ]] || { echo 'module tree with modules.dep is required' >&2; exit 2; }
release=$(basename -- "$modules")
[[ "$release" =~ ^[A-Za-z0-9._+-]+$ ]] || { echo 'invalid kernel release' >&2; exit 2; }

# Stage beside the output, on its filesystem, and publish by rename.
stage=$(mktemp -d -- "$output.partial.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
chmod 0755 -- "$stage"
mkdir -p "$stage/bin" "$stage/sbin" "$stage/usr/share/zfs-tools" "$stage/usr/lib/zboot" "$stage/lib/modules"
manifest=$stage/usr/share/zfs-tools/runtime-sources.sha256
ram_boot_files=$stage/usr/lib/zboot/ram-boot.files
: > "$manifest"
: > "$ram_boot_files"
copy_file() {
    local source=$1 destination=$2
    mkdir -p -- "$(dirname -- "$stage$destination")"
    cp --dereference -- "$source" "$stage$destination"
    sha256sum -- "$source" >> "$manifest"
}
copy_program() { # SOURCE DESTINATION [LIST]: LIST also gets both paths
    local source=$1 destination=$2 list=${3:-/dev/null} deps library
    copy_file "$source" "$destination"
    printf '%s\n' "$destination" >> "$list"
    if readelf -l "$source" | grep -q INTERP; then
        deps=$(ldd "$source")
        [[ "$deps" != *'not found'* ]] || { echo "$deps" >&2; exit 1; }
        while IFS= read -r library; do
            [[ "$library" == /lib/* || "$library" == /lib64/* || "$library" == /usr/lib/* ]] || { echo "dependency outside supported loader paths: $library" >&2; exit 1; }
            copy_file "$library" "$library"
            printf '%s\n' "$library" >> "$list"
        done < <(printf '%s\n' "$deps" | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }')
    fi
}
for name in "${names[@]}"; do
    copy_program "${given[$name]}" "${destination[$name]}" ${ram[$name]:+"$ram_boot_files"}
done
LC_ALL=C sort -u -o "$ram_boot_files" "$ram_boot_files"
# Use the substrate's packaged storage rules unchanged. The generic drivers
# rule would load every hardware modalias, beyond the menu's explicit drivers.
for rule in 60-block.rules 60-persistent-storage.rules; do
    copy_file "$udev_rules/$rule" "/usr/lib/udev/rules.d/$rule"
done
for index in "${!firmware_files[@]}"; do
    copy_file "${firmware_sources[$index]}" "/lib/firmware/${firmware_files[$index]}"
done
for applet in dd sh mount umount mkdir sleep cat ls mdev reboot poweroff chroot mknod chmod cp sync sha256sum awk rm touch switch_root mkpasswd udhcpc; do
    # Consume the entire list: grep -q can close the pipe early and turn a
    # successful match into a producer SIGPIPE under pipefail.
    "${given[busybox]}" --list | grep -x "$applet" >/dev/null || { echo "busybox lacks $applet" >&2; exit 1; }
    # DHCP is invoked explicitly as `busybox udhcpc`.
    [[ "$applet" == udhcpc ]] || ln -s busybox "$stage/bin/$applet"
done
ln -s kmod "$stage/sbin/modprobe"
ln -s ../bin/busybox "$stage/sbin/mdev"
ln -s ../bin/busybox "$stage/sbin/switch_root"
tree=$stage/lib/modules/$release
cp -a -- "$modules" "$tree"
# Not runtime inputs: the header/build links escape the module tree, and the
# menu loads modules and kexecs installed kernels, never this kernel's image.
for link in build source; do
    [[ ! -L "$tree/$link" ]] || rm -- "$tree/$link"
done
rm -f -- "$tree/vmlinuz" "$tree/System.map" "$tree/config"
mv -T -- "$stage" "$output"
