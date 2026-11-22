#!/usr/bin/env bash
# Populate a new initramfs root from the trusted runtime files of a build root:
#
#   stage-runtime.sh --root DIR --helpers-dir DIR --module-dir DIR
#       --firmware RELATIVE... --output NEW_DIRECTORY
#
# Every program in `programs` is required. Each comes from its fixed Debian
# (usrmerge) path under the root, or from the helpers directory, and goes to
# its fixed destination with its loader closure; ldd runs only on these
# installed executables. usr/share/zfs-tools/runtime-sources.sha256 records
# every source file for the licence collector. NEW_DIRECTORY appears only when
# the whole root is staged.
set -euo pipefail
umask 022

# SOURCE DESTINATION [ram]. SOURCE is under --root, or under --helpers-dir
# when it starts with `helpers/`. `ram` also lists the program and its
# libraries in usr/lib/zboot/ram-boot.files: `zboot boot --tar` copies those
# into the initramfs it builds around a root tar.
programs=(
    '/usr/lib/systemd/systemd-udevd /usr/lib/systemd/systemd-udevd'
    '/usr/bin/udevadm /usr/bin/udevadm'
    '/usr/lib/udev/ata_id /usr/lib/udev/ata_id'
    '/usr/lib/udev/scsi_id /usr/lib/udev/scsi_id'
    '/bin/busybox /bin/busybox ram'
    '/usr/sbin/zfs /sbin/zfs'
    '/usr/sbin/zpool /sbin/zpool'
    '/usr/sbin/zdb /sbin/zdb'
    'helpers/zboot-probe-signatures /sbin/zboot-probe-signatures'
    # restore relinks encryption keys through the host's libzfs_core.
    'helpers/zboot-change-key /sbin/zboot-change-key'
    '/usr/sbin/mount.zfs /sbin/mount.zfs'
    '/usr/sbin/kexec /sbin/kexec'
    '/usr/bin/kmod /sbin/kmod'
    '/usr/bin/lsblk /bin/lsblk'
    '/usr/bin/findmnt /bin/findmnt'
    '/usr/sbin/losetup /usr/sbin/losetup'
    '/usr/sbin/sfdisk /sbin/sfdisk'
    '/usr/sbin/sgdisk /sbin/sgdisk'
    '/usr/sbin/wipefs /sbin/wipefs'
    # wipe sanitizes NVMe through nvme-cli.
    '/usr/sbin/nvme /sbin/nvme'
    '/usr/sbin/partprobe /sbin/partprobe'
    '/usr/sbin/mkfs.vfat /sbin/mkfs.vfat'
    '/usr/sbin/blkid /sbin/blkid'
    '/usr/bin/tar /bin/tar ram'
    '/usr/bin/zstd /bin/zstd ram'
    '/usr/sbin/sshd /usr/sbin/sshd'
    '/usr/lib/openssh/sshd-auth /usr/lib/openssh/sshd-auth'
    '/usr/lib/openssh/sshd-session /usr/lib/openssh/sshd-session'
    '/usr/bin/ssh-keygen /usr/bin/ssh-keygen'
    '/usr/bin/ip /bin/ip'
)

root='' helpers='' modules='' output=''
firmware_files=()
firmware_sources=()
while (( $# )); do
    case "$1" in
        --help)
            echo 'usage: stage-runtime.sh --root DIR --helpers-dir DIR --module-dir DIR --firmware RELATIVE... --output NEW_DIRECTORY'
            exit 0 ;;
        --root) root=$2 ;;
        --helpers-dir) helpers=$2 ;;
        --firmware) firmware_files+=("$2") ;;
        --module-dir) modules=$2 ;;
        --output) output=$2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift 2
done
[[ -n "$output" && "$output" == /* && ! -e "$output" && ! -L "$output" ]] || { echo 'output must be a new absolute directory' >&2; exit 2; }
[[ "$root" == /* && -d "$root" ]] || { echo 'root must be an absolute directory' >&2; exit 2; }
[[ "$helpers" == /* && -d "$helpers" ]] || { echo 'helpers directory must be an absolute directory' >&2; exit 2; }
# "/" stays "" so a root of / names each file by its own absolute path.
root=${root%/} helpers=${helpers%/}
sources=() destinations=() lists=()
for row in "${programs[@]}"; do
    read -r path destination flag <<< "$row"
    if [[ "$path" == helpers/* ]]; then file=$helpers/${path#helpers/}; else file=$root$path; fi
    [[ -f "$file" && -x "$file" ]] || { echo "required trusted executable missing: $file" >&2; exit 2; }
    sources+=("$file")
    destinations+=("$destination")
    lists+=("$flag")
    [[ "$destination" != /bin/busybox ]] || busybox=$file
done
firmware_root=$root/usr/lib/firmware
[[ -d "$firmware_root" ]] || { echo "firmware root directory is required: $firmware_root" >&2; exit 2; }
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
udev_rules=$root/usr/lib/udev/rules.d
for rule in 60-block.rules 60-persistent-storage.rules; do
    [[ -f "$udev_rules/$rule" && -s "$udev_rules/$rule" ]] || { echo "required packaged udev rule missing: $udev_rules/$rule" >&2; exit 2; }
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
for index in "${!sources[@]}"; do
    copy_program "${sources[$index]}" "${destinations[$index]}" ${lists[$index]:+"$ram_boot_files"}
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
    "$busybox" --list | grep -x "$applet" >/dev/null || { echo "busybox lacks $applet" >&2; exit 1; }
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
