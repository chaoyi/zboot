#!/usr/bin/env bash
# Internal helper for tests/acceptance/run.py prepare: a runtime
# initrd plus tests/acceptance/guest/init.sh as /init, the zboot/zsnap under
# test, a few host tools and, optionally, bulk fixtures on a separate
# directory. Scenario setup and assertions belong to the tests; this image is
# a development fixture, never product EFI proof.
set -euo pipefail
base='' acceptance='' jq='' zboot='' zsnap='' setfattr='' getfattr='' zvol_id='' fixture_busybox='' mkfs_vfat='' nvme='' flock='' esp_artifacts='' factory_image='' fixture_directory='' output=''
fault_tools=()
while (( $# )); do
    case "$1" in
        --base-initrd) base=$2; shift 2 ;;
        --acceptance) acceptance=$2; shift 2 ;;
        --jq) jq=$2; shift 2 ;;
        --fault-tool) fault_tools+=("$2"); shift 2 ;;
        --zboot) zboot=$2; shift 2 ;;
        --zsnap) zsnap=$2; shift 2 ;;
        --fixture-busybox) fixture_busybox=$2; shift 2 ;;
        --factory-image) factory_image=$2; shift 2 ;;
        --fixture-directory) fixture_directory=$2; shift 2 ;;
        --esp-artifacts) esp_artifacts=$2; shift 2 ;;
        --nvme) nvme=$2; shift 2 ;;
        --flock) flock=$2; shift 2 ;;
        --mkfs-vfat) mkfs_vfat=$2; shift 2 ;;
        --zvol-id) zvol_id=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        --setfattr) setfattr=$2; shift 2 ;;
        --getfattr) getfattr=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -z "$base" || -z "$acceptance" || -z "$output" ]]; then
    echo 'usage: build-initrd.sh --base-initrd FILE --acceptance DIR [--jq FILE] [--fault-tool zfs] [--zboot FILE] [--zsnap FILE] [host tools] [bulk fixtures --fixture-directory DIR] --output "$TMPDIR/FILE"' >&2
    exit 2
fi
temporary_root=$(realpath -e -- "${TMPDIR:-/var/tmp}")
[[ -d "$temporary_root" ]] || { echo 'TMPDIR must be an existing directory' >&2; exit 2; }
output=$(realpath -m -- "$output")
[[ "$output" == "$temporary_root/"* && ! -e "$output" && ! -L "$output" && ! -e "$output.provenance" && ! -L "$output.provenance" ]] || { echo 'output and provenance must be new files under TMPDIR (default /var/tmp)' >&2; exit 2; }
for source in "$base" "$acceptance/init.sh" ${jq:+"$jq"} ${zboot:+"$zboot"} ${zsnap:+"$zsnap"} ${setfattr:+"$setfattr"} ${getfattr:+"$getfattr"} ${zvol_id:+"$zvol_id"} ${fixture_busybox:+"$fixture_busybox"} ${mkfs_vfat:+"$mkfs_vfat"} ${nvme:+"$nvme"} ${flock:+"$flock"}; do
    [[ -f "$source" ]] || { echo "not a regular input file: $source" >&2; exit 2; }
done
if [[ -n "$fixture_directory" ]]; then
    fixture_directory=$(realpath -m -- "$fixture_directory")
    [[ "$fixture_directory" == "$temporary_root/"* && ! -e "$fixture_directory" && ! -L "$fixture_directory" ]] || { echo 'fixture directory must be a new directory under TMPDIR (default /var/tmp)' >&2; exit 2; }
    [[ -n "$esp_artifacts$factory_image" ]] || { echo 'fixture directory requires bulk fixture inputs' >&2; exit 2; }
elif [[ -n "$esp_artifacts$factory_image" ]]; then
    echo 'bulk fixture inputs require --fixture-directory' >&2; exit 2
fi
stage=$(mktemp -d -p "$temporary_root" zboot-acceptance-initrd.XXXXXX)
fixture_created=false
fixture_published=false
cleanup() {
    rm -rf -- "$stage"
    if "$fixture_created" && ! "$fixture_published"; then rm -rf -- "$fixture_directory"; fi
}
trap cleanup EXIT
mkdir "$stage/root"
: > "$stage/input-sha256.txt"
# record_input FILE LABEL: one provenance line, FILE's digest under LABEL.
record_input() {
    printf '%s  %s\n' "$(sha256sum -- "$1" | cut -d ' ' -f 1)" "$2" >> "$stage/input-sha256.txt"
}
zstd -dc -- "$base" | (cd "$stage/root"; cpio -idm --no-absolute-filenames --quiet)
# Signature erasure and probing must use the same pinned runtime/libblkid.
# Older host wipefs versions can leave signatures the runtime recognizes.
[[ -f "$stage/root/sbin/wipefs" && -x "$stage/root/sbin/wipefs" ]] || { echo 'runtime needs executable /sbin/wipefs' >&2; exit 1; }
record_input "$stage/root/sbin/wipefs" 'runtime:/sbin/wipefs'
[[ ! -e "$stage/root/e2e-host-tools" && ! -L "$stage/root/e2e-host-tools" ]] || { echo 'runtime uses reserved fixture namespace' >&2; exit 1; }
mkdir "$stage/root/e2e-host-tools"

safe_parent() {
    local parent
    parent=$(realpath -m -- "$(dirname "$1")")
    [[ "$parent" == "$stage/root" || "$parent" == "$stage/root/"* ]] || {
        echo "staged path escapes image root: $1" >&2; exit 1;
    }
    mkdir -p -- "$parent"
}

install_binary() {
    local source=$1 destination=$2 library deps interpreter isolated libraries loader
    [[ "$destination" =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'unsafe fixture destination' >&2; exit 1; }
    safe_parent "$stage/root$destination"
    isolated="/e2e-host-tools$destination"
    safe_parent "$stage/root$isolated"
    cp --dereference --remove-destination -- "$source" "$stage/root$isolated"
    chmod 0755 "$stage/root$isolated"
    # Host tools must not replace the selected runtime's libc or ELF loader.
    # The two may come from different distributions, including different
    # merged-/usr layouts. Give each dynamic fixture its own dependency closure
    # and invoke its matching loader explicitly from a fixed shell wrapper.
    if readelf -l "$stage/root$isolated" | grep 'INTERP' >/dev/null; then
        [[ "$destination" != /e2e-maintenance-busybox ]] || { echo 'maintenance BusyBox must be static because the fixture copies it into a BE' >&2; exit 2; }
        interpreter=$(readelf -l "$stage/root$isolated" | sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p')
        [[ -f "$interpreter" ]] || { echo 'fixture ELF interpreter missing' >&2; exit 1; }
        libraries="$isolated.libs"
        loader=$(basename "$interpreter")
        [[ "$loader" =~ ^[a-zA-Z0-9_.-]+$ ]] || { echo 'unsafe fixture loader name' >&2; exit 1; }
        mkdir -p "$stage/root$libraries"
        deps=$(ldd "$stage/root$isolated")
        if [[ "$deps" == *'not found'* ]]; then echo "$deps" >&2; exit 1; fi
        while IFS= read -r library; do
            [[ -f "$library" ]] || { echo "missing library: $library" >&2; exit 1; }
            local target
            target="$stage/root$libraries/$(basename "$library")"
            if [[ -e "$target" ]] && ! cmp -s -- "$library" "$target"; then
                echo "conflicting fixture library basename: $library" >&2; exit 1
            fi
            cp --dereference --remove-destination -- "$library" "$target"
            record_input "$target" "$library"
        done < <(printf '%s\n%s\n' "$interpreter" "$deps" | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' | sort -u)
        rm -f -- "$stage/root$destination"
        printf '#!/bin/sh\nexec %s/%s --inhibit-cache --library-path %s %s "$@"\n' \
            "$libraries" "$loader" "$libraries" "$isolated" > "$stage/root$destination"
        record_input "$stage/root$isolated" "$source"
    else
        mv -fT -- "$stage/root$isolated" "$stage/root$destination"
        record_input "$stage/root$destination" "$source"
    fi
    chmod 0755 "$stage/root$destination"
}
# Applets the fixture runs by name that the runtime does not link.
for applet in mdev ln; do
    if [[ -f "$stage/root/bin/busybox" && ! -e "$stage/root/usr/bin/$applet" && ! -L "$stage/root/usr/bin/$applet" ]]; then
        safe_parent "$stage/root/usr/bin/$applet"
        ln -s -- /bin/busybox "$stage/root/usr/bin/$applet"
    fi
done
[[ -z "$jq" ]] || install_binary "$jq" /usr/bin/jq
# guest/init.sh is /init; the rest of guest/ is mounted at /acceptance from a
# read-only share at boot, so case scripts change without a new initrd.
mkdir "$stage/root/acceptance"
install -m 0755 -- "$acceptance/init.sh" "$stage/root/init"
record_input "$stage/root/init" "$acceptance/init.sh"
# Each fault tool keeps its substrate binary at /zt-real/NAME and routes
# every call through fault.sh, which runs it unchanged unless armed.
for tool in "${fault_tools[@]}"; do
    # Only zfs: the product runs it by PATH name. Recovery runs /sbin/zpool
    # by absolute path, which a /usr/bin wrapper would silently miss.
    [[ "$tool" == zfs ]] || { echo "unsupported fault tool: $tool" >&2; exit 2; }
    [[ -f "$stage/root/sbin/$tool" && ! -L "$stage/root/sbin/$tool" ]] || { echo "fault tool needs regular substrate /sbin/$tool" >&2; exit 2; }
    mkdir -p "$stage/root/zt-real"
    cp -- "$stage/root/sbin/$tool" "$stage/root/zt-real/$tool"
    rm -f -- "$stage/root/usr/bin/$tool"
    printf '#!/bin/sh\nexec /acceptance/fault.sh %s /zt-real/%s "$@"\n' "$tool" "$tool" > "$stage/root/usr/bin/$tool"
    chmod 0755 "$stage/root/usr/bin/$tool"
    echo "fixture-fault-tool=$tool" >> "$stage/input-sha256.txt"
done
[[ -z "$zboot" ]] || install_binary "$zboot" /usr/bin/zboot
[[ -z "$zsnap" ]] || install_binary "$zsnap" /usr/bin/zsnap
[[ -z "$zvol_id" ]] || install_binary "$zvol_id" /usr/lib/udev/zvol_id
[[ -z "$setfattr" ]] || install_binary "$setfattr" /usr/bin/setfattr
[[ -z "$getfattr" ]] || install_binary "$getfattr" /usr/bin/getfattr
[[ -z "$fixture_busybox" ]] || install_binary "$fixture_busybox" /e2e-maintenance-busybox
if [[ -n "$mkfs_vfat" ]]; then
    install_binary "$mkfs_vfat" /usr/bin/mkfs.fat
    ln -sf -- mkfs.fat "$stage/root/usr/bin/mkfs.vfat"
fi
[[ -z "$nvme" ]] || install_binary "$nvme" /usr/bin/nvme
[[ -z "$flock" ]] || install_binary "$flock" /usr/bin/flock
# Bulk fixture bytes live outside the kernel-loaded initrd, in a
# development-only directory the runner attaches as a read-only 9p share.
if [[ -n "$fixture_directory" ]]; then
    mkdir -m 0700 -- "$fixture_directory"
    fixture_created=true
fi
if [[ -n "$esp_artifacts" ]]; then
    [[ -d "$esp_artifacts" && ! -L "$esp_artifacts" ]] || { echo 'ESP artifacts must be a real directory' >&2; exit 2; }
    mkdir "$fixture_directory/e2e-esp-artifacts"
    cp -a -- "$esp_artifacts/." "$fixture_directory/e2e-esp-artifacts/"
    (cd "$fixture_directory/e2e-esp-artifacts"; find . -type f -print0 | sort -z | xargs -0 sha256sum) >> "$stage/input-sha256.txt"
fi
# A `zboot factory` root tar, deployed by `zboot deploy --tar`.
if [[ -n "$factory_image" ]]; then
    [[ -f "$factory_image" && ! -L "$factory_image" ]] || { echo 'factory image must be a root tar file' >&2; exit 2; }
    cp -- "$factory_image" "$fixture_directory/e2e-factory.tar.zst"
    record_input "$fixture_directory/e2e-factory.tar.zst" "$factory_image"
fi
if [[ -n "$fixture_directory" ]]; then
    python3 - "$fixture_directory" <<'FIXTURE_MANIFEST'
import hashlib, json, os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
files = []
for directory, dirs, names in os.walk(root, followlinks=False):
    for name in dirs + names:
        path = pathlib.Path(directory) / name
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise SystemExit(f"fixture tree contains symlink or special file: {path}")
    for name in names:
        path = pathlib.Path(directory) / name
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            before = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
            after = os.fstat(handle.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise SystemExit('fixture file changed during manifest hashing')
        files.append({'path': path.relative_to(root).as_posix(), 'bytes': before.st_size, 'sha256': digest.hexdigest()})
with (root / 'manifest.json').open('x') as handle:
    json.dump({'schema_version': 1, 'files': sorted(files, key=lambda entry: entry['path'])}, handle, sort_keys=True, indent=2)
    handle.write('\n')
FIXTURE_MANIFEST
    cp -- "$fixture_directory/manifest.json" "$stage/root/e2e-fixtures.manifest.json"
    printf 'fixture-directory=%s\n' "$fixture_directory" >> "$stage/input-sha256.txt"
    sha256sum -- "$fixture_directory/manifest.json" >> "$stage/input-sha256.txt"
fi
mkdir -p "$stage/root/run/lock"
chmod 0755 "$stage/root" "$stage/root/run" "$stage/root/run/lock"
(cd "$stage/root"; find . -print0 | sort -z | cpio --null -o --format=newc --owner=0:0 --quiet) | zstd -q -T2 -o "$stage/development-initrd.zst"
# Publish only after successful packing; never overwrite an existing artifact.
ln -- "$stage/development-initrd.zst" "$output"
{
    echo 'claim=development-only; supplied fixture runtime substrate; not production EFI'
    sha256sum -- "$base"
    cat "$stage/input-sha256.txt"
    sha256sum -- "$output"
} > "$output.provenance"
fixture_published=true
cat "$output.provenance"
