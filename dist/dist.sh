#!/bin/bash
# Build the zboot UKI, the zboot package and the matching source archive from
# dist/build.lock, rootless:
#
#   dist/dist.sh OUT
#
# docs/BUILD.md owns the prerequisites, the build steps and the table of outputs.
# `outer` runs as the invoking user: it copies the source, names the build by
# that copy's digest and starts one private mmdebstrap --mode=unshare root at
# the lock's snapshot under $TMPDIR. `--inner` is the half that runs inside
# that root, as its root, and writes /out, which becomes OUT.
set -euo pipefail
umask 022

log() { printf 'dist: %s\n' "$*" >&2; }
fail() { log "$*"; exit 1; }
lock_field() { awk -v key="$1" '$1 == key { $1 = ""; sub(/^ /, ""); print; exit }' "$lock"; }
lock_set() { awk -v name="$1" '$1 == "set" && $2 == name { $1 = $2 = ""; sub(/^ +/, ""); print; exit }' "$lock"; }
plain() { [[ "$1" =~ ^/[A-Za-z0-9/._+-]+$ ]]; }

outer() {
    local out=$1 repo work source partial variant packages snapshot epoch sha mirror jobs=${ZBOOT_JOBS:-8}
    local time commit inputs=(Cargo.toml Cargo.lock crates dist LICENSE docs/BUILD.md)
    [[ "$out" == /* ]] || out=$PWD/$out
    plain "$out" || fail "OUT must be a plain absolute path: $out"
    [[ ! -e "$out" && ! -L "$out" && ! -e "$out.partial" ]] || fail "$out (or $out.partial) already exists"
    [[ "$jobs" =~ ^[1-9][0-9]?$ ]] || fail 'ZBOOT_JOBS must be 1 to 99'
    repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    lock=$repo/dist/build.lock
    [[ $(lock_field zboot-build-lock) == 6 ]] || fail 'build.lock must be zboot-build-lock 6'
    read -r variant packages <<< "$(lock_set uki)"
    [[ -n "$variant" && -n "$packages" ]] || fail 'build.lock has no set uki'
    snapshot=$(lock_field snapshot)
    [[ "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail 'build.lock snapshot must be YYYYMMDDTHHMMSSZ'
    epoch=$(date -u -d "${snapshot:0:4}-${snapshot:4:2}-${snapshot:6:2} ${snapshot:9:2}:${snapshot:11:2}:${snapshot:13:2}" +%s)
    mirror=https://snapshot.debian.org/archive/debian/$snapshot
    command -v mmdebstrap > /dev/null || fail 'mmdebstrap is required'

    work=$(mktemp -d -p "${TMPDIR:-/var/tmp}" zboot-uki.XXXXXX)
    plain "$work" || { rmdir -- "$work"; fail "work directory must be a plain path: $work"; }
    # shellcheck disable=SC2064 # the plain path, fixed now
    trap "rm -rf -- '$work'" EXIT
    chmod 0755 "$work"
    local ancestor=$work
    while [[ "$ancestor" != / ]]; do
        [[ $(( 8#$(stat -c %a "$ancestor") & 1 )) == 1 ]] ||
            fail "$ancestor is not searchable by others, so the namespace cannot reach the root; set TMPDIR"
        ancestor=$(dirname -- "$ancestor")
    done

    # A private copy of the source; its digest names every binary built.
    source=$work/source
    mkdir -m 0700 "$source"
    tar -C "$repo" --exclude=target --exclude=__pycache__ -cf - "${inputs[@]}" | tar -C "$source" -xf -
    # The package version leads with the UTC time the inputs were last
    # committed, so later builds sort later. A tree outside Git, such as the
    # project copy in corresponding-source.tar.zst, carries it in
    # dist/source-time. The digest leaves that file out: it identifies the
    # content, so the same source has one digest whatever history built it.
    if [[ -e "$source/dist/source-time" ]]; then
        time=$(< "$source/dist/source-time")
    else
        [[ "$(git -C "$repo" rev-parse --show-toplevel 2> /dev/null)" == "$(cd -- "$repo" && pwd -P)" ]] ||
            fail "$repo is not a Git checkout and has no dist/source-time (YYYYMMDDHHMMSS, UTC)"
        [[ "$(git -C "$repo" rev-parse --is-shallow-repository)" == false ]] ||
            fail 'a shallow clone cannot date the inputs; fetch the full history'
        commit=$(git -C "$repo" log -1 --format=%ct -- "${inputs[@]}")
        [[ "$commit" =~ ^[0-9]+$ ]] || fail 'no commit contains the inputs'
        [[ -z "$(git -C "$repo" status --porcelain -- "${inputs[@]}")" ]] ||
            log 'the inputs have uncommitted changes; the version carries their last commit time'
        time=$(date -u -d "@$commit" +%Y%m%d%H%M%S)
        printf '%s\n' "$time" > "$source/dist/source-time"
    fi
    [[ "$time" =~ ^[0-9]{14}$ ]] || fail 'dist/source-time must be YYYYMMDDHHMMSS (UTC)'
    sha=$(cd "$source" && find . -type f ! -path ./dist/source-time -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
    log "source $sha of $time, $(wc -w <<< "$packages") requested packages from $mirror"

    partial=$out.partial
    # The namespace's root runs the inner half in the root; the special hooks
    # copy the source in and OUT back as the invoking user.
    TMPDIR=$work SOURCE_DATE_EPOCH=$epoch mmdebstrap --mode=unshare --variant="$variant" --format=null \
        --components="$(lock_field components | tr ' ' ,)" \
        --include="$(tr ' ' , <<< "$packages")" \
        --aptopt='Acquire::Languages "none"' \
        --aptopt='Acquire::Check-Valid-Until "false"' \
        --aptopt='APT::Install-Recommends "false"' \
        --dpkgopt='force-unsafe-io' \
        --essential-hook="mkdir -p \"\$1/etc/dkms/framework.conf.d\" && printf 'parallel_jobs=$jobs\\nsign_file=/nonexistent/zboot-uki-unsigned\\n' > \"\$1/etc/dkms/framework.conf.d/zboot-uki.conf\"" \
        --customize-hook='rm -f "$1/etc/resolv.conf" && cp -L /etc/resolv.conf "$1/etc/resolv.conf"' \
        --customize-hook='mkdir -p "$1/src" "$1/out" "$1/work"' \
        --customize-hook="sync-in $source /src" \
        --customize-hook="/usr/sbin/chroot \"\$1\" /usr/bin/env -i PATH=/opt/rust/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C.UTF-8 TZ=UTC SOURCE_DATE_EPOCH=$epoch ZBOOT_SOURCE_SHA256=$sha ZBOOT_MIRROR=$mirror ZBOOT_JOBS=$jobs /bin/bash /src/dist/dist.sh --inner" \
        --customize-hook="sync-out /out $partial" \
        "$(lock_field suite)" /dev/null "$mirror" || {
        rm -rf -- "$partial"
        fail 'mmdebstrap failed'
    }
    chmod -R u+rwX,go+rX,go-w "$partial"
    for path in usr/bin/zboot usr/bin/zsnap usr/sbin/zboot-probe-signatures \
        usr/sbin/zboot-change-key usr/lib/zboot/zboot.efi usr/lib/tmpfiles.d/zfs-tools.conf vmlinuz; do
        [[ -f "$partial/$path" ]] || { rm -rf -- "$partial"; fail "the build left no $path"; }
    done
    mv -T -- "$partial" "$out"
    ls -l "$out"/zboot_*_amd64.deb "$out/usr/lib/zboot/zboot.efi" >&2
    printf '%s\n' "$out"
}

# Inside the root, as its root: /src (the source copy), /work (scratch, and
# every helper's TMPDIR) and /out (copied to OUT).
inner() {
    lock=/src/dist/build.lock
    local jobs=$ZBOOT_JOBS release version component file sha root tree name section size need time package
    local -a firmware_args=()
    export CARGO_BUILD_JOBS=$jobs MAKEFLAGS=-j$jobs TMPDIR=/work
    release=$(lock_field kernel)
    time=$(< /src/dist/source-time)

    # Each component is checked against the digest rust-lang publishes beside it.
    log "installing Rust $(lock_field rust)"
    mkdir -p /work/rust
    for component in rustc cargo rust-std; do
        file=$component-$(lock_field rust)-x86_64-unknown-linux-gnu.tar.xz
        curl --fail --silent --show-error --location --retry 3 -o "/work/rust/$file" "https://static.rust-lang.org/dist/$file"
        sha=$(curl --fail --silent --show-error --location --retry 3 "https://static.rust-lang.org/dist/$file.sha256" | cut -d' ' -f1)
        [[ "$(sha256sum < "/work/rust/$file" | cut -d' ' -f1)" == "$sha" ]] || fail "$file digest mismatch"
        tar -xJf "/work/rust/$file" -C /work/rust
        rm "/work/rust/$file"
    done
    for component in /work/rust/*/; do
        "$component/install.sh" --prefix=/opt/rust --disable-ldconfig > /dev/null
    done
    rm -rf /work/rust
    rustc --version >&2

    # The locked kernel and a ZFS module for it.
    [[ "$(ls /usr/lib/modules)" == "$release" && -f "/boot/vmlinuz-$release" ]] ||
        fail "the root's kernel is not the locked $release: $(ls /usr/lib/modules)"
    depmod -a "$release"
    if ! modinfo -k "$release" -F vermagic zfs > /dev/null 2>&1; then
        dkms autoinstall -k "$release"
        depmod -a "$release"
    fi
    modinfo -k "$release" -F vermagic zfs > /dev/null || fail "no ZFS module for $release"

    awk '$1 == "firmware" && NF != 2 { bad=1 } END { exit bad }' "$lock" || fail 'firmware rows require one relative path'
    # Firmware packages are in set uki; paths select only files to distribute.
    while read -r file; do
        [[ -z "$file" ]] || firmware_args+=(--firmware "$file")
    done < <(awk '$1 == "firmware" { print $2 }' "$lock")
    (( ${#firmware_args[@]} > 0 )) || fail 'build.lock has no firmware selections'

    log 'fetching locked Rust dependencies'
    mkdir -p /work/cargo-home
    export CARGO_HOME=/work/cargo-home
    cargo fetch --locked --manifest-path /src/Cargo.toml > /dev/null

    log 'building dynamically linked native helpers'
    CARGO_ENCODED_RUSTFLAGS=$(printf '%s\x1f%s\x1f%s\x1f%s' -C target-feature=-crt-static \
        --remap-path-prefix=/src=/zfs-assembly --remap-path-prefix=/work/cargo-home=/cargo-home) \
        CARGO_TARGET_DIR=/work/target \
        cargo build --locked --offline --release --target x86_64-unknown-linux-gnu \
        --manifest-path /src/Cargo.toml -p zboot-helpers --bins
    for name in zboot-probe-signatures zboot-change-key; do
        file=/work/target/x86_64-unknown-linux-gnu/release/$name
        [[ "$(readelf -l "$file")" == *INTERP* ]] || fail "$name must be dynamically linked"
        install -m 0755 "$file" "/work/$name"
    done

    log 'staging the runtime'
    # The staged runtime is the initramfs root the later steps complete.
    root=/work/initramfs
    # Programs come from their fixed Debian paths in this root; the two
    # helpers were installed into /work above.
    bash /src/dist/initramfs/stage-runtime.sh --root / --helpers-dir /work \
        "${firmware_args[@]}" --module-dir "/lib/modules/$release" --output "$root"

    log 'collecting release notices and matching Debian source packages'
    # Only this private build root is changed. Binary and source indices use
    # the same signed snapshot and components.
    printf 'deb-src %s %s %s\n' "$ZBOOT_MIRROR" "$(lock_field suite)" "$(lock_field components)" > /etc/apt/sources.list.d/zboot-sources.list
    apt-get update > /dev/null
    mkdir -p /work/release-source
    python3 /src/dist/licences/collect-debian.py --output /work/debian-licences \
        --files-from "$root/usr/share/zfs-tools/runtime-sources.sha256" \
        --allow-unowned /work/zboot-probe-signatures \
        --allow-unowned /work/zboot-change-key \
        --file "/boot/vmlinuz-$release" \
        --file /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
        --file /usr/lib/x86_64-linux-gnu/libc.a --file /usr/lib/x86_64-linux-gnu/crt1.o \
        --file "$(gcc -print-libgcc-file-name)" \
        --package zfs-dkms --package libc6-dev --package "linux-headers-$release" \
        --source-output /work/release-source/debian
    python3 /src/dist/licences/collect-rust.py --manifest /src/Cargo.toml \
        --sysroot /opt/rust --output /work/rust-licences
    # The project source is the build's own copy; Debian archives above
    # retain all base sources.
    mkdir /work/release-source/project
    cp -a /src/. /work/release-source/project/
    mkdir -p /work/release-source/project/.cargo /work/release-source/kernel
    cp "/boot/config-$release" /work/release-source/kernel/config
    cargo vendor --locked --offline --manifest-path /src/Cargo.toml \
        /work/release-source/cargo-vendor > /work/vendor-config.toml
    # Vendor paths in the release are relative, never build-root paths.
    sed 's|/work/release-source/cargo-vendor|../cargo-vendor|' /work/vendor-config.toml \
        > /work/release-source/project/.cargo/config.toml

    log 'building zboot and zsnap'
    # CARGO_ENCODED_RUSTFLAGS separates flags with 0x1f.
    CARGO_ENCODED_RUSTFLAGS=$(printf '%s\x1f%s\x1f%s\x1f%s' -C target-feature=+crt-static \
        --remap-path-prefix=/src=/zfs-assembly --remap-path-prefix=/work/cargo-home=/cargo-home) \
        CARGO_TARGET_DIR=/work/target ZBOOT_SOURCE_SHA256=$ZBOOT_SOURCE_SHA256 ZBOOT_SOURCE_TIME=$time \
        cargo build --locked --offline --release --target x86_64-unknown-linux-gnu \
        --manifest-path /src/Cargo.toml -p zboot -p zsnap
    for name in zboot zsnap; do
        file=/work/target/x86_64-unknown-linux-gnu/release/$name
        [[ "$(readelf -l "$file")" != *INTERP* ]] || fail "$name is dynamically linked; it must be static"
    done

    log 'assembling the initramfs'
    tree=$root/lib/modules/$release
    [[ -s "$tree/modules.dep" && -n "$(find "$tree" -name 'zfs.ko*' -print -quit)" ]] ||
        fail 'the module tree lacks modules.dep or zfs.ko'
    for name in zboot zsnap; do
        install -D -m 0755 "/work/target/x86_64-unknown-linux-gnu/release/$name" "$root/usr/bin/$name"
    done
    mkdir -p "$root/usr/share/doc/zboot/LICENCES"
    cp -a /work/debian-licences "$root/usr/share/doc/zboot/LICENCES/debian"
    cp -a /work/rust-licences "$root/usr/share/doc/zboot/LICENCES/rust"
    cp /src/LICENSE "$root/usr/share/doc/zboot/copyright"
    install -m 0755 /src/dist/initramfs/init.sh "$root/init"
    install -D -m 0755 /src/dist/initramfs/console.sh "$root/usr/lib/zboot/console.sh"
    install -m 0755 /src/dist/initramfs/menu-dhcp.sh "$root/usr/lib/zboot/menu-dhcp.sh"
    # The Menu's SSH stack is inert until an explicit `connect` action. Its
    # only account has no usable password hash and no host key is baked.
    mkdir -p "$root/etc/ssh" "$root/proc" "$root/sys" "$root/dev" "$root/run"
    mkdir -m 0700 "$root/root"
    printf 'root:x:0:0:root:/root:/bin/sh\nsshd:x:74:74:sshd:/run/sshd:/bin/sh\n' > "$root/etc/passwd"
    printf 'root:x:0:\nsshd:x:74:\n' > "$root/etc/group"
    printf 'root:NP:0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n' > "$root/etc/shadow"
    chmod 0600 "$root/etc/shadow"
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > "$root/etc/nsswitch.conf"
    find "$root" -exec touch -h -d @0 {} +
    (cd "$root" && find . -print0 | LC_ALL=C sort -z |
        cpio --null --create --format=newc --reproducible --owner=0:0 --quiet) > /work/initrd.cpio
    zstd -q -T2 -6 /work/initrd.cpio -o /work/initrd.img.zst
    rm /work/initrd.cpio

    log 'building the UKI'
    version=$("$root/usr/bin/zboot" --version)
    [[ "$version" =~ ^zboot\ ([0-9][0-9A-Za-z.~-]*)\ \(source\ ([0-9a-f]{12})\)$ ]] ||
        fail "unexpected zboot --version: $version"
    local crate=${BASH_REMATCH[1]} short=${BASH_REMATCH[2]}
    [[ "$short" == "${ZBOOT_SOURCE_SHA256:0:12}" ]] || fail 'zboot does not carry this source digest'
    # `zboot factory` repackages itself at the version it carries.
    package=$crate+git$time.$short
    grep -qaF -- "$package" "$root/usr/bin/zboot" || fail "zboot does not carry the package version $package"
    printf '%s\n' 'zboot.recovery=1 console=ttyS0,115200n8 console=tty0 quiet loglevel=3 fbcon=font:TER16x32' > /work/cmdline
    printf 'ID=zboot\nNAME="zboot"\nVERSION_ID="%s"\n' "$crate" > /work/os-release
    /usr/bin/ukify build --config=/dev/null --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
        --linux "/boot/vmlinuz-$release" --initrd /work/initrd.img.zst \
        --cmdline=@/work/cmdline --os-release=@/work/os-release --uname "$release" \
        --no-sign-kernel --output /work/zboot.efi
    # Each payload reads back as itself, padded with zeros to its section.
    for section in linux:"/boot/vmlinuz-$release" initrd:/work/initrd.img.zst; do
        name=${section%%:*} file=${section#*:}
        objcopy --dump-section ".$name=/work/readback.$name" /work/zboot.efi /work/readback.efi
        rm /work/readback.efi
        size=$(stat -c %s "$file")
        cmp -s -n "$size" "$file" "/work/readback.$name" &&
            [[ $(tail -c +$(( size + 1 )) "/work/readback.$name" | tr -d '\0' | wc -c) == 0 ]] ||
            fail "the UKI's .$name is not the input"
        rm "/work/readback.$name"
    done

    log 'writing OUT'
    mkdir -p /out/usr/bin /out/usr/sbin /out/usr/lib/zboot /out/usr/lib/tmpfiles.d
    for name in zboot zsnap; do
        cp -- "$root/usr/bin/$name" "/out/usr/bin/$name"
        chmod 0755 "/out/usr/bin/$name"
        cmp -s "$root/usr/bin/$name" "/out/usr/bin/$name" || fail "$name changed while written"
    done
    # An installed zboot verifies an erase with the probe the UKI carries,
    # and restore relinks encryption keys with its change-key helper. They
    # are the package's two dynamic programs: dist/deb/control names the
    # libc6 they may need, and zfsutils-linux brings the helper's
    # libzfs_core.so.3.
    for name in zboot-probe-signatures zboot-change-key; do
        need=$(objdump -T "/work/$name" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1)
        [[ $(printf '%s\n' "$need" GLIBC_2.34 | sort -V | tail -n 1) == GLIBC_2.34 ]] ||
            fail "$name needs $need, newer than the package's libc6 (>= 2.34)"
        install -m 0755 "/work/$name" "/out/usr/sbin/$name"
        cmp -s "/work/$name" "$root/sbin/$name" ||
            fail "the packaged $name is not the one in the UKI"
    done
    install -m 0644 /work/zboot.efi /out/usr/lib/zboot/zboot.efi
    mkdir -p /out/usr/share/doc
    cp -a "$root/usr/share/doc/zboot" /out/usr/share/doc/
    # Sources accompany releases, never inflate the boot image or Git tree.
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C /work/release-source -cf - . | zstd -q -T2 -6 -o /out/corresponding-source.tar.zst
    cp /work/debian-licences/components.json /out/components.json
    printf 'd /run/zfs-tools 0755 root root -\nf /run/zfs-tools/writer.lock 0644 root root -\n' \
        > /out/usr/lib/tmpfiles.d/zfs-tools.conf
    chmod 0644 /out/usr/lib/tmpfiles.d/zfs-tools.conf
    install -m 0644 "/boot/vmlinuz-$release" /out/vmlinuz
    # The package `zboot` is OUT/usr, at the version `zboot factory` gives it.
    mkdir -p /work/package/DEBIAN
    cp -a /out/usr /work/package/usr
    { cat /src/dist/deb/control; printf 'Version: %s\n' "$package"; } > /work/package/DEBIAN/control
    install -m 0755 /src/dist/deb/preinst /work/package/DEBIAN/preinst
    find /work/package -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    dpkg-deb --root-owner-group --build /work/package "/out/zboot_${package}_amd64.deb" >&2
    (cd /out && sha256sum corresponding-source.tar.zst components.json zboot_*.deb usr/lib/zboot/zboot.efi > SHA256SUMS)
    log "built zboot $package for $release"
}

case "${1:-}" in
    --inner) [[ $# == 1 ]] || exit 2; inner ;;
    ''|-*) echo 'usage: dist/dist.sh OUT' >&2; exit 2 ;;
    *) [[ $# == 1 ]] || { echo 'usage: dist/dist.sh OUT' >&2; exit 2; }; outer "$1" ;;
esac
