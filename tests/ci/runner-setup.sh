#!/bin/bash
# This script is exclusively for disposable GitHub-hosted Ubuntu runners.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
    echo 'runner-setup: only disposable GitHub-hosted runners are supported' >&2; exit 1;
}
case ${1:-} in
    build|vm|offline) kind=$1 ;;
    *) echo 'usage: runner-setup.sh build|vm|offline' >&2; exit 2 ;;
esac
# Try distribution/factory on the ordinary image using measured growth plus
# headroom. Keep VM/offline cleanup until their storage is measured.
# Remove only named preinstalled SDKs in these disposable jobs.
if [[ $kind != build ]]; then
    sudo rm -rf -- /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup /opt/hostedtoolcache/CodeQL
fi
sudo apt-get update
common=(zstd cpio binutils busybox-static libblkid-dev zfsutils-linux)
case $kind in
    build)
        sudo apt-get install -y --no-install-recommends mmdebstrap uidmap debian-archive-keyring "${common[@]}"
        # Debian's 2025 signing keys are absent from Ubuntu 24.04's old
        # keyring. Identity comes from the native Debian signed apt metadata
        # inspected on 2026-11-15: debian-archive-keyring 2025.1, 179244 bytes.
        keyring_deb=$RUNNER_TEMP/debian-archive-keyring_2025.1_all.deb
        curl --fail --location --retry 3 --output "$keyring_deb" \
            https://deb.debian.org/debian/pool/main/d/debian-archive-keyring/debian-archive-keyring_2025.1_all.deb
        printf '%s  %s\n' 9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac "$keyring_deb" | sha256sum --check
        sudo dpkg -i "$keyring_deb"
        sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
        unshare -Ur true
        # Ubuntu supplies Debian's archive keyring; mmdebstrap searches apt's
        # trusted keyring directory. Keep signature verification enabled.
        sudo install -m 0644 /usr/share/keyrings/debian-archive-keyring.gpg /etc/apt/trusted.gpg.d/zfs-tools-debian.gpg
        ;;
    vm)
        sudo apt-get install -y --no-install-recommends "${common[@]}" qemu-system-x86 ovmf mtools fdisk dosfstools attr jq nvme-cli acl
        [[ -c /dev/kvm ]] || { echo 'BLOCKED: /dev/kvm is absent' >&2; exit 1; }
        # QEMU/udev can recreate this node across a power-cut case. Preserve
        # access for the ordinary runner user throughout all guest boots.
        echo 'KERNEL=="kvm", MODE="0666"' | sudo tee /etc/udev/rules.d/99-zfs-tools-ci-kvm.rules
        sudo udevadm control --reload-rules
        sudo udevadm trigger --name-match=kvm
        sudo chmod 0666 /dev/kvm
        [[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'BLOCKED: KVM is inaccessible' >&2; exit 1; }
        ;;
    offline) sudo apt-get install -y --no-install-recommends "${common[@]}" ;;
esac
df -h /
free -h
