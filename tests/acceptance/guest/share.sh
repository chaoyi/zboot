# Bulk fixture share helper for the esp, deploy and efi setup cases.
# POSIX sh (busybox); sourced by case scripts after lib.sh.

# fixtures_mount: mount the read-only zt-fixtures share at /fixtures unless
# lib.sh already did. The mounted manifest must be the one the initrd embeds.
fixtures_mount() {
    if [ ! -f /fixtures/manifest.json ]; then
        found=
        for tag in /sys/bus/virtio/drivers/9pnet_virtio/*/mount_tag; do
            case "$(cat "$tag" 2>/dev/null)" in *zt-fixtures*) found=1 ;; esac
        done
        [ -n "$found" ] || fail 'no zt-fixtures share'
        must fixtures-mkdir mkdir -p /fixtures
        must fixtures-mount mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-fixtures /fixtures
    fi
    must fixtures-manifest sha256sum /fixtures/manifest.json /e2e-fixtures.manifest.json
    set -- $(cat "$ZT_LAST.out")
    [ "$1" = "$3" ] || fail 'fixture share manifest differs from the initrd manifest'
}
