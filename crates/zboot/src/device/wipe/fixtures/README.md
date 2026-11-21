# nvme-cli fixtures for `wipe`

The unit tests in `../tests.rs` feed these files to the `nvme` parsers and to
the selection and sanitize logic. Each file is the standard output of one
`nvme` command in nvme-cli 2.x JSON, as `nvme ... -o json` prints it.

## Real captures

Captured with nvme-cli 2.16 (libnvme 1.16.2), then scrubbed:

| Directory | Drive | What it shows |
|---|---|---|
| `sk-hynix-p41/` | SK hynix Platinum P41 2 TB (`SHPP41-2000GM`) | no namespace management (OACS 23), CMIC 0, NN 1; SANICAP `0x60000002`: block erase only, with the NDI and NODMMAS bits set; the log already reports a successful block erase |
| `xpg-gammix-s11-pro/` | XPG GAMMIX S11 Pro 1 TB | no namespace management (OACS 22), CMIC 0, NN 1; SANICAP 3: crypto and block erase; the log already reports a successful crypto erase with nothing written since |

Per drive:

| File | Command | Exit |
|---|---|---|
| `id-ctrl.json` | `nvme id-ctrl DEV -o json` | 0 |
| `list-ns.json` | `nvme list-ns DEV -o json` (active namespaces) | 0 |
| `id-ns.json` | `nvme id-ns NSDEV -o json` | 0 |
| `sanitize-log.json` | `nvme sanitize-log DEV -o json` | 0 |
| `list-ctrl.rejected.json` | `nvme list-ctrl DEV -o json` | 1, Invalid Field in Command |
| `list-ns-all.rejected.json` | `nvme list-ns DEV --all -o json` | 1, Invalid Field in Command |

`DEV` is the controller character device (`/dev/nvme0`), `NSDEV` the namespace
block device (`/dev/nvme0n1`). zboot sends the same Identify Namespace as
`nvme id-ns DEV --namespace-id=N`. A `.rejected.json` file is what nvme-cli
printed on standard output while exiting 1; the tests answer that command
with an error.

## Synthetic files

Everything in `synthetic/` is **synthetic, replace with capture**. These are
states the real drives above did not show when captured, written in the
nvme-cli 2.16 shape (`nvme-print-json.c`, `json_sanitize_log` and
`json_nvme_list_ns`):

| File | State |
|---|---|
| `sanitize-log-crypto-erase-in-progress.json` | a crypto erase running (status 2, cdw10 4) |
| `sanitize-log-block-erase-in-progress.json` | a block erase running (status 2, cdw10 2) |
| `sanitize-log-crypto-erase-failed.json` | the last crypto erase failed: sanitize failure mode (status 3) |
| `sanitize-log-never-sanitized.json` | never sanitized (status 0) |
| `list-ns-two-namespaces.json` | a subsystem with namespaces 1 and 2 |

Other cases (multi-controller capability, namespace management, a shareable
namespace, other SANICAP values) are the real captures with one field
changed in the test, which names the field.

## Capturing a drive

Run as root on the machine that has the drive. Every command is a read-only
query:

```sh
nvme id-ctrl DEV -o json > id-ctrl.json
nvme list-ctrl DEV -o json > list-ctrl.json
nvme list-ns DEV -o json > list-ns.json
nvme list-ns DEV --all -o json > list-ns-all.json
nvme id-ns DEV --namespace-id=1 -o json > id-ns.json
nvme sanitize-log DEV -o json > sanitize-log.json
```

Note each exit status. A command that exits nonzero is saved as
`NAME.rejected.json`. Never run `nvme sanitize` to capture a state: it
cannot be aborted.

Before committing, scrub every identifier: replace the values of `sn`,
`subnqn` and `fguid` (id-ctrl) and `nguid` and `eui64` (id-ns) with
`"SCRUBBED"`. Serial numbers and NQNs must never be committed. Check that
nothing else names the unit, such as vendor-specific bytes.
