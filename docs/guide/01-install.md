# 01 · Install

## Scope

Install kensa on a controller host and prepare the binaries, signing
keys, rules corpus, and (optionally) the privileged systemd helper that
the agent invokes via sudo.

The controller is the machine where you run `kensa`. Target hosts (the
ones being scanned or remediated) need no kensa installation — only
OpenSSH and, for non-root remediation, sudo. See
[02-quickstart](02-quickstart.md) §"Target requirements" for the
target-side checklist.

## Today vs. v1.0

**v1.0 ship state** (planned):

```bash
sudo dnf install kensa kensa-rules
kensa --version
```

**Today (v0.1.0):** kensa is source-only. `kensa-rpm` and `kensa-rules`
packages are not published yet. Install path is build-from-source; the
rules corpus lives at a separate location you point at with
`--rules-dir`. The rest of this chapter is the today-path. When v1.0
ships, this chapter will gain a **Package install** section above
**Build from source**.

## Prerequisites

| Tool | Required for | Minimum version |
| --- | --- | --- |
| Go | building kensa | 1.26.1 |
| GNU make | running `make build` | any recent |
| git | cloning the repo | any recent |
| OpenSSH client | reaching target hosts | any modern OpenSSH |
| `protoc` + `protoc-gen-go` | regenerating `internal/agent/wirev1/wire.pb.go` (only if editing the wire protocol) | matched to `tools.go` |

Verify Go is present and on a supported version:

```bash
go version    # → go version go1.26.1 linux/amd64 (or newer)
```

## Build from source

```bash
git clone git@github.com:Hanalyx/kensa.git
cd kensa
make build
```

`make build` produces five static binaries in `bin/`:

| Binary | Purpose |
| --- | --- |
| `kensa` | The CLI: `detect`, `check`, `remediate`, `rollback`, `history`, `plan`, `verify`, `diff`, `info`, `coverage`, `mechanisms`, `list`, `agent`, `migrate`. Run `kensa --help` for the full list. |
| `kensa-fuzz` | Failure-injection harness for atomicity verification on real hosts. |
| `kensa-validate` | Rule YAML and spec validator. |
| `kensa-keygen` | Ed25519 keypair generator for evidence signing. |
| `kensa-systemd-helper` | Privileged systemd D-Bus helper (sudo-invoked by the agent). |

Each binary is statically linked (`CGO_ENABLED=0`, `-tags netgo`) with
the version string injected from the repo-root `VERSION` file via
`-ldflags`. The same binary set runs on RHEL 8 (glibc 2.28) through
RHEL 10+, Ubuntu 22.04+, Debian, and Alpine (musl). See README §
"Portability" for the CI gates that enforce this.

Place the binaries where you want them. A common layout:

```bash
sudo install -m 0755 bin/kensa            /usr/local/bin/kensa
sudo install -m 0755 bin/kensa-fuzz       /usr/local/bin/kensa-fuzz
sudo install -m 0755 bin/kensa-validate   /usr/local/bin/kensa-validate
sudo install -m 0755 bin/kensa-keygen     /usr/local/bin/kensa-keygen

# kensa-systemd-helper goes to libexec (it's not for direct invocation):
sudo install -m 0755 bin/kensa-systemd-helper /usr/libexec/kensa-systemd-helper
```

The `kensa-systemd-helper` path matters: the agent expects it at
`/usr/libexec/kensa-systemd-helper` by default. The other four can
live anywhere on `PATH`.

## Generate signing keys

Every successful transaction produces a signed evidence envelope.
`kensa-keygen` generates the Ed25519 keypair.

```bash
kensa-keygen
```

By default this writes two files into the first available of:

```
$KENSA_CONFIG_DIR/keys/
$XDG_CONFIG_HOME/kensa/keys/
$HOME/.config/kensa/keys/
```

The filename stem is the lower-hex SHA-256 of the public key (the
canonical key-identity used by the signer). To use a human-readable
stem instead:

```bash
kensa-keygen --key-id production
# → production.priv (mode 0600)
# → production.pub  (mode 0644)
```

For shared-controller deployments, write the keys to a known location
the operator account owns:

```bash
sudo mkdir -p /var/lib/kensa/keys
sudo chown $USER:$USER /var/lib/kensa/keys
kensa-keygen --out /var/lib/kensa/keys --key-id production
```

To use a persistent operator key, set `KENSA_SIGNING_KEY` to the
`.priv` path before running `kensa remediate`:

```bash
export KENSA_SIGNING_KEY=/var/lib/kensa/keys/production.priv
```

If `KENSA_SIGNING_KEY` is unset, kensa generates an ephemeral keypair
per process — fine for development, but evidence envelopes from
different runs will not share a stable signer identity.

`kensa verify` validates evidence envelopes against a trust directory
of `.pub` files. Distribute the `.pub` to verifiers; never share the
`.priv`.

## Get the rules corpus

Kensa ships no rules in the binary. Rules are YAML files under a
directory you pass to every scan or remediate command via
`--rules-dir`.

The canonical rules corpus is maintained as a separate artifact. In
v1.0, `kensa-rules` will install to `/usr/share/kensa/rules`. Until
then, fetch the corpus from its source repository or distribution
channel and put it wherever you like:

```bash
git clone <rules-corpus-url> ~/kensa-rules
ls ~/kensa-rules/*.yaml | head -3
```

Every scan you run must point at this directory:

```bash
kensa check --rules-dir ~/kensa-rules <host>
```

Validate the corpus once after fetching:

```bash
kensa-validate --rules-dir ~/kensa-rules
```

`kensa-validate` exits `0` if every rule parses, references a defined
mechanism, and has consistent capability-gated implementations. Any
non-zero exit means at least one rule is malformed — fix or remove
those before scanning, or kensa will refuse to load them.

## Install the systemd helper (optional)

You only need this if your rules use the service handlers
(`service_enabled`, `service_disabled`, `service_masked`). The helper
is the privileged side of the agent's split-privilege design: the
agent runs unprivileged and shells out to the helper via sudo for the
seven systemd D-Bus operations.

The binary at `/usr/libexec/kensa-systemd-helper` must be invokable
only as root, via sudo. Install a sudoers fragment that grants
exactly this:

```bash
sudo groupadd --system kensa 2>/dev/null || true
sudo gpasswd -a "$USER" kensa
sudo install -m 0440 -o root -g root \
    <(echo '%kensa ALL=(root) NOPASSWD: /usr/libexec/kensa-systemd-helper') \
    /etc/sudoers.d/kensa-systemd-helper
sudo visudo -c    # syntax check
```

The canonical sudoers fragment is defined in
`specs/agent/systemd-helper.spec.yaml` AC C-06. The v1.0 RPM will ship
this file automatically.

Without the helper installed, service-handler rules will fail at apply
time. All other handlers (file permissions, sysctl, mount options,
SELinux booleans, etc.) work without it.

## Verify the install

Confirm each binary reports the same version:

```bash
for b in kensa kensa-fuzz kensa-validate kensa-keygen kensa-systemd-helper; do
    printf '%-25s ' "$b:"
    "$b" --version 2>&1 | head -1
done
```

Expected:

```
kensa:                    kensa 0.1.0 (kensa)
kensa-fuzz:               kensa-fuzz 0.1.0
kensa-validate:           kensa-validate 0.1.0
kensa-keygen:             kensa-keygen 0.1.0
kensa-systemd-helper:     kensa-systemd-helper: must run as root (...)
```

The systemd helper refusing to run as a normal user is correct — the
privilege check fires before any flag parsing, so `--version` is
rejected. To see the helper's version, invoke through sudo:
`sudo /usr/libexec/kensa-systemd-helper --version`.

Confirm the main binary is statically linked:

```bash
file $(command -v kensa)
# → ELF 64-bit LSB executable, x86-64, ..., statically linked, ...

ldd $(command -v kensa)
# → not a dynamic executable
```

If `ldd` reports any shared library dependencies, the binary was built
without `CGO_ENABLED=0` — rebuild from the repo before deploying.

End-to-end smoke against `localhost` (read-only `check`, no mutation):

```bash
kensa check --rules-dir ~/kensa-rules --severity high localhost
```

If you see a results table or "all hosts compliant," the install is
healthy. If you see an SSH error, your local SSH config needs work —
see [07-integration](07-integration.md) §"SSH transport".

## Uninstall

```bash
sudo rm -f /usr/local/bin/kensa{,-fuzz,-validate,-keygen}
sudo rm -f /usr/libexec/kensa-systemd-helper
sudo rm -f /etc/sudoers.d/kensa-systemd-helper

# Operator state — only if you want to discard transaction history
# and signing keys:
rm -rf ~/.kensa                  # local transaction log
rm -rf ~/.config/kensa/keys      # signing keys
sudo rm -rf /var/lib/kensa       # shared signing keys (if used)
```

The rules corpus directory (`~/kensa-rules` or wherever you fetched
it) is yours to keep or discard separately.

## Next

[02-quickstart](02-quickstart.md) runs your first scan and your first
remediation.
