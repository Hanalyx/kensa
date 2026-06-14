# 01 · Install

## What you'll have when you're done

`kensa` and `kensa-rules` installed from signed packages, the verification
keys imported, and `kensa --version` printing `kensa 0.4.1`. From there,
[02-quickstart](02-quickstart.md) is the next step.

Target hosts (the machines you'll scan) need no kensa installation —
only OpenSSH and, for non-root remediation, sudo.

## Step 1 — Import the verification keys

Every release artifact is signed. The Hanalyx GPG public key verifies
the `.rpm` and `.deb` files; the Kensa cosign public key verifies the
checksums file that anchors the whole set. Both keys live at
[`KEYS`](https://github.com/Hanalyx/kensa/blob/main/KEYS) in the repo
root.

```bash
# RHEL/Fedora/Rocky/Alma + Debian/Ubuntu: import the Hanalyx GPG key
sudo rpm --import https://raw.githubusercontent.com/Hanalyx/kensa/main/KEYS
# or for apt:
curl -fsSL https://raw.githubusercontent.com/Hanalyx/kensa/main/KEYS \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/hanalyx.gpg

# Save the cosign block from KEYS as cosign.pub (everything between
# -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----).
```

With the Hanalyx GPG key imported, `dnf` and `apt` reject any unsigned
or wrong-key kensa package automatically — you get the trust check for
free.

## Step 2 — Install

Pick one path.

### Connected RHEL/Fedora/Rocky/Alma

```bash
sudo dnf install kensa kensa-rules
```

`kensa` Recommends `kensa-rules`, so `dnf install kensa` alone pulls
both by default. Use `--setopt=install_weak_deps=False` to opt out
(you'll need `--rules-dir <path>` on every command).

### Connected Debian/Ubuntu

```bash
sudo apt install kensa kensa-rules
```

### Air-gapped

On a connected host, download the bundled tarball from
[the v0.4.1 release](https://github.com/Hanalyx/kensa/releases/tag/v0.4.1):

```
kensa_0.4.1_linux_<arch>_with-rules.tar.gz   # binaries + rules + LICENSE + KEYS
kensa_0.4.1_checksums.sha256                 # sha256 of every artifact
kensa_0.4.1_checksums.sha256.sig             # cosign signature of the checksums
```

Verify before transferring:

```bash
sha256sum -c kensa_0.4.1_checksums.sha256   # one OK line per artifact you downloaded
cosign verify-blob --key cosign.pub \
  --signature kensa_0.4.1_checksums.sha256.sig \
  kensa_0.4.1_checksums.sha256
```

Then copy the tarball to the air-gapped host and:

```bash
tar xzf kensa_0.4.1_linux_amd64_with-rules.tar.gz
sudo install -m 0755 kensa kensa-validate kensa-keygen /usr/local/bin/
sudo install -m 0755 kensa-systemd-helper /usr/libexec/
sudo mkdir -p /usr/share/kensa && sudo cp -r rules /usr/share/kensa/
```

Both the connected `.rpm`/`.deb` paths and this air-gap path install the
rules to `/usr/share/kensa/rules/`, which is where `kensa check` falls
back when `--rules-dir` is unset (see
[`rule-default-path-resolution`](../../specs/rule/default-path-resolution.spec.yaml)
spec).

## Step 3 — Generate a signing key

`kensa-keygen` writes a keypair to `~/.config/kensa/keys/`. The
private half is mode `0600`; the public half is what you distribute
to anyone running `kensa verify` against your evidence envelopes.

For a stable operator identity across runs, point `KENSA_SIGNING_KEY`
at the `.priv` file before running `kensa remediate`. Without that
env var, kensa generates an ephemeral key per process — fine for
trying things out, but your evidence envelopes won't share a stable
signer identity.

## Service handlers (optional)

You only need this step if your rules use `service_enabled`,
`service_disabled`, or `service_masked`.

The rpm/deb already ship `/etc/sudoers.d/kensa-systemd-helper` (the
`%kensa ALL=(root) NOPASSWD: /usr/libexec/kensa-systemd-helper` rule)
and create the `kensa` group **empty** at install time, so the grant is
inert until you opt a user in. The only remaining step is to add that
user to the group:

```bash
sudo usermod -aG kensa "$USER"   # log out / back in for it to take effect
```

(Installing from the air-gap tarball instead of the package? Create the
group and drop the sudoers file yourself: `sudo groupadd --system
kensa`, then write the one-line rule above to
`/etc/sudoers.d/kensa-systemd-helper` mode `0440` root-owned and run
`sudo visudo -c` to syntax-check.)

The canonical definition is
[`agent-systemd-helper`](../../specs/agent/systemd-helper.spec.yaml)
AC-09 / C-06 and
[`packaging-sudoers-helper`](../../specs/packaging/sudoers-helper.spec.yaml).
Without the helper, only the service handlers fail; everything else
(file permissions, sysctl, mount options, SELinux booleans, audit,
cron, packages, PAM) works as-is.

## Build from source

For contributors and for customising the build. Requires Go 1.26.4+ (the
version pinned in `go.mod`), GNU make, git:

```bash
git clone https://github.com/Hanalyx/kensa.git && cd kensa && make build
```

Five static binaries land in `bin/`: `kensa`, `kensa-fuzz` (the
destructive atomicity harness — not shipped in packages),
`kensa-validate`, `kensa-keygen`, `kensa-systemd-helper`. Install per
the air-gap path above (the `bin/` directory replaces the extracted
tarball). The rules corpus lives at `rules/` in the repo; copy it to
`/usr/share/kensa/rules/` or pass `--rules-dir ./rules` on every command.

## Verify

```bash
kensa --version
```

You're done when this prints `kensa 0.4.1 (kensa)`. If it doesn't,
the binary isn't on your `$PATH` — go back to **Step 2**.

## Next

[02-quickstart](02-quickstart.md) runs your first scan and your first
remediation.
