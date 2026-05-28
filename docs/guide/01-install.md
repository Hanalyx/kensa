# 01 · Install

## What you'll have when you're done

`kensa` installed on your controller host, a signing key generated, a
rules corpus available, and `kensa --version` printing `kensa 0.1.0
(kensa)`. From there, [02-quickstart](02-quickstart.md) is the next
step.

Target hosts (the machines you'll scan) need no kensa installation —
only OpenSSH and, for non-root remediation, sudo.

## Before v1.0 ships

`dnf install kensa` and `dnf install kensa-rules` are the v1.0 ship
path. They don't publish yet. Today the install is build-from-source
and the rules are a separately-fetched directory you pass to every
command with `--rules-dir`. The rest of this chapter is the today-path.

## What you need

A controller host with Go 1.26.1+, GNU make, git, and an OpenSSH
client. Nothing else.

## Build

```bash
git clone git@github.com:Hanalyx/kensa.git && cd kensa && make build
```

You'll get five static binaries in `bin/`. The names tell you what
they do: `kensa` is the CLI, `kensa-fuzz` exercises atomicity on real
hosts, `kensa-validate` checks rule YAML, `kensa-keygen` generates
signing keys, and `kensa-systemd-helper` is the privileged D-Bus
helper that handles `service_*` rules through sudo.

## Install

Move the binaries to where you want them on the controller. `kensa`
through `kensa-keygen` go on your `$PATH`; `kensa-systemd-helper` goes
to `/usr/libexec/` because the agent looks for it there by default:

```bash
sudo install -m 0755 bin/{kensa,kensa-fuzz,kensa-validate,kensa-keygen} /usr/local/bin/ \
    && sudo install -m 0755 bin/kensa-systemd-helper /usr/libexec/
```

## Generate a signing key

`kensa-keygen` writes a keypair to `~/.config/kensa/keys/`. The
private half is mode `0600`; the public half is what you distribute
to anyone running `kensa verify` against your evidence envelopes.

For a stable operator identity across runs, point `KENSA_SIGNING_KEY`
at the `.priv` file before running `kensa remediate`. Without that
env var, kensa generates an ephemeral key per process — fine for
trying things out, but your evidence envelopes won't share a stable
signer identity.

## Fetch the rules

Kensa ships no rules in the binary. Clone the corpus to a directory
you'll point at with `--rules-dir`, and validate it once with
`kensa-validate --rules-dir <path>`. A `0` exit means every rule
parses cleanly; anything else means something needs fixing before
kensa will load it.

## Service handlers (optional)

You only need this step if your rules use `service_enabled`,
`service_disabled`, or `service_masked`. Add yourself to a `kensa`
group, then create `/etc/sudoers.d/kensa-systemd-helper` (mode `0440`,
owned by root) containing:

```
%kensa ALL=(root) NOPASSWD: /usr/libexec/kensa-systemd-helper
```

Run `sudo visudo -c` to syntax-check. The v1.0 RPM ships this fragment
automatically. The canonical definition is
`specs/agent/systemd-helper.spec.yaml` AC C-06.

Without the helper, only the service handlers fail. Everything else
(file permissions, sysctl, mount options, SELinux booleans, audit,
cron, packages, PAM) works as-is.

## Verify

```bash
kensa --version
```

You're done when this prints `kensa 0.1.0 (kensa)`. If it doesn't,
the binary isn't on your `$PATH` — go back to **Install**.

## Next

[02-quickstart](02-quickstart.md) runs your first scan and your first
remediation.
