# Security Model

Kensa runs shell commands on remote hosts via SSH. This document covers the threat model, specific risks, and the coding practices that mitigate them.

## Threat Model

**Trust boundaries:**
- The local machine running kensa is trusted
- The SSH transport (paramiko) is trusted
- Rule YAML files are trusted (authored by us)
- Remote host state is untrusted (we read it, never trust output blindly)
- User-supplied CLI arguments are semi-trusted (validated by click, but could contain adversarial input)

**What we protect against:**
- Shell injection via rule values or CLI input into remote commands
- Credential leakage in logs, error messages, or remote command arguments
- Unintended state changes on remote hosts (dry-run mode, idempotency guards)

**What we do NOT protect against (out of scope for V0):**
- Compromised local machine
- Malicious rule files (rule authors are trusted)
- Man-in-the-middle on SSH (paramiko host key verification set to AutoAdd — acceptable for V0, should be tightened)


## Shell Injection

This is the #1 risk. Every `ssh.run()` call sends a string to a remote shell for execution.

### The Rule

**Every value interpolated into a shell command must be quoted with `shlex.quote()` unless it is a shell glob that needs expansion.**

### Safe Examples

```python
# Good: value from rule YAML is quoted
key = c["key"]  # e.g., "PermitRootLogin"
ssh.run(f"sysctl -n {shlex.quote(key)}")

# Good: path from rule is quoted
path = r["path"]  # e.g., "/etc/ssh/sshd_config"
ssh.run(f"grep -q 'Banner' {shlex.quote(path)}")

# Good: glob path detected and left unquoted
path = c["path"]  # e.g., "/etc/ssh/ssh_host_*_key"
is_glob = "glob" in c or any(ch in path for ch in "*?[")
quoted = path if is_glob else shlex.quote(path)
ssh.run(f"stat -c '%U %G %a' {quoted}")
```

### Dangerous Patterns to Avoid

```python
# BAD: unquoted interpolation
ssh.run(f"grep {key} {path}")        # key="foo; rm -rf /" → disaster

# BAD: building sed with unescaped values
value = r["value"]  # Could contain / or other sed metacharacters
ssh.run(f"sed -i 's/old/{value}/' {path}")  # Injection via value

# BAD: echo without quoting
ssh.run(f"echo {value} >> {path}")   # Value could contain $(cmd) or backticks
```

### The sed Problem

`sed` is particularly dangerous because the delimiter (`/`) appears in paths and values. The current `_remediate_config_set` handler escapes `/` in the replacement string, but this is fragile. Preferred approach for future handlers:

```python
# Safer: use echo + grep/append pattern instead of sed
line = f"{key}{sep}{value}"
ssh.run(f"echo {shlex.quote(line)} >> {shlex.quote(path)}")
```

### Sudo Wrapping

When `--sudo` is active, commands are wrapped as:
```
sudo -n sh -c '<entire command>'
```

The `shlex.quote()` around the entire command handles nested quoting. This is done once in `SSHSession.run()` — handlers don't need to think about sudo.


## Credential Safety

### SSH Credentials

- Passwords are accepted via `--password` CLI flag (visible in process list — users should prefer keys)
- Private key paths are stored in `HostInfo.key_path` but contents are never read by kensa (paramiko handles this)
- Neither passwords nor key contents are ever logged or included in error messages

### What Never Appears in Remote Commands

- Passwords — never pass as arguments to remote commands
- Private key material — never transferred to remote hosts
- API tokens — not applicable in V0 but preserve this principle

### Error Messages

When a command fails, `result.stderr` is shown to the user. Remote stderr could contain:
- File paths (acceptable)
- System configuration details (acceptable)
- Credential fragments if a command accidentally echoes them (mitigated by never passing credentials as command args)


## Host Key Verification

V0 uses `paramiko.AutoAddPolicy()` — accepts any host key on first connect. This is a known weakness.

**Future improvement (P2):** Add `--strict-host-keys` flag that uses `RejectPolicy` and reads from `~/.ssh/known_hosts`. Make it the default, with `--no-strict-host-keys` as the escape hatch.


## File Operations on Remote Hosts

All file writes are done via shell commands, not SFTP:

```python
# Writing a file
ssh.run(f"echo {shlex.quote(content)} > {shlex.quote(path)}")

# Appending to a file
ssh.run(f"echo {shlex.quote(line)} >> {shlex.quote(path)}")
```

This means:
- No binary file transfers
- Content is limited by command-line length (~2MB on Linux, practically ~100KB is safe)
- File permissions are set after writing via separate `chmod`/`chown` commands


## Idempotency

Remediations should be safe to run multiple times. Patterns:

- `unless` guard: skip if condition is already met
  ```yaml
  unless: "test -f /var/lib/aide/aide.db.gz"
  ```
- `config_set`: replaces existing line or appends if absent (no duplicates)
- `config_set_dropin`: overwrites the drop-in file (idempotent by nature)
- `sysctl_set`: overwrites persist file and applies immediately


## Principle of Least Surprise

- `check` commands are read-only — they never modify host state
- `remediate` checks first, only acts on failures, then re-checks
- `--dry-run` on remediate shows what would change without doing it
- Per-rule errors don't stop execution of other rules
- The `manual` remediation mechanism explicitly does nothing and reports what the admin must do
