# P0-1: Sudo and Permissions Model (DONE)

## Status: Complete

## Problem
The initial implementation ran all remote commands as the connecting SSH user. On hardened RHEL systems, files like `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` are `0600 root:root`. A non-root user (e.g., `owadmin`) can't read them, causing:
- Capability probes to fail (sshd_config_d not detected)
- Config value checks to report "not found" (false positives)
- All SSH rules falling back to default implementation, then failing

## Solution
- Added `--sudo` CLI flag
- `SSHSession.run()` wraps all commands with `sudo -n sh -c '<cmd>'` when active
- `-n` = non-interactive, requires NOPASSWD sudo on target
- Applies uniformly to probes, checks, and remediations

## Also Fixed
- `sshd_config_d` probe: added case-insensitive grep (`-qi`) and fallback to checking for .conf files in the directory
- `--verbose` flag: shows failed probe details (exit code, stderr) and which implementation was selected per rule

## Validated
- Without `--sudo`: 7 pass / 28 fail (most SSH rules fail)
- With `--sudo`: 26 pass / 9 fail (legitimate failures only)
