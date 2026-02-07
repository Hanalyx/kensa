# CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 - Missing Rules

**Framework ID:** `cis-rhel8-v4.0.0`
**Published:** 2024-06-28
**Platform:** rhel >= 8 <= 8

## Summary

| Metric | Count |
|--------|-------|
| Total Controls | 311 |
| Implemented (have rules) | 120 |
| **Need Rules** | **172** |
| Manual/Site-specific | 19 |

## Controls Needing Rules

These controls are automatable but don't have rules implemented yet.

### 1. Initial Setup

| Section | Title | Type |
|---------|-------|------|
| 1.1.1.5 | Ensure jffs2 kernel module is not available | Automated |
| 1.1.1.6 | Ensure overlay kernel module is not available | Automated |
| 1.1.2.1.1 | Ensure /tmp is tmpfs or a separate partition | Automated |
| 1.1.2.2.1 | Ensure /dev/shm is tmpfs | Automated |
| 1.1.2.3.1 | Ensure separate partition exists for /home | Automated |
| 1.1.2.4.1 | Ensure separate partition exists for /var | Automated |
| 1.1.2.4.2 | Ensure nodev option set on /var partition | Automated |
| 1.1.2.4.3 | Ensure nosuid option set on /var partition | Automated |
| 1.1.2.5.1 | Ensure separate partition exists for /var/tmp | Automated |
| 1.1.2.6.1 | Ensure separate partition exists for /var/log | Automated |
| 1.1.2.6.2 | Ensure nodev option set on /var/log partition | Automated |
| 1.1.2.6.3 | Ensure nosuid option set on /var/log partition | Automated |
| 1.1.2.6.4 | Ensure noexec option set on /var/log partition | Automated |
| 1.1.2.7.1 | Ensure separate partition exists for /var/log/audit | Automated |
| 1.1.2.7.2 | Ensure nodev option set on /var/log/audit partition | Automated |
| 1.1.2.7.3 | Ensure nosuid option set on /var/log/audit partition | Automated |
| 1.1.2.7.4 | Ensure noexec option set on /var/log/audit partition | Automated |
| 1.2.1.2 | Ensure gpgcheck is configured | Automated |
| 1.2.1.5 | Ensure weak dependencies are configured | Automated |
| 1.3.1.1 | Ensure SELinux is installed | Automated |
| 1.3.1.2 | Ensure SELinux is not disabled in bootloader configuration | Automated |
| 1.3.1.5 | Ensure the SELinux mode is enforcing | Automated |
| 1.3.1.7 | Ensure the MCS Translation Service (mcstrans) is not installed | Automated |
| 1.3.1.8 | Ensure SETroubleshoot is not installed | Automated |
| 1.5.1 | Ensure core file size is configured | Automated |
| 1.5.2 | Ensure fs.protected_hardlinks is configured | Automated |
| 1.5.3 | Ensure fs.protected_symlinks is configured | Automated |
| 1.6.3 | Ensure system wide crypto policy macs are configured | Automated |
| 1.6.4 | Ensure system wide crypto policy disables cbc for ssh | Automated |
| 1.7.3 | Ensure /etc/issue.net is configured | Automated |
| 1.8.1 | Ensure GDM login banner is configured | Automated |
| 1.8.2 | Ensure GDM disable-user-list is configured | Automated |
| 1.8.3 | Ensure GDM screen lock is configured | Automated |
| 1.8.4 | Ensure GDM automount is configured | Automated |
| 1.8.5 | Ensure GDM autorun-never is configured | Automated |
| 1.8.6 | Ensure XDMCP is not enabled | Automated |
| 1.8.7 | Ensure Xwayland is configured | Automated |

### 2. Services

| Section | Title | Type |
|---------|-------|------|
| 2.1.1 | Ensure autofs services are not in use | Automated |
| 2.1.10 | Ensure nis server services are not in use | Automated |
| 2.1.11 | Ensure print server services are not in use | Automated |
| 2.1.12 | Ensure rpcbind services are not in use | Automated |
| 2.1.13 | Ensure rsync services are not in use | Automated |
| 2.1.14 | Ensure samba file server services are not in use | Automated |
| 2.1.15 | Ensure snmp services are not in use | Automated |
| 2.1.16 | Ensure telnet server services are not in use | Automated |
| 2.1.17 | Ensure tftp server services are not in use | Automated |
| 2.1.18 | Ensure web proxy server services are not in use | Automated |
| 2.1.19 | Ensure web server services are not in use | Automated |
| 2.1.2 | Ensure avahi daemon services are not in use | Automated |
| 2.1.20 | Ensure xinetd services are not in use | Automated |
| 2.1.21 | Ensure GNOME Display Manager is removed | Automated |
| 2.1.22 | Ensure X window server services are not in use | Automated |
| 2.1.23 | Ensure mail transfer agents are configured for local-only mode | Automated |
| 2.1.3 | Ensure cockpit web services are not in use | Automated |
| 2.1.4 | Ensure dhcp server services are not in use | Automated |
| 2.1.5 | Ensure dns server services are not in use | Automated |
| 2.1.6 | Ensure dnsmasq services are not in use | Automated |
| 2.1.7 | Ensure ftp server services are not in use | Automated |
| 2.1.8 | Ensure message access server services are not in use | Automated |
| 2.1.9 | Ensure network file system services are not in use | Automated |
| 2.2.1 | Ensure ftp client is not installed | Automated |
| 2.2.2 | Ensure ldap client is not installed | Automated |
| 2.2.3 | Ensure nis client is not installed | Automated |
| 2.2.4 | Ensure telnet client is not installed | Automated |
| 2.2.5 | Ensure tftp client is not installed | Automated |
| 2.3.1 | Ensure time synchronization is in use | Automated |
| 2.3.2 | Ensure chrony is configured | Automated |
| 2.3.3 | Ensure chrony is not run as the root user | Automated |
| 2.4.1.1 | Ensure cron daemon is enabled and active | Automated |
| 2.4.1.2 | Ensure access to /etc/crontab is configured | Automated |
| 2.4.1.3 | Ensure access to /etc/cron.hourly is configured | Automated |
| 2.4.1.4 | Ensure access to /etc/cron.daily is configured | Automated |
| 2.4.1.5 | Ensure access to /etc/cron.weekly is configured | Automated |
| 2.4.1.6 | Ensure access to /etc/cron.monthly is configured | Automated |
| 2.4.1.7 | Ensure access to /etc/cron.yearly is configured | Automated |
| 2.4.1.8 | Ensure access to /etc/cron.d is configured | Automated |
| 2.4.1.9 | Ensure access to crontab is configured | Automated |
| 2.4.2.1 | Ensure access to at is configured | Automated |

### 3. Network Configuration

| Section | Title | Type |
|---------|-------|------|
| 3.1.3 | Ensure bluetooth services are not in use | Automated |
| 3.2.5 | Ensure sctp kernel module is not available | Automated |
| 3.2.6 | Ensure tipc kernel module is not available | Automated |
| 3.3.1.10 | Ensure net.ipv4.conf.all.secure_redirects is configured | Automated |
| 3.3.1.11 | Ensure net.ipv4.conf.default.secure_redirects is configured | Automated |
| 3.3.1.12 | Ensure net.ipv4.conf.all.rp_filter is configured | Automated |
| 3.3.1.13 | Ensure net.ipv4.conf.default.rp_filter is configured | Automated |
| 3.3.1.14 | Ensure net.ipv4.conf.all.accept_source_route is configured | Automated |
| 3.3.1.15 | Ensure net.ipv4.conf.default.accept_source_route is configured | Automated |
| 3.3.1.18 | Ensure net.ipv4.tcp_syncookies is configured | Automated |
| 3.3.1.2 | Ensure net.ipv4.conf.all.forwarding is configured | Automated |
| 3.3.1.3 | Ensure net.ipv4.conf.default.forwarding is configured | Automated |
| 3.3.1.4 | Ensure net.ipv4.conf.all.send_redirects is configured | Automated |
| 3.3.1.5 | Ensure net.ipv4.conf.default.send_redirects is configured | Automated |
| 3.3.1.6 | Ensure net.ipv4.icmp_ignore_bogus_error_responses is configured | Automated |
| 3.3.1.7 | Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured | Automated |
| 3.3.1.8 | Ensure net.ipv4.conf.all.accept_redirects is configured | Automated |
| 3.3.1.9 | Ensure net.ipv4.conf.default.accept_redirects is configured | Automated |
| 3.3.2.1 | Ensure net.ipv6.conf.all.forwarding is configured | Automated |
| 3.3.2.2 | Ensure net.ipv6.conf.default.forwarding is configured | Automated |
| 3.3.2.3 | Ensure net.ipv6.conf.all.accept_redirects is configured | Automated |
| 3.3.2.4 | Ensure net.ipv6.conf.default.accept_redirects is configured | Automated |
| 3.3.2.5 | Ensure net.ipv6.conf.all.accept_source_route is configured | Automated |
| 3.3.2.6 | Ensure net.ipv6.conf.default.accept_source_route is configured | Automated |
| 3.3.2.7 | Ensure net.ipv6.conf.all.accept_ra is configured | Automated |
| 3.3.2.8 | Ensure net.ipv6.conf.default.accept_ra is configured | Automated |

### 4. Logging and Auditing

| Section | Title | Type |
|---------|-------|------|
| 4.1.1 | Ensure firewalld is installed | Automated |
| 4.1.2 | Ensure firewalld backend is configured | Automated |
| 4.1.3 | Ensure firewalld.service is configured | Automated |
| 4.1.4 | Ensure firewalld active zone target is configured | Automated |

### 5. Access, Authentication, and Authorization

| Section | Title | Type |
|---------|-------|------|
| 5.1.1 | Ensure sshd crypto_policy is not set | Automated |
| 5.1.16 | Ensure sshd LogLevel is configured | Automated |
| 5.1.23 | Ensure sshd PermitUserEnvironment is disabled | Automated |
| 5.1.24 | Ensure sshd UsePAM is enabled | Automated |
| 5.2.1 | Ensure sudo is installed | Automated |
| 5.2.4 | Ensure users must provide password for escalation | Automated |
| 5.2.7 | Ensure access to the su command is restricted | Automated |
| 5.3.1.1 | Ensure latest version of pam is installed | Automated |
| 5.3.1.2 | Ensure latest version of authselect is installed | Automated |
| 5.3.2.1 | Ensure active authselect profile includes pam modules | Automated |
| 5.3.2.2 | Ensure pam_faillock module is enabled | Automated |
| 5.3.2.3 | Ensure pam_pwquality module is enabled | Automated |
| 5.3.2.4 | Ensure pam_pwhistory module is enabled | Automated |
| 5.3.2.5 | Ensure pam_unix module is enabled | Automated |
| 5.3.3.1.1 | Ensure password failed attempts lockout is configured | Automated |
| 5.3.3.1.2 | Ensure password unlock time is configured | Automated |
| 5.3.3.1.3 | Ensure password failed attempts lockout includes root account | Automated |
| 5.3.3.3.3 | Ensure pam_pwhistory includes use_authtok | Automated |
| 5.4.2.2 | Ensure root is the only GID 0 account | Automated |
| 5.4.2.3 | Ensure group root is the only GID 0 group | Automated |
| 5.4.2.5 | Ensure root path integrity | Automated |
| 5.4.2.6 | Ensure root user umask is configured | Automated |
| 5.4.2.7 | Ensure system accounts do not have a valid login shell | Automated |
| 5.4.2.8 | Ensure accounts without a valid login shell are locked | Automated |

### 6. System Maintenance

| Section | Title | Type |
|---------|-------|------|
| 6.1.2 | Ensure filesystem integrity is regularly checked | Automated |
| 6.2.1.1.1 | Ensure journald service is active | Automated |
| 6.2.1.1.4 | Ensure journald ForwardToSyslog is disabled | Automated |
| 6.2.1.1.5 | Ensure journald Storage is configured | Automated |
| 6.2.1.1.6 | Ensure journald Compress is configured | Automated |
| 6.2.1.2.1 | Ensure systemd-journal-remote is installed | Automated |
| 6.2.1.2.3 | Ensure systemd-journal-upload is enabled and active | Automated |
| 6.2.1.2.4 | Ensure systemd-journal-remote service is not in use | Automated |
| 6.2.2.1 | Ensure rsyslog is installed | Automated |
| 6.2.2.2 | Ensure rsyslog service is enabled and active | Automated |
| 6.2.2.3 | Ensure journald is configured to send logs to rsyslog | Automated |
| 6.2.2.4 | Ensure rsyslog log file creation mode is configured | Automated |
| 6.2.2.7 | Ensure rsyslog is not configured to receive logs from a remote client | Automated |
| 6.2.3.1 | Ensure access to all logfiles has been configured | Automated |
| 6.3.1.3 | Ensure audit_backlog_limit is configured | Automated |
| 6.3.2.1 | Ensure audit log storage size is configured | Automated |
| 6.3.2.2 | Ensure audit logs are not automatically deleted | Automated |
| 6.3.2.3 | Ensure system is disabled when audit logs are full | Automated |
| 6.3.2.4 | Ensure system warns when audit logs are low on space | Automated |
| 6.3.3.2 | Ensure actions as another user are always logged | Automated |
| 6.3.3.3 | Ensure events that modify the sudo log file are collected | Automated |
| 6.3.4.1 | Ensure the audit log file directory mode is configured | Automated |
| 6.3.4.10 | Ensure audit tools group owner is configured | Automated |
| 6.3.4.2 | Ensure audit log files mode is configured | Automated |
| 6.3.4.3 | Ensure audit log files owner is configured | Automated |
| 6.3.4.4 | Ensure audit log files group owner is configured | Automated |
| 6.3.4.5 | Ensure audit configuration files mode is configured | Automated |
| 6.3.4.6 | Ensure audit configuration files owner is configured | Automated |
| 6.3.4.7 | Ensure audit configuration files group owner is configured | Automated |
| 6.3.4.8 | Ensure audit tools mode is configured | Automated |
| 6.3.4.9 | Ensure audit tools owner is configured | Automated |

### 7. System Maintenance (cont.)

| Section | Title | Type |
|---------|-------|------|
| 7.1.10 | Ensure access to /etc/security/opasswd is configured | Automated |
| 7.1.9 | Ensure access to /etc/shells is configured | Automated |
| 7.2.1 | Ensure accounts in /etc/passwd use shadowed passwords | Automated |
| 7.2.2 | Ensure /etc/shadow password fields are not empty | Automated |
| 7.2.3 | Ensure all groups in /etc/passwd exist in /etc/group | Automated |
| 7.2.6 | Ensure no duplicate user names exist | Automated |
| 7.2.7 | Ensure no duplicate group names exist | Automated |
| 7.2.8 | Ensure local interactive user home directories are configured | Automated |
| 7.2.9 | Ensure local interactive user dot files access is configured | Automated |

## Manual/Site-Specific Controls

These controls require manual verification or are site-specific policy decisions.

| Section | Title | Reason |
|---------|-------|--------|
| 1.1.1.11 | Ensure unused filesystems kernel modules are not available | Manual check - requires human verification |
| 1.2.1.1 | Ensure GPG keys are configured | Manual check - requires human verification |
| 1.2.1.3 | Ensure repo_gpgcheck is globally activated | Manual check - requires human verification |
| 1.2.1.4 | Ensure package manager repositories are configured | Manual check - requires human verification |
| 1.2.2.1 | Ensure updates, patches, and additional security software are installed | Manual check - requires human verification |
| 1.3.1.6 | Ensure no unconfined services exist | Manual check - requires human verification |
| 1.6.5 | Ensure system wide crypto policy disables chacha20-poly1305 for ssh | Manual check - requires human verification |
| 1.6.6 | Ensure system wide crypto policy disables EtM for ssh | Manual check - requires human verification |
| 2.1.24 | Ensure only approved services are listening on a network interface | Manual check - requires human verification |
| 4.1.5 | Ensure firewalld loopback traffic is configured | Manual check - requires human verification |
| 4.1.6 | Ensure firewalld loopback source address traffic is configured | Manual check - requires human verification |
| 4.1.7 | Ensure firewalld services and ports are configured | Manual check - requires human verification |
| 6.2.1.1.2 | Ensure journald log file access is configured | Manual check - requires human verification |
| 6.2.1.1.3 | Ensure journald log file rotation is configured | Manual check - requires human verification |
| 6.2.1.2.2 | Ensure systemd-journal-remote authentication is configured | Manual check - requires human verification |
| 6.2.2.5 | Ensure rsyslog logging is configured | Manual check - requires human verification |
| 6.2.2.6 | Ensure rsyslog is configured to send logs to a remote log host | Manual check - requires human verification |
| 6.2.2.8 | Ensure logrotate is configured | Manual check - requires human verification |
| 6.3.3.22 | Ensure the running and on disk configuration is the same | Manual check - requires human verification |
