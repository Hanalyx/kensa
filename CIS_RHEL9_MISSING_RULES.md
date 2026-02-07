# CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 - Missing Rules

**Framework ID:** `cis-rhel9-v2.0.0`
**Published:** 2024-06-28
**Platform:** rhel >= 9

## Summary

| Metric | Count |
|--------|-------|
| Total Controls | 285 |
| Implemented (have rules) | 151 |
| **Need Rules** | **133** |
| Manual/Site-specific | 18 |

## Controls Needing Rules

These controls are automatable but don't have rules implemented yet.

### 1. Initial Setup

| Section | Title | Type |
|---------|-------|------|
| 1.1.2.1.1 | Ensure /tmp is a separate partition | Automated |
| 1.1.2.2.1 | Ensure /dev/shm is a separate partition | Automated |
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
| 1.3.1.1 | Ensure SELinux is installed | Automated |
| 1.3.1.2 | Ensure SELinux is not disabled in bootloader configuration | Automated |
| 1.3.1.4 | Ensure the SELinux mode is not disabled | Automated |
| 1.3.1.7 | Ensure the MCS Translation Service (mcstrans) is not installed | Automated |
| 1.3.1.8 | Ensure SETroubleshoot is not installed | Automated |
| 1.6.5 | Ensure system wide crypto policy disables cbc for ssh | Automated |
| 1.8.1 | Ensure GNOME Display Manager is removed | Automated |
| 1.8.10 | Ensure XDMCP is not enabled | Automated |
| 1.8.2 | Ensure GDM login banner is configured | Automated |
| 1.8.3 | Ensure GDM disable-user-list option is enabled | Automated |
| 1.8.4 | Ensure GDM screen locks when the user is idle | Automated |
| 1.8.5 | Ensure GDM screen locks cannot be overridden | Automated |
| 1.8.6 | Ensure GDM automatic mounting of removable media is disabled | Automated |
| 1.8.8 | Ensure GDM autorun-never is enabled | Automated |
| 1.8.9 | Ensure GDM autorun-never is not overridden | Automated |

### 2. Services

| Section | Title | Type |
|---------|-------|------|
| 2.1.1 | Ensure autofs services are not in use | Automated |
| 2.1.10 | Ensure nis server services are not in use | Automated |
| 2.1.11 | Ensure print server services are not in use | Automated |
| 2.1.12 | Ensure rpcbind services are not in use | Automated |
| 2.1.13 | Ensure rsync services are not in use | Automated |
| 2.1.14 | Ensure snmp services are not in use | Automated |
| 2.1.15 | Ensure telnet server services are not in use | Automated |
| 2.1.16 | Ensure tftp server services are not in use | Automated |
| 2.1.17 | Ensure web proxy server services are not in use | Automated |
| 2.1.18 | Ensure web server services are not in use | Automated |
| 2.1.19 | Ensure xinetd services are not in use | Automated |
| 2.1.2 | Ensure avahi daemon services are not in use | Automated |
| 2.1.20 | Ensure X window server services are not in use | Automated |
| 2.1.21 | Ensure mail transfer agents are configured for local-only mode | Automated |
| 2.1.3 | Ensure dhcp server services are not in use | Automated |
| 2.1.4 | Ensure dns server services are not in use | Automated |
| 2.1.5 | Ensure dnsmasq services are not in use | Automated |
| 2.1.6 | Ensure samba file server services are not in use | Automated |
| 2.1.7 | Ensure ftp server services are not in use | Automated |
| 2.1.8 | Ensure message access server services are not in use | Automated |
| 2.1.9 | Ensure network file system services are not in use | Automated |
| 2.2.1 | Ensure ftp client is not installed | Automated |
| 2.2.3 | Ensure nis client is not installed | Automated |
| 2.3.1 | Ensure time synchronization is in use | Automated |
| 2.3.2 | Ensure chrony is configured | Automated |
| 2.3.3 | Ensure chrony is not run as the root user | Automated |
| 2.4.1.1 | Ensure cron daemon is enabled and active | Automated |
| 2.4.1.2 | Ensure permissions on /etc/crontab are configured | Automated |
| 2.4.1.3 | Ensure permissions on /etc/cron.hourly are configured | Automated |
| 2.4.1.4 | Ensure permissions on /etc/cron.daily are configured | Automated |
| 2.4.1.5 | Ensure permissions on /etc/cron.weekly are configured | Automated |
| 2.4.1.6 | Ensure permissions on /etc/cron.monthly are configured | Automated |
| 2.4.1.7 | Ensure permissions on /etc/cron.d are configured | Automated |
| 2.4.1.8 | Ensure crontab is restricted to authorized users | Automated |
| 2.4.2.1 | Ensure at is restricted to authorized users | Automated |

### 3. Network Configuration

| Section | Title | Type |
|---------|-------|------|
| 3.1.2 | Ensure wireless interfaces are disabled | Automated |

### 4. Logging and Auditing

| Section | Title | Type |
|---------|-------|------|
| 4.1.1 | Ensure nftables is installed | Automated |
| 4.1.2 | Ensure a single firewall configuration utility is in use | Automated |
| 4.2.2 | Ensure firewalld loopback traffic is configured | Automated |
| 4.3.1 | Ensure nftables base chains exist | Automated |
| 4.3.3 | Ensure nftables default deny firewall policy | Automated |
| 4.3.4 | Ensure nftables loopback traffic is configured | Automated |

### 5. Access, Authentication, and Authorization

| Section | Title | Type |
|---------|-------|------|
| 5.1.19 | Ensure only strong MAC algorithms are used | N/A |
| 5.1.22 | Ensure sshd UsePAM is enabled | Automated |
| 5.2.4 | Ensure users must provide password for escalation | Automated |
| 5.3.1.1 | Ensure latest version of pam is installed | Automated |
| 5.3.1.2 | Ensure latest version of authselect is installed | Automated |
| 5.3.1.3 | Ensure latest version of libpwquality is installed | Automated |
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
| 6.2.1.1 | Ensure journald service is enabled and active | Automated |
| 6.2.1.4 | Ensure only one logging system is in use | Automated |
| 6.2.2.1.1 | Ensure systemd-journal-remote is installed | Automated |
| 6.2.2.1.3 | Ensure systemd-journal-upload is enabled and active | Automated |
| 6.2.2.1.4 | Ensure systemd-journal-remote service is not in use | Automated |
| 6.2.2.2 | Ensure journald ForwardToSyslog is disabled | Automated |
| 6.2.2.3 | Ensure journald Compress is configured | Automated |
| 6.2.2.4 | Ensure journald Storage is configured | Automated |
| 6.2.3.1 | Ensure rsyslog is installed | Automated |
| 6.2.3.2 | Ensure rsyslog service is enabled and active | Automated |
| 6.2.3.3 | Ensure journald is configured to send logs to rsyslog | Automated |
| 6.2.3.4 | Ensure rsyslog log file creation mode is configured | Automated |
| 6.2.3.7 | Ensure rsyslog is not configured to receive logs from a remote client | Automated |
| 6.2.4.1 | Ensure access to all logfiles has been configured | Automated |
| 6.3.1.3 | Ensure audit_backlog_limit is sufficient | Automated |
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
| 7.1.10 | Ensure permissions on /etc/security/opasswd are configured | Automated |
| 7.1.9 | Ensure permissions on /etc/shells are configured | Automated |
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
| 1.1.1.9 | Ensure unused filesystems kernel modules are not available | Manual check - requires human verification |
| 1.1.2.1 | Ensure /tmp is a separate partition | Site-specific partitioning decision |
| 1.1.2.2 | Ensure nodev option set on /tmp partition | Requires /tmp to be separate partition |
| 1.2.1.1 | Ensure GPG keys are configured | Manual check - requires human verification |
| 1.2.2.1 | Ensure updates, patches, and additional security software are installed | Manual check - requires human verification |
| 1.3.1.6 | Ensure no unconfined services exist | Manual check - requires human verification |
| 1.6.6 | Ensure system wide crypto policy disables chacha20-poly1305 for ssh | Manual check - requires human verification |
| 1.6.7 | Ensure system wide crypto policy disables EtM for ssh | Manual check - requires human verification |
| 2.1.22 | Ensure only approved services are listening on a network interface | Manual check - requires human verification |
| 3.1.1 | Ensure IPv6 status is identified | Manual check - requires human verification |
| 4.2.1 | Ensure firewalld drops unnecessary services and ports | Manual check - requires human verification |
| 4.3.2 | Ensure nftables established connections are configured | Manual check - requires human verification |
| 6.2.1.2 | Ensure journald log file access is configured | Manual check - requires human verification |
| 6.2.1.3 | Ensure journald log file rotation is configured | Manual check - requires human verification |
| 6.2.2.1.2 | Ensure systemd-journal-upload authentication is configured | Manual check - requires human verification |
| 6.2.3.5 | Ensure rsyslog logging is configured | Manual check - requires human verification |
| 6.2.3.6 | Ensure rsyslog is configured to send logs to a remote log host | Manual check - requires human verification |
| 6.2.3.8 | Ensure rsyslog logrotate is configured | Manual check - requires human verification |
