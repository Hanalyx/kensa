# DISA STIG Red Hat Enterprise Linux 9 V2R7 - Missing Rules

**Framework ID:** `stig-rhel9-v2r7`
**Published:** 2026-01-05
**Platform:** rhel >= 9 <= 9

## Summary

| Metric | Count |
|--------|-------|
| Total Controls | 446 |
| Implemented (have rules) | 232 |
| **Need Rules** | **214** |
| Manual/Site-specific | 0 |

## Controls Needing Rules

These controls are automatable but don't have rules implemented yet.

| Finding ID | Title |
|------------|-------|
| V-257777 | RHEL 9 must be a vendor-supported release. |
| V-257778 | RHEL 9 vendor packaged system security patches and updates must be installed and up to date. |
| V-257781 | The graphical display manager must not be the default target on RHEL 9 unless approved. |
| V-257782 | RHEL 9 must enable the hardware random number generator entropy gatherer service. |
| V-257783 | RHEL 9 systemd-journald service must be enabled. |
| V-257786 | RHEL 9 debug-shell systemd service must be disabled. |
| V-257788 | RHEL 9 must disable the ability of systemd to spawn an interactive boot process. |
| V-257792 | RHEL 9 must disable virtual system calls. |
| V-257793 | RHEL 9 must clear the page allocator to prevent use-after-free attacks. |
| V-257794 | RHEL 9 must clear memory when it is freed to prevent use-after-free attacks. |
| V-257795 | RHEL 9 must enable mitigations against processor-based vulnerabilities. |
| V-257796 | RHEL 9 must enable auditing of processes that start prior to the audit daemon. |
| V-257801 | RHEL 9 must enable kernel parameters to enforce discretionary access control (DAC) on hardlinks. |
| V-257802 | RHEL 9 must enable kernel parameters to enforce discretionary access (DAC) control on symlinks. |
| V-257804 | RHEL 9 must be configured to disable the Asynchronous Transfer Mode kernel module. |
| V-257805 | RHEL 9 must be configured to disable the Controller Area Network kernel module. |
| V-257818 | The kdump service on RHEL 9 must be disabled. |
| V-257823 | RHEL 9 must be configured so that the cryptographic hashes of system files match vendor values. |
| V-257824 | RHEL 9 must remove all software components after updated versions have been installed. |
| V-257825 | RHEL 9 subscription-manager package must be installed. |
| V-257826 | RHEL 9 must not have a File Transfer Protocol (FTP) server package installed. |
| V-257827 | RHEL 9 must not have the sendmail package installed. |
| V-257828 | RHEL 9 must not have the nfs-utils package installed. |
| V-257834 | RHEL 9 must not have the tuned package installed. |
| V-257842 | RHEL 9 must have the s-nail package installed. |
| V-257843 | A separate RHEL 9 file system must be used for user home directories (such as /home or an equivalent). |
| V-257844 | RHEL 9 must use a separate file system for /tmp. |
| V-257845 | RHEL 9 must use a separate file system for /var. |
| V-257846 | RHEL 9 must use a separate file system for /var/log. |
| V-257875 | RHEL 9 must mount /var/log/audit with the nosuid option. |
| V-257879 | RHEL 9 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection. |
| V-257888 | RHEL 9 permissions of cron configuration files and directories must not be modified from the operating system defaults. |
| V-257889 | All RHEL 9 local initialization files must have mode 0740 or less permissive. |
| V-257922 | RHEL 9 library directories must be owned by root. |
| V-257923 | RHEL 9 library directories must be group-owned by root or a system account. |
| V-257924 | RHEL 9 audit tools must be owned by root. |
| V-257925 | RHEL 9 audit tools must be group-owned by root. |
| V-257926 | RHEL 9 cron configuration files directory must be owned by root. |
| V-257927 | RHEL 9 cron configuration files directory must be group-owned by root. |
| V-257932 | RHEL 9 must be configured so that all system device files are correctly labeled to prevent unauthorized modification. |
| V-257935 | RHEL 9 must have the firewalld package installed. |
| V-257940 | RHEL 9 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments. |
| V-257941 | RHEL 9 network interfaces must not be in promiscuous mode. |
| V-257978 | All RHEL 9 networked systems must have SSH installed. |
| V-257979 | All RHEL 9 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission. |
| V-257983 | RHEL 9 SSHD must accept public key authentication. |
| V-257986 | RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD. |
| V-257996 | RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive. |
| V-257997 | RHEL 9 SSH server configuration file must be group-owned by root. |
| V-257998 | The RHEL 9 SSH server configuration file must be owned by root. |
| V-258001 | RHEL 9 SSH public host key files must have mode 0644 or less permissive. |
| V-258002 | RHEL 9 SSH daemon must not allow compression or must only allow compression after successful authentication. |
| V-258003 | RHEL 9 SSH daemon must not allow GSSAPI authentication. |
| V-258008 | RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files. |
| V-258009 | RHEL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon. |
| V-258012 | RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon. |
| V-258013 | RHEL 9 must prevent a user from overriding the banner-message-enable setting for the graphical user interface. |
| V-258015 | RHEL 9 must prevent a user from overriding the disabling of the graphical user interface automount function. |
| V-258016 | RHEL 9 must disable the graphical user interface autorun function unless required. |
| V-258017 | RHEL 9 must prevent a user from overriding the disabling of the graphical user interface autorun function. |
| V-258020 | RHEL 9 must prevent a user from overriding the disabling of the graphical user smart card removal action. |
| V-258021 | RHEL 9 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions. |
| V-258022 | RHEL 9 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface. |
| V-258023 | RHEL 9 must automatically lock graphical user sessions after 10 minutes of inactivity. |
| V-258024 | RHEL 9 must prevent a user from overriding the session idle-delay setting for the graphical user interface. |
| V-258025 | RHEL 9 must initiate a session lock for graphical user interfaces when the screensaver is activated. |
| V-258026 | RHEL 9 must prevent a user from overriding the session lock-delay setting for the graphical user interface. |
| V-258027 | RHEL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image. |
| V-258028 | RHEL 9 effective dconf policy must match the policy keyfiles. |
| V-258029 | RHEL 9 must disable the ability of a user to restart the system from the login screen. |
| V-258030 | RHEL 9 must prevent a user from overriding the disable-restart-buttons setting for the graphical user interface. |
| V-258033 | RHEL 9 must disable the user list at logon for graphical user interfaces. |
| V-258035 | RHEL 9 must have the USBGuard package installed. |
| V-258036 | RHEL 9 must have the USBGuard package enabled. |
| V-258037 | RHEL 9 must enable Linux audit logging for the USBGuard daemon. |
| V-258038 | RHEL 9 must block unauthorized peripherals before establishing a connection. |
| V-258040 | RHEL 9 wireless network adapters must be disabled. |
| V-258043 | All RHEL 9 local interactive user accounts must be assigned a home directory upon creation. |
| V-258045 | RHEL 9 duplicate User IDs (UIDs) must not exist for interactive users. |
| V-258047 | RHEL 9 must automatically expire temporary accounts within 72 hours. |
| V-258048 | All RHEL 9 interactive users must have a primary group that exists. |
| V-258050 | Executable search paths within the initialization files of all local interactive RHEL 9 users must only contain paths that resolve to the system default or the users home directory. |
| V-258051 | All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file. |
| V-258052 | All RHEL 9 local interactive user home directories defined in the /etc/passwd file must exist. |
| V-258053 | All RHEL 9 local interactive user home directories must be group-owned by the home directory owner's primary group. |
| V-258058 | RHEL 9 must not have unauthorized accounts. |
| V-258060 | RHEL 9 must ensure account lockouts persist. |
| V-258061 | RHEL 9 groups must have unique Group ID (GID). |
| V-258069 | RHEL 9 must limit the number of concurrent sessions to ten for all accounts and/or account types. |
| V-258070 | RHEL 9 must log username information when unsuccessful logon attempts occur. |
| V-258071 | RHEL 9 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt. |
| V-258072 | RHEL 9 must define default permissions for the bash shell. |
| V-258073 | RHEL 9 must define default permissions for the c shell. |
| V-258074 | RHEL 9 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files. |
| V-258075 | RHEL 9 must define default permissions for the system default profile. |
| V-258078 | RHEL 9 must use a Linux Security Module configured to enforce limits on system services. |
| V-258080 | RHEL 9 must configure SELinux context type to allow the use of a nondefault faillock tally directory. |
| V-258081 | RHEL 9 must have policycoreutils package installed. |
| V-258082 | RHEL 9 policycoreutils-python-utils package must be installed. |
| V-258083 | RHEL 9 must have the sudo package installed. |
| V-258085 | RHEL 9 must use the invoking user's password for privilege escalation when using "sudo". |
| V-258086 | RHEL 9 must require users to reauthenticate for privilege escalation. |
| V-258089 | RHEL 9 fapolicy module must be installed. |
| V-258090 | RHEL 9 fapolicy module must be enabled. |
| V-258091 | RHEL 9 must ensure the password complexity module in the system-auth file is configured for three retries or less. |
| V-258095 | RHEL 9 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file. |
| V-258096 | RHEL 9 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file. |
| V-258097 | RHEL 9 must ensure the password complexity module is enabled in the password-auth file. |
| V-258098 | RHEL 9 must ensure the password complexity module is enabled in the system-auth file. |
| V-258099 | RHEL 9 password-auth must be configured to use a sufficient number of hashing rounds. |
| V-258100 | RHEL 9 system-auth must be configured to use a sufficient number of hashing rounds. |
| V-258101 | RHEL 9 must enforce password complexity rules for the root account. |
| V-258106 | RHEL 9 must require users to provide a password for privilege escalation. |
| V-258116 | RHEL 9 must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords. |
| V-258117 | RHEL 9 must be configured to use the shadow file to store only encrypted representations of passwords. |
| V-258118 | RHEL 9 must not be configured to bypass password requirements for privilege escalation. |
| V-258121 | RHEL 9 must use the common access card (CAC) smart card driver. |
| V-258122 | RHEL 9 must enable certificate based smart card authentication. |
| V-258123 | RHEL 9 must implement certificate status checking for multifactor authentication. |
| V-258124 | RHEL 9 must have the pcsc-lite package installed. |
| V-258125 | The pcscd service on RHEL 9 must be active. |
| V-258126 | RHEL 9 must have the opensc package installed. |
| V-258127 | RHEL 9, for PKI-based authentication, must enforce authorized access to the corresponding private key. |
| V-258131 | RHEL 9, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor. |
| V-258132 | RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication. |
| V-258133 | RHEL 9 must prohibit the use of cached authenticators after one day. |
| V-258134 | RHEL 9 must have the AIDE package installed. |
| V-258135 | RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered. |
| V-258137 | RHEL 9 must use cryptographic mechanisms to protect the integrity of audit tools. |
| V-258138 | RHEL 9 must be configured so that the file integrity tool verifies Access Control Lists (ACLs). |
| V-258139 | RHEL 9 must be configured so that the file integrity tool verifies extended attributes. |
| V-258140 | RHEL 9 must have the rsyslog package installed. |
| V-258141 | RHEL 9 must have the packages required for encrypting offloaded audit logs installed. |
| V-258142 | The rsyslog service on RHEL 9 must be active. |
| V-258143 | RHEL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation. |
| V-258144 | All RHEL 9 remote access methods must be monitored. |
| V-258146 | RHEL 9 must authenticate the remote logging server for offloading audit logs via rsyslog. |
| V-258147 | RHEL 9 must encrypt the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog. |
| V-258148 | RHEL 9 must encrypt via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog. |
| V-258149 | RHEL 9 must be configured to forward audit records via TCP to a different system or media from the system being audited via rsyslog. |
| V-258150 | RHEL 9 must use cron logging. |
| V-258153 | RHEL 9 audit system must take appropriate action when an error writing to the audit storage volume occurs. |
| V-258154 | RHEL 9 audit system must take appropriate action when the audit storage volume is full. |
| V-258155 | RHEL 9 must allocate audit record storage capacity to store at least one week's worth of audit records. |
| V-258156 | RHEL 9 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity. |
| V-258157 | RHEL 9 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent utilization. |
| V-258158 | RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity. |
| V-258159 | RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity. |
| V-258160 | RHEL 9 audit system must take appropriate action when the audit files have reached maximum size. |
| V-258161 | RHEL 9 must label all offloaded audit logs before sending them to the central log server. |
| V-258162 | RHEL 9 must take appropriate action when the internal event queue is full. |
| V-258163 | RHEL 9 System Administrator (SA) and/or information system security officer (ISSO) (at a minimum) must be alerted of an audit processing failure event. |
| V-258164 | RHEL 9 audit system must audit local events. |
| V-258165 | RHEL 9 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access. |
| V-258166 | RHEL 9 audit log directory must be owned by root to prevent unauthorized read access. |
| V-258167 | RHEL 9 audit logs file must have mode 0600 or less permissive to prevent unauthorized access to the audit log. |
| V-258168 | RHEL 9 must periodically flush audit records to disk to prevent the loss of audit records. |
| V-258169 | RHEL 9 must produce audit records containing information to establish the identity of any individual or process associated with the event. |
| V-258170 | RHEL 9 must write audit records to disk. |
| V-258171 | RHEL 9 must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited. |
| V-258173 | RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon. |
| V-258174 | RHEL 9 must have mail aliases to notify the information system security officer (ISSO) and system administrator (SA) (at a minimum) in the event of an audit processing failure. |
| V-258175 | RHEL 9 audispd-plugins package must be installed. |
| V-258176 | RHEL 9 must audit uses of the "execve" system call. |
| V-258181 | RHEL 9 must audit all uses of the chacl command. |
| V-258182 | RHEL 9 must audit all uses of the setfacl command. |
| V-258183 | RHEL 9 must audit all uses of the chcon command. |
| V-258184 | RHEL 9 must audit all uses of the semanage command. |
| V-258185 | RHEL 9 must audit all uses of the setfiles command. |
| V-258186 | RHEL 9 must audit all uses of the setsebool command. |
| V-258188 | RHEL 9 must audit all uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls. |
| V-258191 | RHEL 9 must audit all uses of the chage command. |
| V-258192 | RHEL 9 must audit all uses of the chsh command. |
| V-258193 | RHEL 9 must audit all uses of the crontab command. |
| V-258194 | RHEL 9 must audit all uses of the gpasswd command. |
| V-258195 | RHEL 9 must audit all uses of the kmod command. |
| V-258196 | RHEL 9 must audit all uses of the newgrp command. |
| V-258197 | RHEL 9 must audit all uses of the pam_timestamp_check command. |
| V-258198 | RHEL 9 must audit all uses of the passwd command. |
| V-258199 | RHEL 9 must audit all uses of the postdrop command. |
| V-258200 | RHEL 9 must audit all uses of the postqueue command. |
| V-258201 | RHEL 9 must audit all uses of the ssh-agent command. |
| V-258202 | RHEL 9 must audit all uses of the ssh-keysign command. |
| V-258203 | RHEL 9 must audit all uses of the su command. |
| V-258204 | RHEL 9 must audit all uses of the sudo command. |
| V-258205 | RHEL 9 must audit all uses of the sudoedit command. |
| V-258206 | RHEL 9 must audit all uses of the unix_chkpwd command. |
| V-258207 | RHEL 9 must audit all uses of the unix_update command. |
| V-258208 | RHEL 9 must audit all uses of the userhelper command. |
| V-258209 | RHEL 9 must audit all uses of the usermod command. |
| V-258211 | Successful/unsuccessful uses of the init command in RHEL 9 must generate an audit record. |
| V-258212 | Successful/unsuccessful uses of the poweroff command in RHEL 9 must generate an audit record. |
| V-258213 | Successful/unsuccessful uses of the reboot command in RHEL 9 must generate an audit record. |
| V-258214 | Successful/unsuccessful uses of the shutdown command in RHEL 9 must generate an audit record. |
| V-258215 | Successful/unsuccessful uses of the umount system call in RHEL 9 must generate an audit record. |
| V-258216 | Successful/unsuccessful uses of the umount2 system call in RHEL 9 must generate an audit record. |
| V-258221 | RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd. |
| V-258222 | RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd. |
| V-258223 | RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow. |
| V-258224 | RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock. |
| V-258225 | RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/lastlog. |
| V-258227 | RHEL 9 must take appropriate action when a critical audit processing failure occurs. |
| V-258228 | RHEL 9 audit system must protect logon UIDs from unauthorized change. |
| V-258229 | RHEL 9 audit system must protect auditing rules from unauthorized change. |
| V-258234 | RHEL 9 must have the crypto-policies package installed. |
| V-258236 | RHEL 9 cryptographic policy must not be overridden. |
| V-258242 | RHEL 9 must implement DOD-approved encryption in the bind package. |
| V-270174 | RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon. |
| V-270175 | RHEL 9 "/etc/audit/" must be owned by root. |
| V-270176 | RHEL 9 "/etc/audit/" must be group-owned by root. |
| V-270180 | The RHEL 9 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs. |
| V-272488 | RHEL 9 must have the Postfix package installed. |
| V-272496 | RHEL 9 must elevate the SELinux context when an administrator calls the sudo command. |
| V-279936 | RHEL 9 must audit any script or executable called by cron as root or by any privileged user. |
