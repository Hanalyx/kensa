# DISA STIG Red Hat Enterprise Linux 8 V2R6 - Missing Rules

**Framework ID:** `stig-rhel8-v2r6`
**Published:** 2026-01-05
**Platform:** rhel >= 8 <= 8

## Summary

| Metric | Count |
|--------|-------|
| Total Controls | 366 |
| Implemented (have rules) | 116 |
| **Need Rules** | **250** |
| Manual/Site-specific | 0 |

## Controls Needing Rules

These controls are automatable but don't have rules implemented yet.

| Finding ID | Title |
|------------|-------|
| V-230221 | RHEL 8 must be a vendor-supported release. |
| V-230222 | RHEL 8 vendor packaged system security patches and updates must be installed and up to date. |
| V-230224 | All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection. |
| V-230226 | RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon. |
| V-230227 | RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon. |
| V-230228 | All RHEL 8 remote access methods must be monitored. |
| V-230229 | RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor. |
| V-230230 | RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key. |
| V-230233 | The RHEL 8 shadow password suite must be configured to use a sufficient number of hashing rounds. |
| V-230238 | RHEL 8 must prevent system daemons from using Kerberos for authentication. |
| V-230239 | The krb5-workstation package must not be installed on RHEL 8. |
| V-230240 | RHEL 8 must use a Linux Security Module configured to enforce limits on system services. |
| V-230241 | RHEL 8 must have policycoreutils package installed. |
| V-230244 | RHEL 8 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive. |
| V-230245 | The RHEL 8 /var/log/messages file must have mode 0640 or less permissive. |
| V-230246 | The RHEL 8 /var/log/messages file must be owned by root. |
| V-230247 | The RHEL 8 /var/log/messages file must be group-owned by root. |
| V-230248 | The RHEL 8 /var/log directory must have mode 0755 or less permissive. |
| V-230249 | The RHEL 8 /var/log directory must be owned by root. |
| V-230250 | The RHEL 8 /var/log directory must be group-owned by root. |
| V-230253 | RHEL 8 must ensure the SSH server uses strong entropy. |
| V-230257 | RHEL 8 system commands must have mode 755 or less permissive. |
| V-230258 | RHEL 8 system commands must be owned by root. |
| V-230259 | RHEL 8 system commands must be group-owned by root or a system account. |
| V-230260 | RHEL 8 library files must have mode 755 or less permissive. |
| V-230261 | RHEL 8 library files must be owned by root. |
| V-230262 | RHEL 8 library files must be group-owned by root. |
| V-230263 | The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency. |
| V-230267 | RHEL 8 must enable kernel parameters to enforce discretionary access control on symlinks. |
| V-230268 | RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks. |
| V-230271 | RHEL 8 must require users to provide a password for privilege escalation. |
| V-230272 | RHEL 8 must require users to reauthenticate for privilege escalation. |
| V-230273 | RHEL 8 must have the packages required for multifactor authentication installed. |
| V-230274 | RHEL 8 must implement certificate status checking for multifactor authentication. |
| V-230275 | RHEL 8 must accept Personal Identity Verification (PIV) credentials. |
| V-230276 | RHEL 8 must implement non-executable data to protect its memory from unauthorized code execution. |
| V-230277 | RHEL 8 must clear the page allocator to prevent use-after-free attacks. |
| V-230278 | RHEL 8 must disable virtual syscalls. |
| V-230279 | RHEL 8 must clear memory when it is freed to prevent use-after-free attacks. |
| V-230281 | YUM must remove all software components after updated versions have been installed on RHEL 8. |
| V-230283 | There must be no shosts.equiv files on the RHEL 8 operating system. |
| V-230284 | There must be no .shosts files on the RHEL 8 operating system. |
| V-230285 | RHEL 8 must enable the hardware random number generator entropy gatherer service. |
| V-230286 | The RHEL 8 SSH public host key files must have mode 0644 or less permissive. |
| V-230287 | The RHEL 8 SSH private host key files must have mode 0640 or less permissive. |
| V-230288 | The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files. |
| V-230290 | The RHEL 8 SSH daemon must not allow authentication using known host’s authentication. |
| V-230291 | The RHEL 8 SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements. |
| V-230292 | RHEL 8 must use a separate file system for /var. |
| V-230293 | RHEL 8 must use a separate file system for /var/log. |
| V-230294 | RHEL 8 must use a separate file system for the system audit data path. |
| V-230295 | A separate RHEL 8 filesystem must be used for the /tmp directory. |
| V-230296 | RHEL 8 must not permit direct logons to the root account using remote access via SSH. |
| V-230298 | The rsyslog service must be running in RHEL 8. |
| V-230299 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories. |
| V-230300 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot directory. |
| V-230301 | RHEL 8 must prevent special devices on non-root local partitions. |
| V-230302 | RHEL 8 must prevent code from being executed on file systems that contain user home directories. |
| V-230303 | RHEL 8 must prevent special devices on file systems that are used with removable media. |
| V-230304 | RHEL 8 must prevent code from being executed on file systems that are used with removable media. |
| V-230305 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media. |
| V-230306 | RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS). |
| V-230307 | RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS). |
| V-230308 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS). |
| V-230310 | RHEL 8 must disable kernel dumps unless needed. |
| V-230311 | RHEL 8 must disable the kernel.core_pattern. |
| V-230315 | RHEL 8 must disable core dump backtraces. |
| V-230316 | For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured. |
| V-230317 | Executable search paths within the initialization files of all local interactive RHEL 8 users must only contain paths that resolve to the system default or the users home directory. |
| V-230320 | All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file. |
| V-230321 | All RHEL 8 local interactive user home directories must have mode 0750 or less permissive. |
| V-230322 | All RHEL 8 local interactive user home directories must be group-owned by the home directory owner’s primary group. |
| V-230323 | All RHEL 8 local interactive user home directories defined in the /etc/passwd file must exist. |
| V-230324 | All RHEL 8 local interactive user accounts must be assigned a home directory upon creation. |
| V-230325 | All RHEL 8 local initialization files must have mode 0740 or less permissive. |
| V-230326 | All RHEL 8 local files and directories must have a valid owner. |
| V-230327 | All RHEL 8 local files and directories must have a valid group owner. |
| V-230328 | A separate RHEL 8 filesystem must be used for user home directories (such as /home or an equivalent). |
| V-230329 | Unattended or automatic logon via the RHEL 8 graphical user interface must not be allowed. |
| V-230338 | RHEL 8 must ensure account lockouts persist. |
| V-230339 | RHEL 8 must ensure account lockouts persist. |
| V-230340 | RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur. |
| V-230341 | RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur. |
| V-230342 | RHEL 8 must log user name information when unsuccessful logon attempts occur. |
| V-230343 | RHEL 8 must log user name information when unsuccessful logon attempts occur. |
| V-230346 | RHEL 8 must limit the number of concurrent sessions to ten for all accounts and/or account types. |
| V-230347 | RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions. |
| V-230351 | RHEL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed. |
| V-230352 | RHEL 8 must automatically lock graphical user sessions after 15 minutes of inactivity. |
| V-230354 | RHEL 8 must prevent a user from overriding the session lock-delay setting for the graphical user interface. |
| V-230355 | RHEL 8 must map the authenticated identity to the user or group account for PKI-based authentication. |
| V-230356 | RHEL 8 must ensure the password complexity module is enabled in the password-auth file. |
| V-230371 | RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users. |
| V-230372 | RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts. |
| V-230374 | RHEL 8 must automatically expire temporary accounts within 72 hours. |
| V-230376 | RHEL 8 must prohibit the use of cached authentications after one day. |
| V-230378 | RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt. |
| V-230379 | RHEL 8 must not have unnecessary accounts. |
| V-230382 | RHEL 8 must display the date and time of the last successful account logon upon an SSH logon. |
| V-230385 | RHEL 8 must define default permissions for logon and non-logon shells. |
| V-230387 | Cron logging must be implemented in RHEL 8. |
| V-230388 | The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted of an audit processing failure event. |
| V-230389 | The RHEL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) must have mail aliases to be notified of an audit processing failure. |
| V-230390 | The RHEL 8 System must take appropriate action when an audit processing failure occurs. |
| V-230392 | The RHEL 8 audit system must take appropriate action when the audit storage volume is full. |
| V-230393 | The RHEL 8 audit system must audit local events. |
| V-230394 | RHEL 8 must label all off-loaded audit logs before sending them to the central log server. |
| V-230395 | RHEL 8 must resolve audit information before writing to disk. |
| V-230396 | RHEL 8 audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access. |
| V-230397 | RHEL 8 audit logs must be owned by root to prevent unauthorized read access. |
| V-230398 | RHEL 8 audit logs must be group-owned by root to prevent unauthorized read access. |
| V-230399 | RHEL 8 audit log directory must be owned by root to prevent unauthorized read access. |
| V-230400 | RHEL 8 audit log directory must be group-owned by root to prevent unauthorized read access. |
| V-230401 | RHEL 8 audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access. |
| V-230402 | RHEL 8 audit system must protect auditing rules from unauthorized change. |
| V-230403 | RHEL 8 audit system must protect logon UIDs from unauthorized change. |
| V-230412 | Successful/unsuccessful uses of the su command in RHEL 8 must generate an audit record. |
| V-230418 | Successful/unsuccessful uses of the chage command in RHEL 8 must generate an audit record. |
| V-230419 | Successful/unsuccessful uses of the chcon command in RHEL 8 must generate an audit record. |
| V-230421 | Successful/unsuccessful uses of the ssh-agent in RHEL 8 must generate an audit record. |
| V-230422 | Successful/unsuccessful uses of the passwd command in RHEL 8 must generate an audit record. |
| V-230426 | Successful/unsuccessful uses of the unix_update in RHEL 8 must generate an audit record. |
| V-230427 | Successful/unsuccessful uses of postdrop in RHEL 8 must generate an audit record. |
| V-230428 | Successful/unsuccessful uses of postqueue in RHEL 8 must generate an audit record. |
| V-230429 | Successful/unsuccessful uses of semanage in RHEL 8 must generate an audit record. |
| V-230430 | Successful/unsuccessful uses of setfiles in RHEL 8 must generate an audit record. |
| V-230431 | Successful/unsuccessful uses of userhelper in RHEL 8 must generate an audit record. |
| V-230432 | Successful/unsuccessful uses of setsebool in RHEL 8 must generate an audit record. |
| V-230433 | Successful/unsuccessful uses of unix_chkpwd in RHEL 8 must generate an audit record. |
| V-230434 | Successful/unsuccessful uses of the ssh-keysign in RHEL 8 must generate an audit record. |
| V-230435 | Successful/unsuccessful uses of the setfacl command in RHEL 8 must generate an audit record. |
| V-230436 | Successful/unsuccessful uses of the pam_timestamp_check command in RHEL 8 must generate an audit record. |
| V-230437 | Successful/unsuccessful uses of the newgrp command in RHEL 8 must generate an audit record. |
| V-230444 | Successful/unsuccessful uses of the gpasswd command in RHEL 8 must generate an audit record. |
| V-230446 | Successful/unsuccessful uses of the delete_module command in RHEL 8 must generate an audit record. |
| V-230447 | Successful/unsuccessful uses of the crontab command in RHEL 8 must generate an audit record. |
| V-230448 | Successful/unsuccessful uses of the chsh command in RHEL 8 must generate an audit record. |
| V-230449 | Successful/unsuccessful uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls in RHEL 8 must generate an audit record. |
| V-230455 | Successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls in RHEL 8 must generate an audit record. |
| V-230456 | Successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls in RHEL 8 must generate an audit record. |
| V-230462 | Successful/unsuccessful uses of the sudo command in RHEL 8 must generate an audit record. |
| V-230463 | Successful/unsuccessful uses of the usermod command in RHEL 8 must generate an audit record. |
| V-230464 | Successful/unsuccessful uses of the chacl command in RHEL 8 must generate an audit record. |
| V-230465 | Successful/unsuccessful uses of the kmod command in RHEL 8 must generate an audit record. |
| V-230466 | Successful/unsuccessful modifications to the faillock log file in RHEL 8 must generate an audit record. |
| V-230467 | Successful/unsuccessful modifications to the lastlog file in RHEL 8 must generate an audit record. |
| V-230468 | RHEL 8 must enable auditing of processes that start prior to the audit daemon. |
| V-230469 | RHEL 8 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon. |
| V-230470 | RHEL 8 must enable Linux audit logging for the USBGuard daemon. |
| V-230471 | RHEL 8 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited. |
| V-230472 | RHEL 8 audit tools must have a mode of 0755 or less permissive. |
| V-230473 | RHEL 8 audit tools must be owned by root. |
| V-230474 | RHEL 8 audit tools must be group-owned by root. |
| V-230475 | RHEL 8 must use cryptographic mechanisms to protect the integrity of audit tools. |
| V-230476 | RHEL 8 must allocate audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility. |
| V-230477 | RHEL 8 must have the packages required for offloading audit logs installed. |
| V-230478 | RHEL 8 must have the packages required for encrypting offloaded audit logs installed. |
| V-230479 | The RHEL 8 audit records must be off-loaded onto a different system or storage media from the system being audited. |
| V-230480 | RHEL 8 must take appropriate action when the internal event queue is full. |
| V-230481 | RHEL 8 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited. |
| V-230482 | RHEL 8 must authenticate the remote logging server for off-loading audit logs. |
| V-230483 | RHEL 8 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity. |
| V-230484 | RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). |
| V-230485 | RHEL 8 must disable the chrony daemon from acting as a server. |
| V-230486 | RHEL 8 must disable network management of the chrony daemon. |
| V-230487 | RHEL 8 must not have the telnet-server package installed. |
| V-230488 | RHEL 8 must not have any automated bug reporting tools installed. |
| V-230489 | RHEL 8 must not have the sendmail package installed. |
| V-230491 | RHEL 8 must enable mitigations against processor-based vulnerabilities. |
| V-230492 | RHEL 8 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository. |
| V-230493 | RHEL 8 must cover or disable the built-in or attached camera when not in use. |
| V-230494 | RHEL 8 must disable the asynchronous transfer mode (ATM) protocol. |
| V-230495 | RHEL 8 must disable the controller area network (CAN) protocol. |
| V-230496 | RHEL 8 must disable the stream control transmission protocol (SCTP). |
| V-230497 | RHEL 8 must disable the transparent inter-process communication (TIPC) protocol. |
| V-230498 | RHEL 8 must disable mounting of cramfs. |
| V-230500 | RHEL 8 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments. |
| V-230502 | The RHEL 8 file system automounter must be disabled. |
| V-230504 | A RHEL 8 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems. |
| V-230505 | A firewall must be installed on RHEL 8. |
| V-230506 | RHEL 8 wireless network adapters must be disabled. |
| V-230514 | RHEL 8 must mount /var/log with the nodev option. |
| V-230515 | RHEL 8 must mount /var/log with the nosuid option. |
| V-230516 | RHEL 8 must mount /var/log with the noexec option. |
| V-230517 | RHEL 8 must mount /var/log/audit with the nodev option. |
| V-230518 | RHEL 8 must mount /var/log/audit with the nosuid option. |
| V-230519 | RHEL 8 must mount /var/log/audit with the noexec option. |
| V-230523 | The RHEL 8 fapolicy module must be installed. |
| V-230524 | RHEL 8 must block unauthorized peripherals before establishing a connection. |
| V-230525 | A firewall must be able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces. |
| V-230526 | All RHEL 8 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission. |
| V-230527 | RHEL 8 must force a frequent session key renegotiation for SSH connections to the server. |
| V-230532 | The debug-shell systemd service must be disabled on RHEL 8. |
| V-230533 | The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for RHEL 8 operational support. |
| V-230547 | RHEL 8 must restrict exposed kernel pointer addresses access. |
| V-230550 | RHEL 8 must be configured to prevent unrestricted mail relaying. |
| V-230551 | The RHEL 8 file integrity tool must be configured to verify extended attributes. |
| V-230552 | The RHEL 8 file integrity tool must be configured to verify Access Control Lists (ACLs). |
| V-230553 | The graphical display manager must not be installed on RHEL 8 unless approved. |
| V-230554 | RHEL 8 network interfaces must not be in promiscuous mode. |
| V-230555 | RHEL 8 remote X connections for interactive users must be disabled unless to fulfill documented and validated mission requirements. |
| V-230556 | The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display. |
| V-230557 | If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode. |
| V-230558 | A File Transfer Protocol (FTP) server package must not be installed unless mission essential on RHEL 8. |
| V-230559 | The gssproxy package must not be installed unless mission essential on RHEL 8. |
| V-230560 | The iprutils package must not be installed unless mission essential on RHEL 8. |
| V-230561 | The tuned package must not be installed unless mission essential on RHEL 8. |
| V-237640 | The krb5-server package must not be installed on RHEL 8. |
| V-237642 | RHEL 8 must use the invoking user's password for privilege escalation when using "sudo". |
| V-244519 | RHEL 8 must display a banner before granting local or remote access to the system via a graphical user logon. |
| V-244525 | RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive. |
| V-244527 | RHEL 8 must have the packages required to use the hardware random number generator entropy gatherer service. |
| V-244528 | The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements. |
| V-244529 | RHEL 8 must use a separate file system for /var/tmp. |
| V-244530 | RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory. |
| V-244531 | All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive. |
| V-244532 | RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member. |
| V-244533 | RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file. |
| V-244534 | RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file. |
| V-244535 | RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated. |
| V-244536 | RHEL 8 must disable the user list at logon for graphical user interfaces. |
| V-244538 | RHEL 8 must prevent a user from overriding the session idle-delay setting for the graphical user interface. |
| V-244539 | RHEL 8 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface. |
| V-244542 | RHEL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events. |
| V-244543 | RHEL 8 must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization. |
| V-244544 | A firewall must be active on RHEL 8. |
| V-244545 | The RHEL 8 fapolicy module must be enabled. |
| V-244546 | The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs. |
| V-244547 | RHEL 8 must have the USBGuard installed. |
| V-244548 | RHEL 8 must enable the USBGuard. |
| V-244549 | All RHEL 8 networked systems must have SSH installed. |
| V-244554 | RHEL 8 must enable hardening for the Berkeley Packet Filter Just-in-time compiler. |
| V-250315 | RHEL 8 systems, versions 8.2 and above, must configure SELinux context type to allow the use of a non-default faillock tally directory. |
| V-250316 | RHEL 8 systems below version 8.2 must configure SELinux context type to allow the use of a non-default faillock tally directory. |
| V-251707 | RHEL 8 library directories must have mode 755 or less permissive. |
| V-251708 | RHEL 8 library directories must be owned by root. |
| V-251709 | RHEL 8 library directories must be group-owned by root or a system account. |
| V-251710 | The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions. |
| V-251711 | RHEL 8 must specify the default "include" directory for the /etc/sudoers file. |
| V-251712 | The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation. |
| V-251713 | RHEL 8 must ensure the password complexity module is enabled in the system-auth file. |
| V-251716 | RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less. |
| V-251718 | The graphical display manager must not be the default target on RHEL 8 unless approved. |
| V-254520 | RHEL 8 must prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. |
| V-256974 | RHEL 8 must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel. |
| V-272484 | RHEL 8 must elevate the SELinux context when an administrator calls the sudo command. |
| V-274877 | RHEL 8 must audit any script or executable called by cron as root or by any privileged user. |
| V-279931 | RHEL 8 must implement DOD-approved encryption in the bind package. |
| V-279932 | RHEL 8 cryptographic policy must not be overridden. |
| V-279933 | RHEL 8 must have the crypto-policies package installed. |
