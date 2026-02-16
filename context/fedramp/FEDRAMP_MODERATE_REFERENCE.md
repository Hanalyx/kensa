# FedRAMP Moderate Rev 5 — Reference Guide

**Source:** GSA/fedramp-automation OSCAL profile
**URL:** https://github.com/GSA/fedramp-automation/blob/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json
**Catalog:** NIST SP 800-53 Rev 5
**Last synced:** 2026-02-16

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total controls | 323 |
| Control families | 18 |
| Technical (SSH-enforceable) | 83 |
| Semi-technical (partially automatable) | 56 |
| Procedural (organizational only) | 184 |

### Coverage by Family

| Family | ID | Total | Technical | Semi-Tech | Procedural |
|--------|----|-------|-----------|-----------|------------|
| Access Control | AC | 43 | 26 | 8 | 9 |
| Awareness and Training | AT | 6 | 0 | 0 | 6 |
| Audit and Accountability | AU | 16 | 9 | 6 | 1 |
| Assessment, Authorization, and Monitoring | CA | 14 | 0 | 2 | 12 |
| Configuration Management | CM | 27 | 6 | 14 | 7 |
| Contingency Planning | CP | 23 | 0 | 0 | 23 |
| Identification and Authentication | IA | 27 | 14 | 2 | 11 |
| Incident Response | IR | 17 | 0 | 0 | 17 |
| Maintenance | MA | 10 | 0 | 0 | 10 |
| Media Protection | MP | 7 | 0 | 0 | 7 |
| Physical and Environmental Protection | PE | 19 | 0 | 0 | 19 |
| Planning | PL | 7 | 0 | 0 | 7 |
| Personnel Security | PS | 10 | 0 | 0 | 10 |
| Risk Assessment | RA | 11 | 0 | 4 | 7 |
| System and Services Acquisition | SA | 21 | 0 | 0 | 21 |
| System and Communications Protection | SC | 29 | 16 | 11 | 2 |
| System and Information Integrity | SI | 24 | 12 | 9 | 3 |
| Supply Chain Risk Management | SR | 12 | 0 | 0 | 12 |

---

## FedRAMP-Specific Parameters

FedRAMP Moderate extends NIST 800-53 with stricter parameter values:

| Control | Parameter | FedRAMP Value |
|---------|-----------|---------------|
| AC-2 | Inactive account disable | 90 days |
| AC-7 | Unsuccessful logon attempts | 3 |
| AC-7 | Time period for counting | 15 minutes |
| AC-7 | Lockout duration | 60 minutes |
| AU-4 | Audit storage capacity | Sufficient for retention period |
| IA-5 | Minimum password length | 12 characters |
| IA-5 | Password complexity | Upper, lower, numeric, special |
| IA-5 | Password lifetime | 60 days |
| IA-5 | Password history | 24 remembered |
| SC-7 | Default firewall policy | Deny by default |

---

## Applicability Classification

Controls are classified for RHEL host-level SSH enforcement:

- **Technical** — Fully enforceable via SSH checks (e.g., checking PAM config, SSH settings, audit rules, service status, file permissions)
- **Semi-technical** — Partially automatable (e.g., checking if rsyslog forwards to SIEM, but the SIEM itself is out of scope)
- **Procedural** — Organizational/documentation only (e.g., security awareness training, incident response plans, physical access controls)

---

## Control Listing by Family

### AC — Access Control (43 controls)

| ID | Title | Type |
|----|-------|------|
| AC-1 | Policy and Procedures | Procedural |
| AC-2 | Account Management | Technical |
| AC-2(1) | Automated System Account Management | Technical |
| AC-2(2) | Automated Temporary and Emergency Account Management | Technical |
| AC-2(3) | Disable Accounts | Technical |
| AC-2(4) | Automated Audit Actions | Technical |
| AC-2(5) | Inactivity Logout | Technical |
| AC-2(7) | Privileged User Accounts | Semi-technical |
| AC-2(9) | Restrictions on Use of Shared and Group Accounts | Semi-technical |
| AC-2(12) | Account Monitoring for Atypical Usage | Semi-technical |
| AC-2(13) | Disable Accounts for High-Risk Individuals | Procedural |
| AC-3 | Access Enforcement | Technical |
| AC-4 | Information Flow Enforcement | Technical |
| AC-4(21) | Physical or Logical Separation of Information Flows | Semi-technical |
| AC-5 | Separation of Duties | Semi-technical |
| AC-6 | Least Privilege | Technical |
| AC-6(1) | Authorize Access to Security Functions | Technical |
| AC-6(2) | Non-Privileged Access for Nonsecurity Functions | Technical |
| AC-6(5) | Privileged Accounts | Technical |
| AC-6(7) | Review of User Privileges | Procedural |
| AC-6(9) | Log Use of Privileged Functions | Technical |
| AC-6(10) | Prohibit Non-Privileged Users from Executing Privileged Functions | Technical |
| AC-7 | Unsuccessful Logon Attempts | Technical |
| AC-8 | System Use Notification | Technical |
| AC-11 | Device Lock | Technical |
| AC-11(1) | Pattern-Hiding Displays | Technical |
| AC-12 | Session Termination | Technical |
| AC-14 | Permitted Actions Without Identification or Authentication | Procedural |
| AC-17 | Remote Access | Technical |
| AC-17(1) | Monitoring and Control | Technical |
| AC-17(2) | Protection of Confidentiality and Integrity Using Encryption | Technical |
| AC-17(3) | Managed Access Control Points | Semi-technical |
| AC-17(4) | Privileged Commands and Access | Technical |
| AC-18 | Wireless Access | Technical |
| AC-18(1) | Authentication and Encryption | Technical |
| AC-18(3) | Disable Wireless Networking | Technical |
| AC-19 | Access Control for Mobile Devices | Procedural |
| AC-19(5) | Full Device or Container-Based Encryption | Semi-technical |
| AC-20 | Use of External Systems | Procedural |
| AC-20(1) | Limits on Authorized Use | Procedural |
| AC-20(2) | Portable Storage Devices — Restricted Use | Semi-technical |
| AC-21 | Information Sharing | Procedural |
| AC-22 | Publicly Accessible Content | Procedural |

### AT — Awareness and Training (6 controls)

| ID | Title | Type |
|----|-------|------|
| AT-1 | Policy and Procedures | Procedural |
| AT-2 | Literacy Training and Awareness | Procedural |
| AT-2(2) | Insider Threat | Procedural |
| AT-2(3) | Social Engineering and Mining | Procedural |
| AT-3 | Role-Based Training | Procedural |
| AT-4 | Training Records | Procedural |

### AU — Audit and Accountability (16 controls)

| ID | Title | Type |
|----|-------|------|
| AU-1 | Policy and Procedures | Procedural |
| AU-2 | Event Logging | Technical |
| AU-3 | Content of Audit Records | Technical |
| AU-3(1) | Additional Audit Information | Technical |
| AU-4 | Audit Log Storage Capacity | Technical |
| AU-5 | Response to Audit Logging Process Failures | Technical |
| AU-6 | Audit Record Review, Analysis, and Reporting | Semi-technical |
| AU-6(1) | Automated Process Integration | Semi-technical |
| AU-6(3) | Correlate Audit Record Repositories | Semi-technical |
| AU-7 | Audit Record Reduction and Report Generation | Semi-technical |
| AU-7(1) | Automatic Processing | Semi-technical |
| AU-8 | Time Stamps | Technical |
| AU-9 | Protection of Audit Information | Technical |
| AU-9(4) | Access by Subset of Privileged Users | Technical |
| AU-11 | Audit Record Retention | Semi-technical |
| AU-12 | Audit Record Generation | Technical |

### CA — Assessment, Authorization, and Monitoring (14 controls)

| ID | Title | Type |
|----|-------|------|
| CA-1 | Policy and Procedures | Procedural |
| CA-2 | Control Assessments | Procedural |
| CA-2(1) | Independent Assessors | Procedural |
| CA-2(3) | Leveraging Results from External Organizations | Procedural |
| CA-3 | Information Exchange | Procedural |
| CA-5 | Plan of Action and Milestones | Procedural |
| CA-6 | Authorization | Procedural |
| CA-7 | Continuous Monitoring | Semi-technical |
| CA-7(1) | Independent Assessment | Procedural |
| CA-7(4) | Risk Monitoring | Procedural |
| CA-8 | Penetration Testing | Procedural |
| CA-8(1) | Independent Penetration Testing Agent or Team | Procedural |
| CA-8(2) | Red Team Exercises | Procedural |
| CA-9 | Internal System Connections | Semi-technical |

### CM — Configuration Management (27 controls)

| ID | Title | Type |
|----|-------|------|
| CM-1 | Policy and Procedures | Procedural |
| CM-2 | Baseline Configuration | Semi-technical |
| CM-2(2) | Automation Support for Accuracy and Currency | Semi-technical |
| CM-2(3) | Retention of Previous Configurations | Semi-technical |
| CM-2(7) | Configure Systems and Components for High-Risk Areas | Semi-technical |
| CM-3 | Configuration Change Control | Semi-technical |
| CM-3(2) | Testing, Validation, and Documentation of Changes | Procedural |
| CM-3(4) | Security and Privacy Representatives | Procedural |
| CM-4 | Impact Analyses | Procedural |
| CM-4(2) | Verification of Controls | Procedural |
| CM-5 | Access Restrictions for Change | Technical |
| CM-5(1) | Automated Access Enforcement and Audit Records | Technical |
| CM-5(5) | Privilege Limitation for Production and Operation | Semi-technical |
| CM-6 | Configuration Settings | Technical |
| CM-6(1) | Automated Management, Application, and Verification | Technical |
| CM-7 | Least Functionality | Technical |
| CM-7(1) | Periodic Review | Semi-technical |
| CM-7(2) | Prevent Program Execution | Technical |
| CM-7(5) | Authorized Software — Allow-by-Exception | Semi-technical |
| CM-8 | System Component Inventory | Semi-technical |
| CM-8(1) | Updates During Installation and Removal | Semi-technical |
| CM-8(3) | Automated Unauthorized Component Detection | Semi-technical |
| CM-9 | Configuration Management Plan | Procedural |
| CM-10 | Software Usage Restrictions | Procedural |
| CM-11 | User-Installed Software | Semi-technical |
| CM-12 | Information Location | Semi-technical |
| CM-12(1) | Automated Tools to Support Information Location | Semi-technical |

### CP — Contingency Planning (23 controls)

All 23 controls are **Procedural** (backup plans, alternate sites, recovery procedures).

| ID | Title |
|----|-------|
| CP-1 | Policy and Procedures |
| CP-2 | Contingency Plan |
| CP-2(1) | Coordinate with Related Plans |
| CP-2(3) | Resume Mission and Business Functions |
| CP-2(8) | Identify Critical Assets |
| CP-3 | Contingency Training |
| CP-4 | Contingency Plan Testing |
| CP-4(1) | Coordinate with Related Plans |
| CP-6 | Alternate Storage Site |
| CP-6(1) | Separation from Primary Site |
| CP-6(3) | Accessibility |
| CP-7 | Alternate Processing Site |
| CP-7(1) | Separation from Primary Site |
| CP-7(2) | Accessibility |
| CP-7(3) | Priority of Service |
| CP-8 | Telecommunications Services |
| CP-8(1) | Priority of Service Provisions |
| CP-8(2) | Single Points of Failure |
| CP-9 | System Backup |
| CP-9(1) | Testing for Reliability and Integrity |
| CP-9(8) | Cryptographic Protection |
| CP-10 | System Recovery and Reconstitution |
| CP-10(2) | Transaction Recovery |

### IA — Identification and Authentication (27 controls)

| ID | Title | Type |
|----|-------|------|
| IA-1 | Policy and Procedures | Procedural |
| IA-2 | Identification and Authentication (Organizational Users) | Technical |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | Technical |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | Technical |
| IA-2(5) | Individual Authentication with Group Authentication | Technical |
| IA-2(6) | Access to Accounts — Separate Device | Semi-technical |
| IA-2(8) | Access to Accounts — Replay Resistant | Technical |
| IA-2(12) | Acceptance of PIV Credentials | Technical |
| IA-3 | Device Identification and Authentication | Technical |
| IA-4 | Identifier Management | Semi-technical |
| IA-4(4) | Identify User Status | Technical |
| IA-5 | Authenticator Management | Technical |
| IA-5(1) | Password-Based Authentication | Technical |
| IA-5(2) | Public Key-Based Authentication | Technical |
| IA-5(6) | Protection of Authenticators | Procedural |
| IA-5(7) | No Embedded Unencrypted Static Authenticators | Procedural |
| IA-6 | Authentication Feedback | Technical |
| IA-7 | Cryptographic Module Authentication | Technical |
| IA-8 | Identification and Authentication (Non-Organizational Users) | Procedural |
| IA-8(1) | Acceptance of PIV Credentials from Other Agencies | Procedural |
| IA-8(2) | Acceptance of External Authenticators | Procedural |
| IA-8(4) | Use of Defined Profiles | Procedural |
| IA-11 | Re-Authentication | Technical |
| IA-12 | Identity Proofing | Procedural |
| IA-12(2) | Identity Evidence | Procedural |
| IA-12(3) | Identity Evidence Validation and Verification | Procedural |
| IA-12(5) | Address Confirmation | Procedural |

### IR — Incident Response (17 controls)

All 17 controls are **Procedural** (incident handling, reporting, response plans).

| ID | Title |
|----|-------|
| IR-1 | Policy and Procedures |
| IR-2 | Incident Response Training |
| IR-3 | Incident Response Testing |
| IR-3(2) | Coordination with Related Plans |
| IR-4 | Incident Handling |
| IR-4(1) | Automated Incident Handling Processes |
| IR-5 | Incident Monitoring |
| IR-6 | Incident Reporting |
| IR-6(1) | Automated Reporting |
| IR-6(3) | Supply Chain Coordination |
| IR-7 | Incident Response Assistance |
| IR-7(1) | Automation Support for Availability of Information and Support |
| IR-8 | Incident Response Plan |
| IR-9 | Information Spillage Response |
| IR-9(2) | Training |
| IR-9(3) | Post-Spill Operations |
| IR-9(4) | Exposure to Unauthorized Personnel |

### MA — Maintenance (10 controls)

All 10 controls are **Procedural**.

| ID | Title |
|----|-------|
| MA-1 | Policy and Procedures |
| MA-2 | Controlled Maintenance |
| MA-3 | Maintenance Tools |
| MA-3(1) | Inspect Tools |
| MA-3(2) | Inspect Media |
| MA-3(3) | Prevent Unauthorized Removal |
| MA-4 | Nonlocal Maintenance |
| MA-5 | Maintenance Personnel |
| MA-5(1) | Individuals Without Appropriate Access |
| MA-6 | Timely Maintenance |

### MP — Media Protection (7 controls)

All 7 controls are **Procedural**.

| ID | Title |
|----|-------|
| MP-1 | Policy and Procedures |
| MP-2 | Media Access |
| MP-3 | Media Marking |
| MP-4 | Media Storage |
| MP-5 | Media Transport |
| MP-6 | Media Sanitization |
| MP-7 | Media Use |

### PE — Physical and Environmental Protection (19 controls)

All 19 controls are **Procedural**.

| ID | Title |
|----|-------|
| PE-1 | Policy and Procedures |
| PE-2 | Physical Access Authorizations |
| PE-3 | Physical Access Control |
| PE-4 | Access Control for Transmission |
| PE-5 | Access Control for Output Devices |
| PE-6 | Monitoring Physical Access |
| PE-6(1) | Intrusion Alarms and Surveillance Equipment |
| PE-8 | Visitor Access Records |
| PE-9 | Power Equipment and Cabling |
| PE-10 | Emergency Shutoff |
| PE-11 | Emergency Power |
| PE-12 | Emergency Lighting |
| PE-13 | Fire Protection |
| PE-13(1) | Detection Systems — Automatic Activation and Notification |
| PE-13(2) | Suppression Systems — Automatic Activation and Notification |
| PE-14 | Environmental Controls |
| PE-15 | Water Damage Protection |
| PE-16 | Delivery and Removal |
| PE-17 | Alternate Work Site |

### PL — Planning (7 controls)

All 7 controls are **Procedural**.

| ID | Title |
|----|-------|
| PL-1 | Policy and Procedures |
| PL-2 | System Security and Privacy Plans |
| PL-4 | Rules of Behavior |
| PL-4(1) | Social Media and External Site/Application Usage Restrictions |
| PL-8 | Security and Privacy Architectures |
| PL-10 | Baseline Selection |
| PL-11 | Baseline Tailoring |

### PS — Personnel Security (10 controls)

All 10 controls are **Procedural**.

| ID | Title |
|----|-------|
| PS-1 | Policy and Procedures |
| PS-2 | Position Risk Designation |
| PS-3 | Personnel Screening |
| PS-3(3) | Information Requiring Special Protective Measures |
| PS-4 | Personnel Termination |
| PS-5 | Personnel Transfer |
| PS-6 | Access Agreements |
| PS-7 | External Personnel Security |
| PS-8 | Personnel Sanctions |
| PS-9 | Position Descriptions |

### RA — Risk Assessment (11 controls)

| ID | Title | Type |
|----|-------|------|
| RA-1 | Policy and Procedures | Procedural |
| RA-2 | Security Categorization | Procedural |
| RA-3 | Risk Assessment | Procedural |
| RA-3(1) | Supply Chain Risk Assessment | Procedural |
| RA-5 | Vulnerability Monitoring and Scanning | Semi-technical |
| RA-5(2) | Update Vulnerabilities to Be Scanned | Semi-technical |
| RA-5(3) | Breadth and Depth of Coverage | Semi-technical |
| RA-5(5) | Privileged Access | Semi-technical |
| RA-5(11) | Public Disclosure Program | Procedural |
| RA-7 | Risk Response | Procedural |
| RA-9 | Criticality Analysis | Procedural |

### SA — System and Services Acquisition (21 controls)

All 21 controls are **Procedural**.

| ID | Title |
|----|-------|
| SA-1 | Policy and Procedures |
| SA-2 | Allocation of Resources |
| SA-3 | System Development Life Cycle |
| SA-4 | Acquisition Process |
| SA-4(1) | Functional Properties of Controls |
| SA-4(2) | Design and Implementation Information for Controls |
| SA-4(9) | Functions, Ports, Protocols, and Services in Use |
| SA-4(10) | Use of Approved PIV Products |
| SA-5 | System Documentation |
| SA-8 | Security and Privacy Engineering Principles |
| SA-9 | External System Services |
| SA-9(1) | Risk Assessments and Organizational Approvals |
| SA-9(2) | Identification of Functions, Ports, Protocols, and Services |
| SA-9(5) | Processing, Storage, and Service Location |
| SA-10 | Developer Configuration Management |
| SA-11 | Developer Testing and Evaluation |
| SA-11(1) | Static Code Analysis |
| SA-11(2) | Threat Modeling and Vulnerability Analyses |
| SA-15 | Development Process, Standards, and Tools |
| SA-15(3) | Criticality Analysis |
| SA-22 | Unsupported System Components |

### SC — System and Communications Protection (29 controls)

| ID | Title | Type |
|----|-------|------|
| SC-1 | Policy and Procedures | Procedural |
| SC-2 | Separation of System and User Functionality | Technical |
| SC-4 | Information in Shared System Resources | Technical |
| SC-5 | Denial-of-Service Protection | Technical |
| SC-7 | Boundary Protection | Technical |
| SC-7(3) | Access Points | Semi-technical |
| SC-7(4) | External Telecommunications Services | Technical |
| SC-7(5) | Deny by Default — Allow by Exception | Technical |
| SC-7(7) | Split Tunneling for Remote Devices | Semi-technical |
| SC-7(8) | Route Traffic to Authenticated Proxy Servers | Semi-technical |
| SC-7(12) | Host-Based Protection | Semi-technical |
| SC-7(18) | Fail Secure | Semi-technical |
| SC-8 | Transmission Confidentiality and Integrity | Technical |
| SC-8(1) | Cryptographic Protection | Technical |
| SC-10 | Network Disconnect | Technical |
| SC-12 | Cryptographic Key Establishment and Management | Technical |
| SC-13 | Cryptographic Protection | Technical |
| SC-15 | Collaborative Computing Devices and Applications | Semi-technical |
| SC-17 | Public Key Infrastructure Certificates | Semi-technical |
| SC-18 | Mobile Code | Procedural |
| SC-20 | Secure Name/Address Resolution Service (Authoritative Source) | Semi-technical |
| SC-21 | Secure Name/Address Resolution Service (Recursive or Caching Resolver) | Semi-technical |
| SC-22 | Architecture and Provisioning for Name/Address Resolution Service | Semi-technical |
| SC-23 | Session Authenticity | Technical |
| SC-28 | Protection of Information at Rest | Technical |
| SC-28(1) | Cryptographic Protection | Technical |
| SC-39 | Process Isolation | Technical |
| SC-45 | System Time Synchronization | Technical |
| SC-45(1) | Synchronization with Authoritative Time Source | Semi-technical |

### SI — System and Information Integrity (24 controls)

| ID | Title | Type |
|----|-------|------|
| SI-1 | Policy and Procedures | Procedural |
| SI-2 | Flaw Remediation | Semi-technical |
| SI-2(2) | Automated Flaw Remediation Status | Semi-technical |
| SI-2(3) | Time to Remediate Flaws and Benchmarks for Corrective Actions | Semi-technical |
| SI-3 | Malicious Code Protection | Technical |
| SI-4 | System Monitoring | Technical |
| SI-4(1) | System-Wide Intrusion Detection System | Semi-technical |
| SI-4(2) | Automated Tools and Mechanisms for Real-Time Analysis | Technical |
| SI-4(4) | Inbound and Outbound Communications Traffic | Technical |
| SI-4(5) | System-Generated Alerts | Technical |
| SI-4(16) | Correlate Monitoring Information | Semi-technical |
| SI-4(18) | Analyze Traffic and Event Patterns | Semi-technical |
| SI-4(23) | Host-Based Devices | Semi-technical |
| SI-5 | Security Alerts, Advisories, and Directives | Procedural |
| SI-6 | Security and Privacy Function Verification | Technical |
| SI-7 | Software, Firmware, and Information Integrity | Technical |
| SI-7(1) | Integrity Checks | Technical |
| SI-7(7) | Integration of Detection and Response | Technical |
| SI-8 | Spam Protection | Semi-technical |
| SI-8(2) | Automatic Updates | Semi-technical |
| SI-10 | Information Input Validation | Technical |
| SI-11 | Error Handling | Technical |
| SI-12 | Information Management and Retention | Procedural |
| SI-16 | Memory Protection | Technical |

### SR — Supply Chain Risk Management (12 controls)

All 12 controls are **Procedural**.

| ID | Title |
|----|-------|
| SR-1 | Policy and Procedures |
| SR-2 | Supply Chain Risk Management Plan |
| SR-2(1) | Establish SCRM Team |
| SR-3 | Supply Chain Controls and Processes |
| SR-5 | Acquisition Strategies, Tools, and Methods |
| SR-6 | Supplier Assessments and Reviews |
| SR-8 | Notification Agreements |
| SR-10 | Inspection of Systems or Components |
| SR-11 | Component Authenticity |
| SR-11(1) | Anti-Counterfeit Training |
| SR-11(2) | Configuration Control for Component Service and Repair |
| SR-12 | Component Disposal |

---

## Mapping to Aegis Rule Categories

Controls with **technical** applicability map to Aegis rules in these categories:

| Aegis Category | Primary Control Families |
|---------------|------------------------|
| `access-control/` | AC-2, AC-3, AC-5, AC-6, AC-7 |
| `audit/` | AU-2, AU-3, AU-4, AU-5, AU-9, AU-12 |
| `filesystem/` | AC-3(4), SC-28 |
| `kernel/` | SC-39, SI-16 |
| `logging/` | AU-6, AU-8, SI-4 |
| `network/` | AC-4, SC-5, SC-7 |
| `services/` | CM-7 |
| `system/` | AC-8, CM-6, IA-5, IA-7, SC-8, SC-13 |
