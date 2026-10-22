# Log Retention Policy

> **Project:** SIEM Detection Engineering, Alert Triage & SOC Operations
> **Document type:** Log retention reference

---

## 1. Purpose

This document defines how long each log source is retained in the SIEM and in long-term storage. Retention directly affects:

- **Detection engineering:** correlation rules and baselines need enough history to work (e.g., 30-day behavioral baselines).
- **Alert triage:** analysts need recent, searchable data to investigate quickly.
- **Incident response and threat hunting:** intrusions are often discovered weeks or months after initial access.
- **Compliance and audit:** many frameworks set minimum retention periods.

## 2. Retention Tiers

| Tier | Storage | Searchable | Typical Use |
|------|---------|------------|-------------|
| **Hot** | SIEM index / fast SSD | Yes, real-time | Live detection, alert triage, dashboards |
| **Warm** | SIEM, lower-cost storage | Yes, slower | Threat hunting, recent incident investigation |
| **Cold / Archive** | Object storage (S3, Azure Blob, GCS), compressed | No, must be restored or rehydrated | Compliance, legal hold, forensics |

## 3. Log Retention Table

| # | Log Source | Category | Priority | Hot | Warm | Cold / Archive | Total | Primary Detection Use Cases | Compliance Driver |
|---|-----------|----------|----------|-----|------|----------------|-------|-----------------------------|-------------------|
| 1 | Windows Security Event Logs (4624, 4625, 4688, 4672, 4720, etc.) | Endpoint / OS | Critical | 90 days | 90 days | 1 year | **~14 months** | Brute force, privilege escalation, account creation, lateral movement | PCI DSS, SOC 2, ISO 27001 |
| 2 | Sysmon (Process, Network, Registry, File events) | Endpoint / OS | Critical | 60 days | 120 days | 1 year | **~15 months** | Process injection, LOLBins, persistence, C2 beaconing | MITRE ATT&CK coverage |
| 3 | Linux Auth / Syslog (`auth.log`, `secure`, `audit.log`) | Endpoint / OS | High | 90 days | 90 days | 1 year | **~14 months** | SSH brute force, sudo abuse, unauthorized access | PCI DSS, SOC 2 |
| 4 | EDR Telemetry and Alerts | Endpoint | Critical | 60 days | 120 days | 1 year | **~15 months** | Malware execution, ransomware behavior, host isolation events | Internal policy |
| 5 | Active Directory / Domain Controller Logs | Identity | Critical | 90 days | 90 days | 2 years | **~2 years** | Kerberoasting, DCSync, Golden Ticket, GPO changes | SOC 2, ISO 27001 |
| 6 | Identity Provider (Entra ID / Okta) Sign-in and Audit Logs | Identity | Critical | 90 days | 90 days | 1 year | **~14 months** | Impossible travel, MFA fatigue, risky sign-ins, role changes | SOC 2, ISO 27001 |
| 7 | VPN / Remote Access Logs | Network | High | 90 days | 90 days | 1 year | **~14 months** | Anomalous logins, geo-anomalies, credential stuffing | PCI DSS, SOC 2 |
| 8 | Firewall Logs (allow/deny) | Network | High | 30 days | 60 days | 1 year | **~15 months** | Port scans, blocked C2, outbound anomalies | PCI DSS |
| 9 | IDS/IPS Alerts (Snort, Suricata) | Network | High | 90 days | 90 days | 1 year | **~14 months** | Exploit attempts, known malicious signatures | PCI DSS |
| 10 | DNS Logs | Network | High | 30 days | 60 days | 1 year | **~15 months** | DGA domains, DNS tunneling, C2 lookups | Threat hunting |
| 11 | Proxy / Web Gateway Logs | Network | Medium | 30 days | 60 days | 1 year | **~15 months** | Malicious downloads, data exfiltration, phishing URLs | Internal policy |
| 12 | NetFlow / Zeek Connection Logs | Network | Medium | 14 days | 45 days | 6 months | **~8 months** | Beaconing, lateral movement, large data transfers | Threat hunting |
| 13 | Email Gateway / Mail Security Logs | Email | High | 60 days | 120 days | 1 year | **~15 months** | Phishing campaigns, malicious attachments, BEC | SOC 2 |
| 14 | Web Server Logs (Apache, Nginx, IIS) | Application | Medium | 30 days | 60 days | 1 year | **~15 months** | SQLi, XSS, web shell access, scanning | PCI DSS |
| 15 | WAF Logs | Application | High | 60 days | 120 days | 1 year | **~15 months** | OWASP Top 10 attacks, bot activity | PCI DSS |
| 16 | Database Audit Logs | Application | Critical | 90 days | 90 days | 2 years | **~2 years** | Privileged queries, mass data access, schema changes | PCI DSS, HIPAA, SOX |
| 17 | Cloud Control Plane Logs (AWS CloudTrail, Azure Activity, GCP Audit) | Cloud | Critical | 90 days | 90 days | 2 years | **~2 years** | IAM changes, resource tampering, API abuse, logging disabled | SOC 2, ISO 27001, CIS |
| 18 | Cloud Network Flow Logs (VPC Flow, NSG Flow) | Cloud | Medium | 14 days | 45 days | 6 months | **~8 months** | Exfiltration, unusual east-west traffic | Threat hunting |
| 19 | Kubernetes / Container Audit Logs | Cloud | High | 30 days | 60 days | 1 year | **~15 months** | Privileged pods, exec into containers, RBAC changes | CIS Benchmarks |
| 20 | SaaS Audit Logs (M365, Google Workspace, GitHub) | Cloud | High | 90 days | 90 days | 1 year | **~14 months** | Mailbox rule abuse, mass downloads, repo exposure | SOC 2 |
| 21 | PAM / Privileged Session Logs | Identity | Critical | 90 days | 90 days | 2 years | **~2 years** | Privileged misuse, session anomalies | SOC 2, ISO 27001 |
| 22 | Vulnerability Scanner Results | Security Tooling | Medium | 90 days | 275 days | 1 year | **~1 year** | Exposure correlation, patch SLA tracking | PCI DSS, ISO 27001 |
| 23 | SIEM Alerts, Cases and Triage Notes | SOC Operations | Critical | 1 year | n/a | 2 years | **~2 years** | Metrics (MTTD/MTTR), audit trail, tuning decisions | Internal policy, SOC 2 |
| 24 | SIEM Admin / Audit Logs (rule changes, user access) | SOC Operations | Critical | 1 year | n/a | 3 years | **~3 years** | Detect tampering with detection content, change accountability | SOC 2, ISO 27001 |
| 25 | Endpoint DLP Logs | Data Protection | Medium | 90 days | 90 days | 1 year | **~14 months** | Policy violations, USB or cloud upload of sensitive data | GDPR, internal policy |

## 4. Priority Definitions

| Priority | Meaning |
|----------|---------|
| **Critical** | Essential for detecting and reconstructing a compromise; loss would block investigations |
| **High** | Strong detection value; needed for most triage workflows |
| **Medium** | Useful for hunting and enrichment; high volume, so retained for a shorter period |

## 5. Compliance Reference

Retention minimums vary by jurisdiction, industry, and contract. Verify against your current obligations with legal and compliance teams.

| Framework | Relevant Requirement (summary) |
|-----------|-------------------------------|
| **PCI DSS** | Retain audit log history for at least 12 months, with at least the most recent 3 months immediately available for analysis |
| **HIPAA** | Security-related documentation retained for 6 years (log retention is typically set to support this) |
| **SOC 2** | No fixed duration; retention must be defined, consistently applied, and evidenced for the audit period (commonly 12 months) |
| **ISO/IEC 27001** | Logs must be produced, protected, and reviewed; duration is set by organizational risk assessment |
| **NIST SP 800-92** | Guidance on log management; retention driven by organizational policy and risk |
| **GDPR** | Logs containing personal data must be kept no longer than necessary (data minimization) |

## 6. Design Notes and Assumptions

1. **Hot tier is sized for detection and triage.** Most correlation searches and dashboards run against 30 to 90 days of data.
2. **High-volume sources get shorter hot retention** (NetFlow, DNS, firewall, cloud flow logs) to control licensing and storage cost. Summarized or filtered data can be kept longer.
3. **Identity and control plane logs are kept longest.** They are low volume and have the highest forensic value.
4. **Dwell time matters.** Long cold retention supports investigating intrusions discovered months after initial access.
5. **Archived logs must be integrity-protected:** write-once storage (e.g., S3 Object Lock), hashing, and restricted access.
6. **Legal hold overrides this table.** Affected logs must be preserved until the hold is released.
7. **Personal data:** apply masking, pseudonymization, or access controls where logs contain PII.
8. **Total** is hot + warm + cold, counted as one continuous timeline, rounded.

## 7. Operational Requirements

- [ ] All sources in the table are onboarded and verified as ingesting (no silent log gaps)
- [ ] Time synchronization (NTP) enforced on all log sources
- [ ] Log integrity controls enabled on the archive tier
- [ ] Role-based access control on SIEM and archive storage
- [ ] Restore (rehydration) from cold storage tested at least annually
- [ ] Retention settings reviewed at least annually, or after major changes to the environment, regulations, or detection strategy
- [ ] Log source health monitoring alerts configured (e.g., no events from a critical source in 1 hour)

## 8. Review and Ownership

| Field | Value |
|-------|-------|
| **Owner** | SOC Manager / Detection Engineering Lead |
| **Reviewers** | Security Architecture, Compliance, IT Operations |
| **Review cycle** | Annually |
| **Last reviewed** | YYYY-MM-DD |
| **Version** | 1.0 |

## 9. Change Log

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 1.0 | YYYY-MM-DD | Your Name | Initial release |
