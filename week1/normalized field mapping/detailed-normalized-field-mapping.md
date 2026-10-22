# Normalized Field Mapping (Wazuh)

> **Project:** SIEM Detection Engineering, Alert Triage & SOC Operations
> **Platform:** Wazuh 4.x (manager, indexer, dashboard)
> **Document type:** Data normalization reference
> **Canonical schema:** ECS-style names (for portability and Sigma compatibility), mapped to native Wazuh fields
> **Status:** Template. Field names depend on decoder and agent version. Validate every mapping with `wazuh-logtest` and real alerts before relying on it.

---

## 1. Purpose

Wazuh decodes each log source with its own decoder, so the same concept lands in different fields depending on where the event came from. A source IP might be `data.srcip` (Linux, firewall), `data.win.eventdata.ipAddress` (Windows logon), `data.win.eventdata.sourceIp` (Sysmon), `data.src_ip` (Suricata), or `data.aws.sourceIPAddress` (CloudTrail).

This document defines one **canonical field name** per concept and records **where each concept lives in Wazuh for every log source**, so that:

- Detection rules and dashboards are built from a single reference instead of per-analyst knowledge.
- Alert triage uses consistent terminology.
- Cross-source correlation (e.g., the same IP in Windows, SSH, firewall, and cloud logs) is straightforward.
- Detection content can be exported to or imported from other platforms (Sigma, ECS-based SIEMs).

## 2. How Normalization Works in Wazuh

### 2.1 Event flow

| Stage | Component | Output | Role in normalization |
|-------|-----------|--------|-----------------------|
| 1 | Agent / syslog / API module | Raw event | Collects the log; `location` records the source |
| 2 | Manager: pre-decoding | `predecoder.*` | Extracts syslog header (timestamp, hostname, program name) |
| 3 | Manager: decoding | `data.*`, `decoder.*` | Extracts fields. Windows Event Channel events arrive as `data.win.system.*` and `data.win.eventdata.*` |
| 4 | Manager: rule matching | `rule.*` | Adds rule ID, level, description, groups, MITRE and compliance tags |
| 5 | Filebeat and indexer ingest pipeline | `wazuh-alerts-4.x-*` | Adds GeoIP enrichment (`GeoLocation.*`) and indexes the alert |
| 6 | Wazuh dashboard | Visualizations | Queries the indexed fields |

Wazuh does **not** rename fields across sources by default. Normalization is therefore a deliberate design choice, implemented using one or more of the options below.

### 2.2 Implementation options

| Option | Where | Effort | Strengths | Limitations |
|--------|-------|--------|-----------|-------------|
| **A. Reference mapping (query-time)** | Rules and dashboards use the per-source fields in section 5 and 6 | Low | No pipeline changes; safe | Rules may need one condition per source |
| **B. Decoder-level static fields** | Custom decoders using Wazuh static fields (`srcip`, `dstip`, `srcport`, `dstport`, `srcuser`, `dstuser`, `protocol`, `action`, `id`, `url`, `status`) | Medium | Enables native correlation (`<same_srcip />`, `<same_dstuser />`) | Limited field set; does not apply to Windows Event Channel JSON fields |
| **C. Ingest-time canonical fields** | OpenSearch ingest pipeline on `wazuh-alerts-*` adds ECS-style fields | Medium to high | One query works across all sources; Sigma-friendly | Pipeline and template maintenance; re-test after Wazuh upgrades |

**Recommendation:** start with A and B. Add C when cross-source dashboards or Sigma conversion become a requirement. An example pipeline is in section 9.

## 3. Conventions

| Rule | Standard |
|------|----------|
| Canonical names | Lowercase, dot-separated, ECS-style (`source.ip`) |
| Native Wazuh fields | Keep exactly as generated. Never edit the default ruleset under `ruleset/` |
| Custom content | Decoders in `/var/ossec/etc/decoders/`, rules in `/var/ossec/etc/rules/`, using custom rule IDs in the 100000 to 120000 range |
| Windows field names | Wazuh lowercases the first letter (`targetUserName`, `ipAddress`). Queries are case-sensitive |
| Data types | Decoded values arrive as strings. Cast ports and PIDs to integers and IPs to `ip` type in the index template |
| Timestamps | UTC. `timestamp` is when the alert was generated; `data.win.system.systemTime` is the original Windows event time |
| Host identity | `agent.name` is the canonical host. Enroll agents using the lowercase short hostname |
| Usernames and hostnames | Lowercase, domain separated from name |
| Placeholders | Treat `-`, `::1`, `127.0.0.1`, `N/A`, and empty strings as missing, not as values |
| Original event | Preserved in `full_log`. Enable archives so non-alerting events are also kept (section 11) |
| Outcome | `success`, `failure`, `unknown` only |

## 4. Wazuh Alert Envelope Fields

These fields exist on every alert regardless of source.

| Wazuh Field | Canonical Field | Description |
|-------------|-----------------|-------------|
| `timestamp` / `@timestamp` | `@timestamp` | Alert generation time |
| `id` | `event.id` | Unique alert ID |
| `agent.id` | `host.id` | Wazuh agent ID |
| `agent.name` | `host.name` | Agent (host) name |
| `agent.ip` | `host.ip` | Agent IP address |
| `manager.name` | `observer.name` | Wazuh manager that processed the event |
| `decoder.name` | `event.dataset` | Decoder that parsed the event (e.g., `sshd`, `windows_eventchannel`) |
| `decoder.parent` | `event.module` | Parent decoder |
| `location` | `log.file.path` | Where the log was collected from |
| `input.type` | `input.type` | `log`, `command`, etc. |
| `full_log` | `event.original` | Raw log |
| `rule.id` | `rule.id` | Wazuh rule ID |
| `rule.description` | `rule.name` | Rule description |
| `rule.level` | `event.severity` | Rule level, 0 to 15 (see section 7.5) |
| `rule.groups` | `event.category` (derived) | Rule groups (see section 7.4) |
| `rule.mitre.id` | `threat.technique.id` | MITRE ATT&CK technique IDs |
| `rule.mitre.tactic` | `threat.tactic.name` | MITRE ATT&CK tactics |
| `rule.mitre.technique` | `threat.technique.name` | MITRE ATT&CK technique names |
| `rule.firedtimes` | `rule.fired_times` | Times the rule fired |
| `rule.pci_dss`, `rule.gdpr`, `rule.hipaa`, `rule.nist_800_53`, `rule.tsc` | `rule.compliance.*` | Compliance tags (supports the audit and retention requirements) |
| `GeoLocation.country_name` | `source.geo.country_name` | GeoIP enrichment of the source IP |
| `GeoLocation.city_name` | `source.geo.city_name` | GeoIP enrichment |
| `GeoLocation.location` | `source.geo.location` | Latitude and longitude |
| `predecoder.hostname` | `host.hostname` | Hostname from the syslog header |
| `predecoder.program_name` | `process.name` | Program from the syslog header |

## 5. Cross-Source Quick Reference

Use this matrix when writing a rule that must cover several sources. Empty cells (`-`) mean the source does not provide the field.

| Canonical Field | Windows Security | Sysmon | Linux (sshd / sudo) | Suricata / Firewall | AWS CloudTrail |
|-----------------|------------------|--------|---------------------|---------------------|----------------|
| `host.name` | `agent.name` | `agent.name` | `agent.name` | `agent.name` | n/a |
| `user.name` | `data.win.eventdata.targetUserName` (logons) or `subjectUserName` (actions) | `data.win.eventdata.user` | `data.dstuser` (sshd), `data.srcuser` (sudo) | - | `data.aws.userIdentity.userName` |
| `user.target.name` | `data.win.eventdata.targetUserName` (account management) | - | `data.dstuser` (sudo target) | - | - |
| `user.domain` | `data.win.eventdata.targetDomainName` | `data.win.eventdata.user` (prefix) | - | - | - |
| `source.ip` | `data.win.eventdata.ipAddress` | `data.win.eventdata.sourceIp` | `data.srcip` | `data.src_ip` (Suricata), `data.srcip` (firewall) | `data.aws.sourceIPAddress` |
| `source.port` | `data.win.eventdata.ipPort` | `data.win.eventdata.sourcePort` | `data.srcport` | `data.src_port`, `data.srcport` | - |
| `destination.ip` | - | `data.win.eventdata.destinationIp` | - | `data.dest_ip`, `data.dstip` | - |
| `destination.port` | - | `data.win.eventdata.destinationPort` | - | `data.dest_port`, `data.dstport` | - |
| `network.transport` | - | `data.win.eventdata.protocol` | - | `data.proto`, `data.protocol` | - |
| `process.executable` | `data.win.eventdata.newProcessName` (4688) | `data.win.eventdata.image` | - | - | - |
| `process.command_line` | `data.win.eventdata.commandLine` | `data.win.eventdata.commandLine` | `data.command` (sudo), `data.audit.command` (auditd) | - | - |
| `process.parent.executable` | `data.win.eventdata.parentProcessName` | `data.win.eventdata.parentImage` | - | - | - |
| `file.path` | - | `data.win.eventdata.targetFilename` | `syscheck.path` (FIM) | - | - |
| `dns.question.name` | - | `data.win.eventdata.queryName` | - | `data.dns.rrname` | - |
| `event.code` | `data.win.system.eventID` | `data.win.system.eventID` | `rule.id` (no vendor code) | `data.alert.signature_id` | - |
| `event.action` | derived (section 7.3) | derived | derived | `data.event_type` | `data.aws.eventName` |
| `event.outcome` | `data.win.system.severityValue` | n/a | `rule.groups` | `data.action` | `data.aws.errorCode` presence |
| `cloud.region` | - | - | - | - | `data.aws.awsRegion` |

## 6. Source-Specific Mappings

### 6.1 Windows Security (Event Channel)

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.win.system.systemTime` | `@timestamp` (event time) | Original event time in UTC |
| `data.win.system.computer` | `host.hostname` | FQDN as reported by Windows. Use `agent.name` for `host.name` |
| `data.win.system.eventID` | `event.code` | String value |
| `data.win.system.channel` | `event.dataset` | `Security`, `System`, `Application` |
| `data.win.system.providerName` | `event.provider` | |
| `data.win.system.severityValue` | `event.outcome` | `AUDIT_SUCCESS` becomes `success`, `AUDIT_FAILURE` becomes `failure` |
| `data.win.eventdata.targetUserName` | `user.name` (4624, 4625) or `user.target.name` (4720, 4726, 4728, 4732) | See note below |
| `data.win.eventdata.targetDomainName` | `user.domain` | |
| `data.win.eventdata.targetUserSid` | `user.id` | |
| `data.win.eventdata.subjectUserName` | `user.name` (4688, 4720, 4728, 4732) | Actor performing the action |
| `data.win.eventdata.ipAddress` | `source.ip` | Drop `-` and `::1` |
| `data.win.eventdata.ipPort` | `source.port` | Cast to integer |
| `data.win.eventdata.workstationName` | `source.domain` | |
| `data.win.eventdata.logonType` | `winlog.logon.type` | Map using section 7.2 |
| `data.win.eventdata.status`, `subStatus` | `winlog.event_data.sub_status` | Failure reason, e.g. `0xc000006a` wrong password, `0xc0000064` unknown user |
| `data.win.eventdata.newProcessName` | `process.executable` | 4688. Derive `process.name` from the path |
| `data.win.eventdata.commandLine` | `process.command_line` | Requires command-line process auditing enabled |
| `data.win.eventdata.newProcessId` | `process.pid` | Hex, convert to decimal |
| `data.win.eventdata.processId` | `process.parent.pid` | In 4688 this is the creator process, hex |
| `data.win.eventdata.parentProcessName` | `process.parent.executable` | Only on newer Windows builds |

> **Subject vs. target:** In account-management events, `subjectUserName` is the actor and `targetUserName` is the affected account. In logon events (4624, 4625), `targetUserName` is the account logging on.

### 6.2 Sysmon (Microsoft-Windows-Sysmon/Operational)

| Sysmon Event | Wazuh Field | Canonical Field |
|--------------|-------------|-----------------|
| All | `data.win.eventdata.utcTime` | `@timestamp` (event time) |
| All | `data.win.eventdata.user` | `user.name` (split into `user.domain`) |
| 1 | `data.win.eventdata.image` | `process.executable` |
| 1 | `data.win.eventdata.commandLine` | `process.command_line` |
| 1 | `data.win.eventdata.processId` | `process.pid` |
| 1 | `data.win.eventdata.parentImage` | `process.parent.executable` |
| 1 | `data.win.eventdata.parentCommandLine` | `process.parent.command_line` |
| 1 | `data.win.eventdata.parentProcessId` | `process.parent.pid` |
| 1 | `data.win.eventdata.hashes` | `process.hash.sha256`, `process.hash.md5` (parse the combined string) |
| 1 | `data.win.eventdata.originalFileName` | `process.pe.original_file_name` |
| 1 | `data.win.eventdata.currentDirectory` | `process.working_directory` |
| 3 | `data.win.eventdata.sourceIp`, `sourcePort` | `source.ip`, `source.port` |
| 3 | `data.win.eventdata.destinationIp`, `destinationPort` | `destination.ip`, `destination.port` |
| 3 | `data.win.eventdata.destinationHostname` | `destination.domain` |
| 3 | `data.win.eventdata.protocol` | `network.transport` |
| 3 | `data.win.eventdata.initiated` | `network.direction` (`true` becomes `outbound`) |
| 11 | `data.win.eventdata.targetFilename` | `file.path` |
| 12, 13, 14 | `data.win.eventdata.targetObject` | `registry.path` |
| 13 | `data.win.eventdata.details` | `registry.data.strings` |
| 22 | `data.win.eventdata.queryName` | `dns.question.name` |
| 22 | `data.win.eventdata.queryResults` | `dns.resolved_ip` |

### 6.3 Linux Authentication (sshd, sudo, PAM)

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `agent.name` | `host.name` | |
| `predecoder.program_name` | `process.name` | `sshd`, `sudo`, `su` |
| `data.srcip` | `source.ip` | sshd |
| `data.srcport` | `source.port` | sshd |
| `data.dstuser` | `user.name` | sshd login user. For sudo, the target (run-as) user |
| `data.srcuser` | `user.name` | sudo: the user who ran the command |
| `data.command` | `process.command_line` | sudo |
| `data.pwd` | `process.working_directory` | sudo |
| `rule.groups` contains `authentication_success` | `event.outcome` = `success` | |
| `rule.groups` contains `authentication_failed` | `event.outcome` = `failure` | |

> Which user field a decoder populates can differ between decoder versions. Confirm with `wazuh-logtest` on a real log line.

### 6.4 Linux auditd

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.audit.exe` | `process.executable` | |
| `data.audit.command` | `process.name` | Short command name |
| `data.audit.pid` | `process.pid` | |
| `data.audit.ppid` | `process.parent.pid` | |
| `data.audit.auid` | `user.id` | Original login UID |
| `data.audit.euid` | `user.effective.id` | |
| `data.audit.cwd` | `process.working_directory` | |
| `data.audit.file.name` | `file.path` | |
| `data.audit.syscall` | `event.action` | |
| `data.audit.success` | `event.outcome` | `yes` becomes `success`, `no` becomes `failure` |
| `data.audit.key` | `rule.ruleset` / tag | Audit rule key, useful for filtering |

### 6.5 File Integrity Monitoring (Syscheck)

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `syscheck.path` | `file.path` or `registry.path` | Registry keys appear here on Windows |
| `syscheck.event` | `event.type` | `added` becomes `creation`, `modified` becomes `change`, `deleted` becomes `deletion` |
| `syscheck.md5_after`, `sha1_after`, `sha256_after` | `file.hash.md5`, `.sha1`, `.sha256` | |
| `syscheck.uname_after` | `file.owner` | |
| `syscheck.perm_after` | `file.mode` | |
| `syscheck.size_after` | `file.size` | |
| `syscheck.value_name` | `registry.value` | Windows registry |

### 6.6 Suricata (IDS)

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.timestamp` | `@timestamp` (event time) | |
| `data.src_ip`, `data.src_port` | `source.ip`, `source.port` | |
| `data.dest_ip`, `data.dest_port` | `destination.ip`, `destination.port` | |
| `data.proto` | `network.transport` | Lowercase |
| `data.app_proto` | `network.protocol` | |
| `data.event_type` | `event.action` | `alert`, `dns`, `http`, `flow` |
| `data.alert.signature` | `rule.name` (source rule) | Keep separate from the Wazuh `rule.*` fields |
| `data.alert.signature_id` | `event.code` | |
| `data.alert.category` | `event.category` (derived) | |
| `data.alert.severity` | `event.severity` | Suricata scale: 1 is highest |
| `data.http.hostname`, `data.http.url` | `url.domain`, `url.path` | |
| `data.dns.rrname`, `rrtype`, `rcode` | `dns.question.name`, `dns.question.type`, `dns.response_code` | |

### 6.7 Firewall Logs

Field names depend on the decoder (iptables, pf, Cisco ASA, FortiGate, Palo Alto, etc.). The decoders generally populate the Wazuh static fields below.

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.srcip` | `source.ip` | |
| `data.srcport` | `source.port` | |
| `data.dstip` | `destination.ip` | |
| `data.dstport` | `destination.port` | |
| `data.protocol` | `network.transport` | Lowercase, convert numbers (6 = `tcp`, 17 = `udp`, 1 = `icmp`) |
| `data.action` | `event.type` and `event.outcome` | `allow` or `accept` becomes `allowed` and `success`. `deny`, `drop`, `reject` becomes `denied` and `failure` |

### 6.8 Web Server Access Logs (Apache, Nginx, IIS)

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.srcip` | `source.ip` | |
| `data.protocol` | `http.request.method` | The web access-log decoder stores the HTTP method here, not the network protocol |
| `data.url` | `url.original` | |
| `data.id` | `http.response.status_code` | The decoder stores the status code in the generic `id` field |

### 6.9 AWS CloudTrail

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.aws.eventTime` | `@timestamp` (event time) | |
| `data.aws.eventName` | `event.action` | `ConsoleLogin`, `StopLogging`, etc. |
| `data.aws.eventSource` | `event.provider` | `iam.amazonaws.com`, etc. |
| `data.aws.awsRegion` | `cloud.region` | |
| `data.aws.recipientAccountId` | `cloud.account.id` | |
| `data.aws.sourceIPAddress` | `source.ip` | May hold an AWS service name instead of an IP; route to `source.domain` in that case |
| `data.aws.userAgent` | `user_agent.original` | |
| `data.aws.userIdentity.userName` | `user.name` | |
| `data.aws.userIdentity.arn` | `user.id` | |
| `data.aws.userIdentity.type` | `aws.cloudtrail.user_identity.type` | `IAMUser`, `AssumedRole`, `Root` |
| `data.aws.errorCode` present | `event.outcome` = `failure` | Absent means `success` |
| `data.aws.errorMessage` | `error.message` | |
| static | `cloud.provider` = `aws` | |

### 6.10 Office 365 and Entra ID (Management Activity API)

Entra ID sign-ins can reach Wazuh through the Office 365 module (`AzureActiveDirectory` workload) or through Microsoft Graph or Azure integrations. The table below covers the Office 365 module. If you ingest through another path, field names will differ and need their own mapping.

| Wazuh Field | Canonical Field | Notes |
|-------------|-----------------|-------|
| `data.office365.CreationTime` | `@timestamp` (event time) | |
| `data.office365.Operation` | `event.action` | `UserLoggedIn`, `UserLoginFailed`, `New-InboxRule`, etc. |
| `data.office365.Workload` | `event.provider` | `AzureActiveDirectory`, `Exchange`, `SharePoint` |
| `data.office365.UserId` | `user.email` and `user.name` | Name is the part before `@` |
| `data.office365.ClientIP` | `source.ip` | |
| `data.office365.ResultStatus` | `event.outcome` | `Success` becomes `success`; others `failure` |
| `data.office365.ObjectId` | `file.path` / `url.original` | Depends on workload |
| `data.office365.UserAgent` | `user_agent.original` | When present |

### 6.11 Wazuh-Native Modules

| Module | Wazuh Fields | Canonical Use |
|--------|--------------|---------------|
| Vulnerability Detector | `data.vulnerability.cve`, `.severity`, `.package.name`, `.package.version`, `.status` | `vulnerability.id`, `vulnerability.severity`, `package.name`, `package.version`. Storage location varies by version (alerts vs. a dedicated vulnerability index in newer 4.x releases) |
| Security Configuration Assessment | `data.sca.policy`, `data.sca.check.id`, `.title`, `.result` | `event.category` = `configuration`; result `passed`, `failed`, `not applicable` |
| Active Response | `data.srcip`, `data.command` | Response actions taken, useful for SOC metrics |

## 7. Value Normalization Tables

### 7.1 Outcome

| Source Value | `event.outcome` |
|--------------|-----------------|
| `AUDIT_SUCCESS`, `Accepted`, `allow`, `accept`, `Success`, `authentication_success` group, CloudTrail without `errorCode` | `success` |
| `AUDIT_FAILURE`, `Failed`, `deny`, `drop`, `reject`, `Failed`, `authentication_failed` group, CloudTrail with `errorCode` | `failure` |
| Anything else | `unknown` |

### 7.2 Windows Logon Types

| `data.win.eventdata.logonType` | Meaning | `winlog.logon.type` |
|--------------------------------|---------|---------------------|
| 2 | Interactive | `Interactive` |
| 3 | Network | `Network` |
| 4 | Batch | `Batch` |
| 5 | Service | `Service` |
| 7 | Unlock | `Unlock` |
| 8 | NetworkCleartext | `NetworkCleartext` |
| 9 | NewCredentials | `NewCredentials` |
| 10 | RemoteInteractive (RDP) | `RemoteInteractive` |
| 11 | CachedInteractive | `CachedInteractive` |

### 7.3 Windows Event ID Categorization

Source field: `data.win.system.eventID`

| Event ID | Description | `event.category` | `event.type` | `event.action` |
|----------|-------------|------------------|--------------|----------------|
| 4624 | Successful logon | `authentication` | `start` | `logged-in` |
| 4625 | Failed logon | `authentication` | `start` | `logon-failed` |
| 4634 / 4647 | Logoff | `authentication` | `end` | `logged-out` |
| 4648 | Logon with explicit credentials | `authentication` | `start` | `logged-in-explicit` |
| 4672 | Special privileges assigned | `iam` | `admin` | `logged-in-special` |
| 4688 | Process created | `process` | `start` | `created-process` |
| 4720 | User account created | `iam` | `user`, `creation` | `added-user-account` |
| 4726 | User account deleted | `iam` | `user`, `deletion` | `deleted-user-account` |
| 4728 / 4732 / 4756 | Member added to group | `iam` | `group`, `change` | `added-member-to-group` |
| 4768 | Kerberos TGT requested | `authentication` | `start` | `kerberos-tgt-requested` |
| 4769 | Kerberos service ticket requested | `authentication` | `start` | `kerberos-service-ticket-requested` |
| 4776 | NTLM credential validation | `authentication` | `start` | `credential-validated` |
| 7045 | Service installed | `configuration` | `change` | `service-installed` |
| 1102 | Audit log cleared | `configuration` | `change` | `audit-log-cleared` |

### 7.4 Wazuh Rule Groups to Event Category (starting point)

Check the groups actually present on your alerts (`rule.groups`) and extend this table.

| `rule.groups` contains | `event.category` |
|------------------------|------------------|
| `authentication_success`, `authentication_failed`, `authentication_failures`, `sshd`, `pam` | `authentication` |
| `sudo`, `adduser`, `account_changed` | `iam` |
| `syscheck`, `syscheck_entry_added`, `syscheck_entry_modified`, `syscheck_entry_deleted` | `file` |
| `sysmon` | `process`, `network`, `file`, `registry`, or `dns` (decide by `eventID`) |
| `web`, `web_scan`, `attack` | `web` |
| `ids`, `suricata` | `intrusion_detection` |
| `firewall`, `iptables`, `pf` | `network` |
| `vulnerability-detector` | `vulnerability` |
| `sca` | `configuration` |
| `aws`, `amazon`, `office365`, `azure`, `gcp` | `cloud` (use `iam` or `web` as secondary where relevant) |

### 7.5 Rule Level to Severity (project convention)

Wazuh rule levels run from 0 to 15. The labels below are an internal convention for triage and should be aligned with your SOC runbooks.

| `rule.level` | Severity Label | Triage Expectation |
|--------------|----------------|--------------------|
| 0 to 3 | Informational | No review, retained for context |
| 4 to 7 | Low / Medium | Batch review, tune if noisy |
| 8 to 11 | High | Review within the SLA, investigate |
| 12 to 15 | Critical | Immediate response |

## 8. Example: Before and After

**Wazuh alert (simplified, Windows failed logon):**

```json
{
  "timestamp": "2026-10-23T08:14:10.201+0000",
  "agent": { "id": "014", "name": "WS-FIN-014", "ip": "10.10.20.14" },
  "rule": {
    "id": "60122",
    "level": 5,
    "description": "Logon Failure - Unknown user or bad password",
    "groups": ["windows", "windows_security", "authentication_failed"]
  },
  "decoder": { "name": "windows_eventchannel" },
  "data": {
    "win": {
      "system": {
        "eventID": "4625",
        "channel": "Security",
        "computer": "WS-FIN-014.corp.local",
        "severityValue": "AUDIT_FAILURE",
        "systemTime": "2026-10-23T08:14:09.512Z"
      },
      "eventdata": {
        "targetUserName": "JSmith",
        "targetDomainName": "CORP",
        "ipAddress": "203.0.113.45",
        "ipPort": "51822",
        "logonType": "3",
        "subStatus": "0xc000006a"
      }
    }
  },
  "location": "EventChannel"
}
```

**Canonical view:**

```json
{
  "@timestamp": "2026-10-23T08:14:09.512Z",
  "event": {
    "code": "4625",
    "category": ["authentication"],
    "type": ["start"],
    "action": "logon-failed",
    "outcome": "failure",
    "dataset": "windows_eventchannel"
  },
  "host": { "name": "ws-fin-014" },
  "user": { "name": "jsmith", "domain": "corp" },
  "source": { "ip": "203.0.113.45", "port": 51822 },
  "winlog": { "logon": { "type": "Network" } },
  "rule": { "id": "60122", "name": "Logon Failure - Unknown user or bad password" },
  "related": { "ip": ["203.0.113.45"], "user": ["jsmith"], "hosts": ["ws-fin-014"] }
}
```

## 9. Implementation Examples

Both examples are **illustrative**. Test in a lab, confirm the rule IDs and field names against your Wazuh version, and keep the final versions in this repo.

### 9.1 Option A: Correlation rule using native fields

Brute-force detection across failed Windows logons from the same source IP. Windows Event Channel fields are not Wazuh static fields, so `<same_field>` is used instead of `<same_srcip />`.

```xml
<group name="local,authentication,brute_force,">
  <rule id="100100" level="10" frequency="10" timeframe="300">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple Windows logon failures from the same source IP</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

Verify that 60122 is the failed-logon rule in your ruleset, and exclude placeholder IPs (`-`, `::1`) so unrelated local failures are not grouped together.

### 9.2 Option C: Ingest pipeline adding canonical fields

```json
PUT _ingest/pipeline/soc-normalize-wazuh-alerts
{
  "description": "Add canonical ECS-style fields to Wazuh alerts",
  "processors": [
    { "set": { "field": "host.name", "value": "{{agent.name}}",
               "if": "ctx.agent?.name != null", "ignore_empty_value": true } },

    { "set": { "field": "source.ip", "value": "{{data.srcip}}",
               "if": "ctx.data?.srcip != null", "override": false, "ignore_empty_value": true } },
    { "set": { "field": "source.ip", "value": "{{data.win.eventdata.ipAddress}}",
               "if": "ctx.data?.win?.eventdata?.ipAddress != null && ctx.data.win.eventdata.ipAddress != '-' && ctx.data.win.eventdata.ipAddress != '::1'",
               "override": false, "ignore_empty_value": true } },
    { "set": { "field": "source.ip", "value": "{{data.win.eventdata.sourceIp}}",
               "if": "ctx.data?.win?.eventdata?.sourceIp != null", "override": false, "ignore_empty_value": true } },
    { "set": { "field": "source.ip", "value": "{{data.aws.sourceIPAddress}}",
               "if": "ctx.data?.aws?.sourceIPAddress != null", "override": false, "ignore_empty_value": true } },

    { "set": { "field": "source.port", "value": "{{data.srcport}}",
               "if": "ctx.data?.srcport != null", "override": false, "ignore_empty_value": true } },
    { "set": { "field": "source.port", "value": "{{data.win.eventdata.ipPort}}",
               "if": "ctx.data?.win?.eventdata?.ipPort != null", "override": false, "ignore_empty_value": true } },
    { "convert": { "field": "source.port", "type": "integer", "ignore_missing": true, "ignore_failure": true } },

    { "set": { "field": "event.code", "value": "{{data.win.system.eventID}}",
               "if": "ctx.data?.win?.system?.eventID != null", "ignore_empty_value": true } },
    { "set": { "field": "event.original", "value": "{{full_log}}",
               "if": "ctx.full_log != null", "ignore_empty_value": true } },

    { "lowercase": { "field": "host.name", "ignore_missing": true } }
  ]
}
```

Notes:

- Define `source.ip` as type `ip` and `source.port` as `long` in the index template **before** the first document is indexed, otherwise dynamic mapping will choose a different type.
- Attach the pipeline as `index.final_pipeline` on `wazuh-alerts-*` so Wazuh's own GeoIP processing still runs first.
- Check results with `POST _ingest/pipeline/soc-normalize-wazuh-alerts/_simulate` using a real alert.
- Re-apply and re-test the template and pipeline after every Wazuh upgrade.

## 10. Validation Checklist

- [ ] Each onboarded log source has a mapping in sections 5 and 6
- [ ] Every mapping tested with `wazuh-logtest` using a real sample log line
- [ ] Agent names match the lowercase short hostname convention
- [ ] Windows audit policy enabled for 4624, 4625, 4688 (with command-line auditing), 4720, 4728, 4732, 1102
- [ ] Sysmon deployed with an approved configuration and forwarded through the Event Channel
- [ ] `source.ip` and `destination.ip` contain valid IPs only (no ports, no placeholders)
- [ ] Time synchronization (NTP) verified on agents, manager, and log sources
- [ ] Decoder and rule parse failures reviewed regularly (events with no matching decoder)
- [ ] Custom decoders and rules stored in `/var/ossec/etc/` (never in the default `ruleset/`) and committed to this repo
- [ ] Sample events for each source stored in `/samples` for regression testing
- [ ] Mappings re-validated after Wazuh, agent, Sysmon, or log-source upgrades

## 11. Relationship to Log Retention

| Wazuh Index | Contents | Notes |
|-------------|----------|-------|
| `wazuh-alerts-4.x-*` | Events that matched a rule at or above the alert level threshold | Used for triage and dashboards |
| `wazuh-archives-4.x-*` | All received events, matched or not | Requires `<logall_json>yes</logall_json>` in `ossec.conf` |

Two practical consequences for the retention table in `log-retention-policy.md`:

1. Sources without a matching rule will **not** be searchable unless archives are enabled. Enable archives for sources used in hunting and detection development.
2. Hot, warm, and cold periods should be implemented with Index State Management (ISM) policies on these indices, and the archive tier should be exported to object storage with integrity protection.

## 12. Review and Ownership

| Field | Value |
|-------|-------|
| **Owner** | Detection Engineering Lead |
| **Reviewers** | SOC Analysts, Wazuh Platform Administrator |
| **Review cycle** | Quarterly, on new log source onboarding, and after Wazuh upgrades |
| **Last reviewed** | YYYY-MM-DD |
| **Wazuh version validated** | 4.x.x |
| **Version** | 1.0 |

## 13. Change Log

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 1.0 | YYYY-MM-DD | Your Name | Initial release (Wazuh) |

## 14. References

- Wazuh decoders syntax: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html
- Wazuh rules syntax: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- Testing decoders and rules (`wazuh-logtest`): https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
- Wazuh log data collection: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
- Elastic Common Schema: https://www.elastic.co/guide/en/ecs/current/
- MITRE ATT&CK: https://attack.mitre.org/
