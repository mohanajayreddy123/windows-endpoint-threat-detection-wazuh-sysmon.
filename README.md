# Windows Endpoint Threat Detection and Investigation Using Wazuh SIEM and Sysmon

## Project Overview

This project demonstrates a small, isolated SOC lab in which a Windows 11 endpoint generates detailed telemetry with Sysmon and forwards selected Windows events to Wazuh for searching and investigation.

**Project type:** Beginner SOC Analyst L1 hands-on lab  
**Tools:** VMware Workstation Pro, Windows 11, Sysmon, Wazuh SIEM  
**Evidence date:** 16 October 2026

## Objectives

- Monitor a dedicated Windows endpoint virtual machine rather than the host computer.
- Collect process telemetry using Sysmon.
- Forward Sysmon Operational events through the Wazuh agent.
- Search endpoint events in Wazuh Threat Hunting.
- Review Wazuh detections and map behavior to MITRE ATT&CK.
- Practice evidence-based alert triage without treating an alert as proof of compromise.

## Lab Architecture

```text
Windows activity on SOCWIN11
          |
          v
Sysmon Operational event channel
          |
          v
Wazuh agent on SOCWIN11
          |
          v
Wazuh server (wazuh-server)
          |
          v
Threat Hunting: events, rule metadata, and investigation
```

## Lab Environment

| Component | Details |
|---|---|
| Host | Windows 11 Pro, 16 GB RAM |
| Virtualization | VMware Workstation Pro |
| Endpoint VM | Windows 11 Pro, hostname `SOCWIN11`, 8 GB RAM, 2 vCPU, 64 GB disk, NAT |
| Endpoint IP observed | `192.168.219.131` |
| Wazuh server | Amazon Linux 2023, Wazuh 4.14.8, hostname `wazuh-server` |
| Wazuh server IP observed | `192.168.219.130` |
| Wazuh agent | Version 4.14.8; agent ID `003` shown in event details |
| Sysmon | Installed and running; Event IDs 1 and 5 observed locally |

> IP addresses are the values visible during the captured session and may change after VM restarts.

## Implementation Summary

1. Created and used a dedicated Windows 11 endpoint VM named `SOCWIN11`.
2. Installed Sysmon and verified the Sysmon Operational event channel in Event Viewer.
3. Installed and connected the Wazuh agent to the existing Wazuh server.
4. Configured the agent to collect the Sysmon Operational event channel.
5. Reviewed events in Wazuh Threat Hunting and inspected event fields and rule metadata.

### Sysmon event-channel configuration

The Wazuh agent configuration contains this block inside the `<ossec_config>` root element:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Configuration file used in the lab:

`C:\Program Files (x86)\ossec-agent\ossec.conf`

## Verification and Findings

- Sysmon Event ID **1** (Process Create) and Event ID **5** (Process Terminated) were observed in Windows Event Viewer.
- Wazuh event details identify `SOCWIN11` and agent ID `003`.
- A Wazuh document showed `data.win.system.channel = Microsoft-Windows-Sysmon/Operational` and `data.win.system.eventID = 1`, confirming that at least one Sysmon process-creation event reached Wazuh.
- Threat Hunting screenshots show detections with rule IDs `92031`, `92066`, and `92058`.

## Example Alert Triage

### Rule 92066 — PowerShell associated with SecEdit.exe

- **Reported rule level:** 4
- **MITRE ATT&CK mapping:** `T1059.001` — PowerShell
- **Visible evidence:** Command-line fragment begins `C:\Windows\SysWOW64\secE...`; the complete command line is not readable in the screenshot.
- **Triage:** Validate full image path, command line, parent process, user, timestamp, file signature/hash, and nearby events.
- **Assessment:** Inconclusive. PowerShell and SecEdit.exe are legitimate Windows tools; the alert alone does not prove malicious activity.

### Rule 92058 — Application Compatibility Database Installer launched

- **Reported rule level:** 12
- **MITRE ATT&CK mapping:** `T1546.011` — Application Shimming
- **Triage:** Prioritize validation of the executable path, signature, parent process, command line, user, timestamp, and relevant compatibility/registry changes.
- **Assessment:** Requires prompt review; the screenshot alone does not prove compromise.

### Rule 92031 — Discovery activity executed

- **Reported rule level:** 3
- **MITRE ATT&CK mapping:** `T1087` — Account Discovery
- **Triage:** Identify the process and command line, user, timestamp, scope of account queries, and surrounding events.
- **Assessment:** Could reflect routine administration or reconnaissance; more context is needed.

## SOC Analyst L1 Workflow

1. Triage the alert: rule ID, level, endpoint, and timestamp.
2. Confirm the event belongs to `SOCWIN11`.
3. Review process image, command line, parent process, user, hashes, and nearby events.
4. Correlate related Sysmon and Windows events.
5. Decide whether activity is expected, suspicious, or confirmed malicious based on evidence.
6. Record the investigation and uncertainty.
7. Escalate high-severity or unexplained activity according to the applicable procedure.

## Limitations

- Screenshots show selected events from one lab session, not all possible Sysmon event types.
- The full command line and process lineage for some detections were not readable in the supplied screenshots.
- Rule severity and MITRE mappings are investigation aids, not a verdict.
- No alert is claimed as a confirmed incident based on the available evidence.

## Screenshots

The [`screenshots/`](screenshots/) folder contains evidence captured during the lab, including local Sysmon events and Wazuh Threat Hunting/event details. Refer to the accompanying project report for detailed figure captions and explanations.

## Conclusion

This lab demonstrates the basic endpoint telemetry path from Sysmon on Windows, through the Wazuh agent, into Wazuh Threat Hunting. The captured Sysmon Event ID 1 document verifies that Sysmon telemetry reached the SIEM. The alert examples provide practice in careful SOC triage, emphasizing evidence and context rather than assuming that every detection is malicious.

## Learning Outcomes

- Basic Sysmon and Windows Event Viewer use
- Wazuh agent and event-channel collection
- Threat Hunting event review
- Initial alert triage
- MITRE ATT&CK mapping
- Evidence-based SOC documentation
