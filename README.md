# Home_SOC_LAB[README.md](https://github.com/user-attachments/files/29482488/README.md)
# Home SOC Lab — Windows Event Log Detection with Splunk Cloud

A hands-on blue team homelab built on an M4 MacBook Air using UTM virtualization. The goal is to simulate a basic Security Operations Center environment: ingest Windows Security Event logs into a cloud SIEM, write detection queries, and build alerts mapped to real attack techniques.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                  M4 MacBook Air (Host)               │
│                                                     │
│  ┌──────────────┐   ┌──────────┐   ┌─────────────┐ │
│  │ Windows 11   │   │  Kali    │   │   Ubuntu    │ │
│  │ ARM64 VM     │   │  Linux   │   │   Server    │ │
│  │ (Victim)     │   │ (Attacker│   │  (Future)   │ │
│  └──────┬───────┘   └──────────┘   └─────────────┘ │
│         │ PowerShell HEC Forwarder                  │
│         │ HTTPS Port 8088                           │
└─────────┼───────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│   Splunk Cloud (SIEM)   │
│   index: main           │
│   4 Active Alerts       │
└─────────────────────────┘
```

---

## Tech Stack

| Component | Tool |
|---|---|
| Hypervisor | UTM (QEMU) on Apple Silicon |
| Victim Machine | Windows 11 ARM64 |
| Attack Platform | Kali Linux (in progress) |
| SIEM | Splunk Cloud |
| Log Forwarder | Custom PowerShell HEC Script |
| Log Source | Windows Security Event Log |

---

## Log Ingestion

Splunk Cloud's free tier restricts external connections on port 9997 (the standard S2S forwarder protocol). To work around this, I wrote a PowerShell script that reads the Windows Security Event Log and ships events to Splunk via the HTTP Event Collector (HEC) API over HTTPS on port 8088.

The script polls every 60 seconds, filters for a defined list of Event IDs, packages each event as a JSON payload, and sends it to Splunk with an authenticated POST request.

**Script:** `Send-WindowsLogsToSplunk.ps1`

**Monitored Event IDs:**

| Event ID | Description | MITRE ATT&CK |
|---|---|---|
| 4624 | Successful Logon | T1078 - Valid Accounts |
| 4625 | Failed Logon | T1110 - Brute Force |
| 4648 | Logon with Explicit Credentials | T1550 - Use Alternate Auth Material |
| 4672 | Special Privileges Assigned | T1068 - Privilege Escalation |
| 4688 | New Process Created | T1059 - Command and Scripting Interpreter |
| 4698 | Scheduled Task Created | T1053 - Scheduled Task/Job |
| 4720 | User Account Created | T1136 - Create Account |
| 4726 | User Account Deleted | T1531 - Account Access Removal |

---

## Detections

### Failed Login Attempt — EventID 4625
**MITRE:** T1110 - Brute Force

```spl
index=main sourcetype="WinEventLog" "4625"
| table _time, MachineName, UserName, Message
```

Triggers in real-time on any failed login event.

---

### New User Account Created — EventID 4720
**MITRE:** T1136 - Create Account

```spl
index=main sourcetype="WinEventLog" "4720"
| table _time, MachineName, UserName, Message
```

Triggers when a new local user account is created. Common persistence technique used by attackers after initial access.

---

### Special Privileges Assigned — EventID 4672
**MITRE:** T1068 - Exploitation for Privilege Escalation

```spl
index=main sourcetype="WinEventLog" "4672"
| table _time, MachineName, UserName, Message
```

Triggers when admin-level privileges are assigned to a logon session.

---

### New Process Created — EventID 4688
**MITRE:** T1059 - Command and Scripting Interpreter

```spl
index=main sourcetype="WinEventLog" "4688"
| table _time, MachineName, UserName, Message
```

Triggers on new process creation. Useful for detecting malware execution and living-off-the-land binaries (LOLBins).

---

## Planned Work

- Kali Linux attack simulation against Windows VM (Nmap, Metasploit)
- Brute force threshold alert (5+ EventID 4625 failures within 5 minutes)
- pfSense firewall VM for network segmentation and firewall log ingestion
- Ubuntu Server for Linux auth log monitoring (/var/log/auth.log)
- Splunk dashboard with attack timeline
- MITRE ATT&CK heatmap of detected techniques

---

## Skills Covered

- Windows Security Event Log analysis
- Splunk Cloud deployment and SPL query writing
- Detection engineering and alert creation
- MITRE ATT&CK framework mapping
- Custom log forwarder development (PowerShell, REST API, JSON)
- VM setup and network configuration on Apple Silicon (UTM/QEMU)
- UEFI/EFI boot troubleshooting
- Network and SSL/TLS troubleshooting

---

## Author

Pablo — Cybersecurity B.S., University of North Georgia (Expected May 2028)
