---
title: "Threat Hunting Methodology"
datePublished: 2026-06-06T09:00:00.000Z
cuid: cmq24hhjo000024ez6xrrhps0
slug: threat-hunting-methodology
cover: https://raw.githubusercontent.com/Jung0310-bit/woogi-blog-assets/main/thumbnails/threat-hunting-methodology.png
tags: soc, cybersecurity, threat-hunting, blue-team

---

Most security tools are reactive. Alerts fire after a rule matches, and analysts triage. **Threat hunting** flips that: you assume something has already evaded the tools, and you go look for it. This post covers the methodology, the three-step process, and where to actually look.

---

## Why Hunt

Signature-based defenses miss zero-days, fileless malware, and living-off-the-land techniques by design. The 2024 Mandiant M-Trends report puts dwell time at around 10 days median, which is shorter than it used to be but still long enough for an attacker to do real damage.

Hunting complements automation by adding three things tools can't:

- **Human intuition** about what's unusual in *your* environment
- **Creativity** to test hypotheses tools weren't programmed for
- **Context** about business operations, employees, and asset criticality

Tools find the obvious. Hunters find the patient.

---

## The Three-Step Process

### 1. Trigger

Something starts a hunt. Three common kinds:

| Trigger Type | Example |
|---|---|
| **Anomaly** (reactive) | "We saw 50 GB of outbound data at 2 AM from an HR laptop" |
| **Known TTP** (proactive) | "If attackers use PowerShell for recon, look for Event ID 4104 with `Invoke-Expression` or encoded commands" |
| **Threat Intelligence** | "Midnight Blizzard is active. Hunt for password sprays against accounts without MFA" |

Without a trigger, you're not hunting; you're scrolling logs.

### 2. Investigation

Pull data, correlate, look for patterns:

- **Network logs** for unusual connections, traffic spikes, suspicious destinations
- **Endpoint logs** for unexpected processes, scheduled tasks, scripts at odd hours
- **Application logs** for unauthorized access, anomalous queries
- **Threat intel** to cross-reference IOCs and TTPs

A SIEM (Splunk, Elastic) is your primary surface. EDR fills in the host detail. The skill is knowing which view answers which question.

### 3. Resolution

Two outcomes:

- **Hypothesis disproved** — document the work, update detection rules so this question gets answered automatically next time
- **Confirmed compromise** — escalate to IR, contain, communicate

Either way, the hunt produces value: better detections or a contained incident. There's no "nothing happened" outcome if you've documented honestly.

---

## Methodology Types

### Hypothesis-Driven

Form a specific testable theory, then go find evidence.

> *"Suspicious PowerShell may indicate compromise. Hunt for Event ID 4104 with obfuscated commands or `EncodedCommand`."*

Concrete, falsifiable, runs against a specific data source. This is the most common hunt style for working analysts.

### Intelligence-Driven

Use a threat actor's known playbook to drive the hunt.

> *"APT29 is known for OAuth abuse and DLL search-order hijacking. Hunt for these in our environment."*

Requires good threat intel feeds and time to translate generic TTPs into queries against your specific telemetry.

### Anomaly-Driven

Start from a deviation, work backwards.

> *"Why did this laptop talk to a Russian IP at 3 AM?"*

Loose hypothesis, but high-yield when you have good baselines.

---

## Endpoint Hunting Targets

Endpoints are where most attacks land. Five techniques to hunt for:

| Technique | What to Look For | Key Event IDs |
|---|---|---|
| **PowerShell abuse** | Encoded commands, obfuscation, `Invoke-Expression` | 4104 (script block), 4688 (process) |
| **Persistence via scheduled tasks** | New or modified tasks, especially with system context | 4698, 106, 140 |
| **Credential dumping** | LSASS access, Mimikatz indicators, suspicious DLL loads | 4624/4625 (logon), 4672 (special), Sysmon ID 10 |
| **Account usage anomalies** | Unusual logon patterns, service accounts in interactive contexts | 4624 with Logon Type codes |
| **Lateral movement** | Remote service installs, named pipes, admin share access | 7045 (service install), 5145 (network share), Sysmon 1/17/18 |

Each row collapses into a 2-line query in your SIEM (see [Splunk for Blue Team](https://woogi.me/splunk-for-blue-team-spl-queries-and-investigation-patterns) or [Elastic SIEM and KQL](https://woogi.me/elastic-siem-and-kql-the-open-source-alternative-to-splunk)). The art is knowing when to add baseline exclusions vs. when the noise is the signal.

### Logon Type Codes Worth Memorizing

- `2` — Interactive (console / KVM)
- `3` — Network (SMB, mapped drive, etc.)
- `7` — Unlock
- `10` — RemoteInteractive (RDP)
- `11` — CachedInteractive (offline)

Service accounts logging in as Type 2 or 10 are usually wrong. That's a hunt right there.

---

## Network Hunting

Endpoints get attention; network often gets less. But fileless attacks still talk over the wire eventually.

| Vector | What to Look For |
|---|---|
| **DNS** | Long encoded labels, TXT/NULL record abuse, queries to fast-flux domains, beacon-like timing |
| **HTTP/S** | Unusual user-agents, beaconing patterns, large POSTs to unfamiliar destinations |
| **NetFlow** | Spike in volume, unusual port usage, long-running connections to non-business destinations |
| **SMB** | Lateral movement: PsExec service installation, admin share access by non-admin accounts |
| **ICMP** | Oversized payloads suggesting tunneling |

For PCAP-level analysis, [Wireshark](https://woogi.me/wireshark-traffic-analysis-for-ir) is the reference tool. For aggregated flow analysis at SIEM scale, KQL or SPL pivots over Zeek-style connection logs.

---

## A Hunt in Practice

Concrete walk-through, hypothesis-driven:

**Hypothesis**: "If credential dumping happened on a workstation, we'd see Mimikatz indicators in process telemetry."

**Investigation**:
1. Query Sysmon Event ID 10 (ProcessAccess) where target is `lsass.exe` and granted access includes `0x1010` or `0x1410` (typical Mimikatz access masks)
2. Filter out known security tools (EDR scanners, vulnerability tools) by signer or process path
3. Pivot on remaining processes: parent process tree, command-line arguments, file hashes
4. Cross-reference user account against expected admin activity
5. Check network flow from same host: any beaconing or unusual outbound?

**Resolution**:
- If clean: document the false positives encountered, refine the query for next time, possibly tune EDR
- If hit: contain the host, escalate to IR, broaden hunt to other hosts the user accessed

That's the loop. Hypothesis → query → triage → outcome → improve detection.

---

## A Hypothesis-Driven Hunt End-to-End

Concrete walk-through of one of the most common hunts: detecting credential dumping via LSASS access.

**Hypothesis**: An attacker on a workstation will attempt to read the memory of `lsass.exe` to extract credentials. Tools like Mimikatz or Cobalt Strike's `mimikatz` module trigger Sysmon Event ID 10 (ProcessAccess) with specific access masks.

### Splunk SPL

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| eval bad_mask=if(GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1fffff"), 1, 0)
| where bad_mask=1
| stats count values(SourceImage) as source_images by Computer, User
| sort -count
```

What this does:

- `EventCode=10` filters to ProcessAccess events from Sysmon
- `TargetImage="*lsass.exe"` keeps only access against the LSASS process
- `GrantedAccess` masks like `0x1010` and `0x1410` are commonly requested by Mimikatz; legitimate access typically uses different masks
- The aggregation surfaces uncommon source processes accessing LSASS per host/user

### Kibana KQL Equivalent

```
event.code: "10" and winlog.event_data.TargetImage: *lsass.exe
and winlog.event_data.GrantedAccess: ("0x1010" or "0x1410" or "0x1438" or "0x143a" or "0x1fffff")
```

Then aggregate with a Lens visualization or table of `host.name` × `winlog.event_data.SourceImage`.

### Triage What Comes Back

Expect noise. Common false positives:

- **EDR vendors** scanning LSASS for their own analysis (Microsoft Defender, CrowdStrike, SentinelOne)
- **Sysinternals tools** like Process Explorer or VMMap when an admin runs them
- **Legitimate vulnerability scanners** that probe credential storage

Filter these out by signer, image path, or user context. What's left is the high-signal subset.

### When You Find Something

If a hit survives triage:

1. Identify the source process and parent process. Build the process tree.
2. Pull network flow from the same host in the same window. Any unusual outbound?
3. Check user account. Was this account logging in interactively at the time?
4. Look for file system artifacts: temporary files dumped, dump files written to disk
5. Escalate per IR runbook. Don't try to "clean it" before forensics is captured.

That's the hunt. Hypothesis to query to triage to resolution. Repeat with other techniques.

---

## Documentation: What to Save

Hunts produce value only if their findings persist beyond the analyst who ran them. A minimal hunt report:

```markdown
# Hunt: <name>
## Hypothesis
<one paragraph>

## Data Sources
- <log type 1>: <date range>
- <log type 2>: <date range>

## Query
<paste query>

## Initial Results
<count, top hits>

## Triage
- False positives identified: <list with reasoning>
- True positives: <list with details>

## Resolution
- New detection rule: <yes/no, link>
- Incident escalated: <yes/no, ticket>
- Known limitations: <gaps>

## Next Hunt
<related hypothesis to try next>
```

The "Next Hunt" field is the often-skipped one that compounds value over time. Each hunt suggests the next.

---

## Tools

| Tool | Use |
|---|---|
| **Splunk** | SPL hunting across log sources |
| **Elastic SIEM / Kibana** | KQL hunting; lab-friendly free tier |
| **Sysmon** | Endpoint telemetry that EDR vendors charge for |
| **Wireshark / tshark** | Per-packet network analysis |
| **DeepBlueCLI** | Fast Windows event log triage from a workstation |

---

## Closing

Hunting is what stops automated detection from being the ceiling. The trigger gets you started, the process keeps you honest, and the documentation makes the next hunt faster.

Next post: where most of these hunts actually run. **Active Directory** is the central nervous system of a Windows enterprise, and the primary target for adversaries who want to pivot laterally or escalate privileges.
