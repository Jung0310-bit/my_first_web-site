---
title: "Splunk for Blue Team: SPL Queries and Investigation Patterns"
datePublished: 2026-05-04T09:00:00.000Z
cuid: cmoqyyjnh000021gfhxd531pg
slug: splunk-for-blue-team-spl-queries-and-investigation-patterns
tags: soc, cybersecurity, splunk, blue-team, siem

---

# Splunk for Blue Team: SPL Queries and Investigation Patterns

Splunk is the most common SIEM you'll encounter in a SOC. If you're doing blue team work, you need to be comfortable with SPL (Splunk Processing Language). This post covers the architecture, the essential SPL commands, and real investigation patterns for things like brute-force detection, suspicious process analysis, and C2 hunting.

---

## Splunk Architecture

Three core components:

| Component | Role |
|-----------|------|
| **Splunk Forwarder** | Lightweight agent on endpoints — collects and forwards data |
| **Splunk Indexer** | Processes incoming data, normalizes into field-value pairs, stores as searchable events |
| **Splunk Search Head** | User interface (Search & Reporting App) for queries, visualizations, alerts |

Data flow:
```
Endpoint → Forwarder → Indexer → Search Head
```

In large deployments, these are distributed across multiple servers. In small deployments, they can all run on one box.

---

## SPL Basics

SPL uses a pipe (`|`) to chain commands together, similar to Unix shell.

### Basic Search

```spl
index="botsv1" earliest=0
index="botsv1" sourcetype="stream:http" http_method=POST
```

- `index=` — selects the dataset (e.g., `main`, `security`, `botsv1`)
- `sourcetype=` — filters by log type
- `earliest=0` — starts from the first event (avoids needing "All Time" picker)

**Tip:** Use **Event Sampling** (1:100) during query development. It lets you test queries on a subset without straining the indexers.

### Search Operators

| Operator | Example | Description |
|----------|---------|-------------|
| `=` / `!=` | `AccountName!=SYSTEM` | Equality / inequality |
| `AND` / `OR` / `NOT` | `src="10.10.10.50" OR dst="10.10.10.50"` | Boolean logic |
| `*` (wildcard) | `src="10.10.10.*"` | Pattern matching |

### Field/Value Pairs

Splunk extracts fields from raw log data. Common fields:

- `host` — originating system
- `source` — file or data source
- `sourcetype` — data format type
- `src_ip`, `dest_ip` — network source/destination
- `Image` — Sysmon process executable

---

## Essential SPL Commands

### Filtering

| Command | Purpose | Example |
|---------|---------|---------|
| `fields` | Add/remove fields | `\| fields + host + User + SourceIp` |
| `search` | Filter after pipe | `\| search Powershell` |
| `dedup` | Remove duplicates | `\| dedup EventID` |
| `rename` | Rename fields | `\| rename User as Employees` |
| `where` | Filter with expressions | `\| where count > 10` |

### Ordering

| Command | Purpose | Example |
|---------|---------|---------|
| `sort` | Order results | `\| sort _time asc` or `\| sort -Hostname` |
| `table` | Custom table | `\| table date, time, srcip, dstport, action` |
| `head` / `tail` | First/last N | `\| head 5` |
| `reverse` | Flip order | `\| reverse` |

### Transformational

| Command | Purpose | Example |
|---------|---------|---------|
| `stats` | Calculate statistics | `\| stats count by srcip` |
| `top` / `rare` | Most/least frequent | `\| top limit=7 Image` |
| `chart` | Table by field | `\| chart count by User` |
| `timechart` | Time-series | `\| timechart count by Image` |
| `highlight` | Highlight in raw view | `\| highlight User, host, EventID` |

---

## Investigation Pattern: Process Analysis

A classic pattern — find all processes executed by a specific image and group by host:

```spl
index="botsv1" earliest=0 Image="*\\cmd.exe" 
| stats values(CommandLine) by host
```

This uses Sysmon's `Image` field to find `cmd.exe` executions and lists every command line grouped by host. Works the same for `powershell.exe`, `wscript.exe`, `rundll32.exe`, etc.

### Variations

**Parent process investigation:**
```spl
index="botsv1" sourcetype=xmlwineventlog EventCode=1 
| stats count by ParentImage, Image 
| sort -count
```

**Command line hunting for suspicious patterns:**
```spl
index="botsv1" sourcetype=xmlwineventlog EventCode=1 
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*")
| table _time, host, User, Image, CommandLine
```

---

## Investigation Pattern: Brute-Force Detection

Detecting brute-force against a web login:

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php"
| stats count by src_ip
| where count > 50
| sort -count
```

- Filter for POST requests to the login endpoint
- Count attempts per source IP
- Flag IPs with high counts

Once you find the attacker IP, pivot:

```spl
index="botsv1" src_ip="<attacker_ip>"
| table _time, sourcetype, dest_ip, http_method, uri, form_data
```

This gives you the full picture of what the attacker did, not just the brute-force.

---

## Investigation Pattern: Vulnerability Scanner Detection

Fortigate UTM logs expose a lot of scanner activity:

```spl
index="botsv1" sourcetype=fortigate_utm url_domain="imreallynotbatman.com" vulnerability
| stats count by attack, attack_id, src_ip, srccountry
| sort -count
```

You get:
- Scanner name (e.g., Acunetix, Nikto)
- Source IP
- Country (via enrichment)
- Attack patterns

---

## Investigation Pattern: Suspicious Binaries

Sometimes you want to spot legitimate tools running from unexpected places.

```spl
index="botsv1" sourcetype=xmlwineventlog osk.exe
| table _time, host, User, Image, CommandLine
```

Check the `Image` field — `osk.exe` (On-Screen Keyboard) should live in `C:\Windows\System32\`. If it's running from `C:\Users\Public\` or `C:\Temp\`, that's suspicious.

**General pattern for binary location hunting:**
```spl
index="botsv1" sourcetype=xmlwineventlog EventCode=1 
| eval IsSystem32=if(match(Image, "C:\\\\Windows\\\\System32\\\\"), "yes", "no")
| search IsSystem32=no AND Image IN ("*\\svchost.exe", "*\\lsass.exe", "*\\winlogon.exe")
```

This flags Windows system binaries running outside System32 — a strong indicator of malware impersonation.

---

## Investigation Pattern: AWS CloudTrail

Splunk also works for cloud logs:

```spl
index=* sourceIPAddress=* "requestParameters.bucketName"="developers-configuration"
| table _time, eventName, sourceIPAddress, userAgent, userIdentity.userName
```

Filter by `userAgent` to distinguish CLI access from browser access — attackers typically use the AWS CLI or SDK, which leaves a different User-Agent than a human using the console.

---

## Investigation Pattern: Backdoor User Detection

Looking for unauthorized account creation:

```spl
index=* EventCode=4720 
| table _time, host, TargetUserName, SubjectUserName
```

- `4720` = user account created
- `SubjectUserName` = who created it
- `TargetUserName` = the new account

Correlate with `4722` (account enabled) and `4732` (user added to privileged group) to find full backdoor setup chains.

---

## Creating Alerts

Alerts run a saved search on a schedule or in real-time and trigger when results meet defined conditions.

### Alert Components

1. **Search Query** — the SPL that detects the activity
2. **Search Timing** — real-time or scheduled (every N minutes/hours)
3. **Trigger Condition** — threshold (e.g., `count > 5`, `per-result`)
4. **Alert Action** — email, webhook, add to triggered alerts list, log event

### Example: Failed Login Spike Alert

**Search:**
```spl
index=windows EventCode=4625 
| stats count by Account_Name, Computer 
| where count > 10
```

**Schedule:** Every 5 minutes, over the last 5 minutes  
**Trigger:** Per-result  
**Action:** Email SOC team + log to `triggered_alerts` index

---

## Dashboards

Dashboards give you a "single pane of glass" view of important activity. Common panels:

- Firewall activity by action (allowed/denied/dropped)
- Alert counts over time
- Traffic flow by source/destination
- Attack maps (geo-IP visualization)
- Event type breakdown (pie chart)

**Naming convention:**
```
<group>_<object>_<description>
```

Examples:
- `IT_Report_FailedLogins`
- `SOC_Dashboard_PhishingMetrics`
- `NET_Report_FirewallDeny`

Dashboards can be powered by inline searches or reference saved Reports. Reports are more reusable.

---

## SPL Tips

- **Use `earliest=0`** instead of "All Time" picker — faster query parsing
- **Filter first, then transform** — put `search` and `where` early, `stats` late
- **Use `tstats` for fast queries** on accelerated data models — much faster than `stats`
- **`| fields + X Y Z`** early in the query makes downstream commands faster
- **Avoid `*` wildcards at the start** of a value (`*evil.com`) — they're much slower than end wildcards (`evil.*`)
- **Use `lookup` tables** for enrichment instead of inline `case` statements

---

## Key Takeaways

- Splunk = **Forwarder → Indexer → Search Head**
- **SPL uses pipes** — chain commands like Unix shell
- **Filter first, transform last** — put `search`/`where` before `stats`
- `stats` is the workhorse — `stats count by <field>` is the most common pattern
- **`pstree`-like patterns** work in Splunk via `ParentImage`/`Image` correlation
- **Brute-force detection** is a `count by src_ip` + threshold
- **Binary location checks** catch malware impersonation of system files
- **Use `earliest=0`** to avoid time-picker overhead
- Alerts = saved search + schedule + trigger + action
- Dashboards consume saved reports — reuse, don't duplicate
