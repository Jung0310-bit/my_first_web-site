---
title: "Elastic SIEM and KQL: The Open-Source Alternative to Splunk"
datePublished: 2026-05-07T09:00:00.000Z
cuid: cmov99pr5000021ci3i6weka8
slug: elastic-siem-and-kql-the-open-source-alternative-to-splunk
tags: kibana, cybersecurity, blue-team, siem, elastic-siem

---

# Elastic SIEM and KQL: The Open-Source Alternative to Splunk

Splunk is powerful but expensive. Elastic Stack (formerly ELK) is the open-source alternative most teams eventually encounter. This post covers the Elastic architecture, ECS (Elastic Common Schema), KQL queries, and the Kibana interface — enough to get productive as a blue teamer.

---

## Elastic Stack Architecture

| Component | Role |
|-----------|------|
| **Elasticsearch** | Distributed search and analytics engine — stores and indexes log data |
| **Kibana** | Web-based UI for searching, visualizing, and managing data |
| **Beats** | Lightweight data shippers on endpoints (Filebeat, Winlogbeat, Packetbeat) |
| **Logstash** | Server-side data processing pipeline for parsing, transforming, enriching logs |
| **Fleet** | Centralized management for Elastic Agents |

### Data Flow

```
Endpoint (Beats/Agent) → Logstash (optional processing) → Elasticsearch (storage/indexing) → Kibana (search/visualization)
```

Logstash is optional. For simpler deployments, Beats can write directly to Elasticsearch.

### Beats Family

Different Beats for different data types:

- **Filebeat** — log files
- **Winlogbeat** — Windows Event Logs
- **Packetbeat** — network traffic
- **Metricbeat** — system and service metrics
- **Auditbeat** — Linux audit framework
- **Heartbeat** — uptime monitoring

Or use the **Elastic Agent** — a single agent that handles everything, managed via Fleet.

---

## Elastic Common Schema (ECS)

This is the feature that makes Elastic useful in practice.

ECS is a standardized field naming convention that ensures consistency across data sources. Without it, different log sources use different names for the same thing:

- `src_ip` vs `source_address` vs `client.ip` — all mean the same thing
- `user` vs `username` vs `account_name` — same concept, different fields

ECS normalizes these.

### Key ECS Field Categories

| Category | Fields |
|----------|--------|
| **Network** | `source.ip`, `destination.ip`, `source.port`, `destination.port` |
| **Process** | `process.name`, `process.pid`, `process.command_line`, `process.parent.pid` |
| **User** | `user.name`, `user.id`, `user.domain` |
| **Event** | `event.action`, `event.category`, `event.outcome`, `event.type` |
| **Host** | `host.name`, `host.os.family`, `host.os.name` |
| **File** | `file.name`, `file.path`, `file.hash.sha256` |

### Why ECS Matters

With ECS, you can write one query that works across all data sources:

```kql
source.ip: "192.168.1.100"
```

This finds every event involving that IP — Windows logs, firewall logs, Sysmon, web server logs — without caring what the original field name was.

---

## KQL (Kibana Query Language)

KQL is the primary query language in Kibana. Much simpler than SPL, closer to Lucene.

### Basic Syntax

```kql
user.name: "admin"
source.ip: 192.168.1.* AND event.action: "logon-failed"
process.name: "powershell.exe" AND NOT user.name: "SYSTEM"
```

### Key Features

- **Field-based queries** — `field: value`
- **Wildcards** — `source.ip: 10.0.*` matches any IP starting with 10.0
- **Boolean operators** — `AND`, `OR`, `NOT`
- **Ranges** — `@timestamp > "2026-01-01"`
- **Existence check** — `process.name: *` (field exists)
- **Free-text search** — search all fields without specifying

### KQL vs Splunk SPL

| Feature | KQL | SPL |
|---------|-----|-----|
| **Syntax** | Simple field:value | Pipe-based |
| **Transformations** | Done in Kibana UI | Inline via `stats`, `table` |
| **Learning curve** | Easy | Moderate |
| **Power** | Good for filtering | Better for transformations |
| **Field naming** | ECS (standardized) | sourcetype-specific |

KQL is better for filtering. Splunk SPL is better for transformations. Elastic handles transformations through **aggregations** in the UI rather than in the query string.

---

## The Kibana Interface

### Discover

The primary search interface for exploring raw log data.

- Set time ranges with the time picker (top right)
- Use KQL in the search bar to filter events
- Expand individual events to see all fields
- Add columns to the results table for focused analysis
- Save queries for reuse

### Visualize

Create visual representations of data:

- Bar charts, line charts, pie charts
- Data tables
- Metric displays
- Maps (geo-IP visualization)
- Heatmaps

Each visualization is powered by a saved search or index pattern, and uses **aggregations** (count, sum, average, unique count, percentile, etc.).

### Dashboards

Combine multiple visualizations into a single view:

- Real-time or snapshot-based monitoring
- Interactive filters that apply across all panels
- Shareable and embeddable in other tools
- Can be exported as PDF

### Fleet

Centralized agent management. Deploy and manage data collection policies across thousands of endpoints from one place. Simplifies:

- Adding new log sources
- Updating collection policies
- Agent version management
- Certificate rotation

---

## Investigation Pattern: Failed Login Attempts

Classic SOC investigation:

```kql
event.action: "logon-failed" AND source.ip: 10.0.2.*
```

Then in Kibana Discover:
1. Add columns: `@timestamp`, `user.name`, `source.ip`, `host.name`
2. Sort by timestamp
3. Look for patterns — same IP hitting multiple accounts, or same account from multiple IPs
4. Pivot to other events from the same IP

---

## Investigation Pattern: Suspicious PowerShell

```kql
process.name: "powershell.exe" AND 
(process.command_line: *EncodedCommand* OR process.command_line: *FromBase64String* OR process.command_line: *DownloadString*)
```

This catches common PowerShell obfuscation and download cradles. Add filters:

- `user.name: *` to exclude SYSTEM
- `host.name: *servers*` to focus on servers
- `@timestamp > "now-24h"` for recent activity

---

## Investigation Pattern: Credential Dumping

Looking for LSASS access:

```kql
event.code: "4656" AND winlog.event_data.ObjectName: *lsass.exe*
```

- Event ID 4656 = Handle to an object was requested
- Filter for handles to LSASS
- Legitimate processes rarely access LSASS memory

Combine with `process.name` to see which process is doing it.

---

## Investigation Pattern: Lateral Movement via PsExec

```kql
event.action: "service-installed" AND 
(winlog.event_data.ServiceName: "PSEXESVC" OR winlog.event_data.ServiceFileName: *PSEXESVC*)
```

PsExec leaves a service installation trail. Hunt for it specifically — or use `winlog.event_data.ServiceName: *` to see all recently installed services and spot anomalies.

---

## Investigation Pattern: Scheduled Task Persistence

```kql
event.code: "4698" OR event.code: "4702"
```

- 4698 = A scheduled task was created
- 4702 = A scheduled task was updated

Check for tasks created by unusual users, at unusual times, or with suspicious names.

---

## Investigation Pattern: Network Exfiltration

```kql
network.transport: "tcp" AND 
(destination.bytes > 10000000 OR source.bytes > 10000000) AND 
NOT destination.ip: (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
```

Find large outbound TCP flows to non-internal IPs. Tune the threshold for your environment. Add `destination.geo.country_iso_code` to spot traffic going to unusual countries.

---

## Elastic SIEM for Threat Hunting

Elastic has a dedicated SIEM app that layers hunting-specific features on top of the base stack:

- **Pre-built detection rules** mapped to MITRE ATT&CK
- **Timeline** for building investigation flows
- **Case management** integrated with Kibana
- **Hosts and Network views** for entity-centric investigation
- **Maps** for geo-based analysis
- **Anomaly detection** via machine learning jobs

The SIEM app is free with the base Elastic Stack. The paid tier adds advanced features like automated response actions and premium detection rules.

---

## Tips for Working with Elastic

- **Use ECS fields when available** — your queries work across data sources
- **Save searches and visualizations** — reuse, don't rewrite
- **Use filters instead of KQL when possible** — filters are cached and faster
- **Use `@timestamp` range explicitly** — avoid scanning all data
- **Take advantage of runtime fields** for ad-hoc calculations without reindexing
- **Alias fields** when onboarding new data sources that don't match ECS
- **Use Data Views** to control which indices Kibana searches

---

## Key Takeaways

- Elastic = **Beats → (Logstash) → Elasticsearch → Kibana**
- **ECS** is what makes Elastic useful — standardized field names
- **KQL** is simpler than SPL, better for filtering
- **Discover** is for raw data, **Visualize** for charts, **Dashboards** for views
- **Fleet** for managing agents at scale
- Use **ECS fields** (`source.ip`, `user.name`) for queries that work across sources
- **Pre-built rules** in Elastic SIEM are mapped to MITRE ATT&CK
- KQL + aggregations in the UI replaces SPL's inline transformations
- Free core features handle 80% of blue team needs
- The paid tier adds ML, advanced detection, and automated response
