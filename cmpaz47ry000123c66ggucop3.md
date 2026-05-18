---
title: "Network Security: IDS/IPS and Snort"
datePublished: 2026-05-18T09:00:00.000Z
cuid: cmpaz47ry000123c66ggucop3
slug: network-security-ids-ips-and-snort
cover: https://raw.githubusercontent.com/Jung0310-bit/woogi-blog-assets/main/thumbnails/network-security-ids-snort.png
tags: cybersecurity, network-security, ids, blue-team, snort

---

Network defense splits cleanly into two questions: **what gets through the perimeter, and what do you do when something does?** This post covers the second question. IDS, IPS, the detection techniques behind them, and Snort, the open-source NIDS that most blue teamers will encounter first.

---

## Network Security Fundamentals

Network security operates across three control levels:

| Level | Examples |
|---|---|
| **Physical** | Locks, gates, CCTV, guards |
| **Technical** | Firewalls, VPNs, encryption, segmentation |
| **Administrative** | Policies, access reviews, training |

The technical layer is where blue teamers spend most of their time. Within it, two families of tools matter most:

- **Access controls**: firewalls, NAC, IAM, Zero Trust, VPN, segmentation. Decide who gets to talk to what.
- **Threat controls**: IDS/IPS, DLP, SIEM, SOAR, NDR. Watch the conversations that do happen.

This post is about the threat controls, specifically the IDS/IPS pair and the rule-based detection that powers them.

---

## IDS vs IPS

### Intrusion Detection System (IDS)

Passive. Watches traffic, alerts on suspicious patterns, doesn't block.

| Type | Where it sits |
|---|---|
| **NIDS** | Monitors a network segment, typically inline, on a tap, or via a SPAN port |
| **HIDS** | Monitors a single endpoint's traffic and host events |

NIDS is what most blue team posts mean when they say "IDS." It sees east-west traffic, north-south traffic, or both, depending on placement.

### Intrusion Prevention System (IPS)

Active. Same detection, but sits in the path and can drop or terminate connections.

| Type | Notes |
|---|---|
| **NIPS** | Network-level blocking; terminates malicious connections in real time |
| **NBA (Network Behavior Analysis)** | Needs a baseline period; flags deviations from learned normal |
| **WIPS** | Wireless-specific |
| **HIPS** | Endpoint-level autonomous defensive actions |

The IDS/IPS distinction is mostly operational. Same engine, same rules. The deployment model decides whether you alert or block.

### When to use which

- **IDS first** when you're new to a network. You don't know what normal looks like, and false-positive blocks are expensive.
- **IPS** for high-confidence rules (known C2 callbacks, signature-confirmed malware) where blocking is cheaper than investigating.
- Most production networks run both: IPS for the obvious, IDS for everything else.

---

## Detection Techniques

Three broad categories. Most modern engines combine them.

| Technique | What it does | Trade-off |
|---|---|---|
| **Signature-based** | Matches known malicious patterns (byte sequences, regex, hashes) | High precision on known threats. Blind to new ones. |
| **Behavior-based** | Compares observed traffic against a learned baseline | Catches unknowns. Generates false positives until baseline matures. |
| **Policy-based** | Flags violations of explicit security policy or configuration | Useful for compliance. Limited to what you've encoded. |

For a blue team analyst's daily work, signature rules dominate. That's what Snort gives you.

---

## Snort: The Standard Open-Source NIDS

Snort is an open-source NIDS/NIPS originally written by Martin Roesch in 1998 and now maintained by Cisco Talos. It's still the reference implementation for rule-based network detection, and most commercial NIDS engines either embed Snort or speak its rule syntax.

Two reasons to start with Snort:

1. The ruleset is public, well-documented, and updated continuously by Talos
2. Snort rules read closely to how you'd describe an attack on a whiteboard, which makes it good for learning detection engineering

### Operating Modes

Snort runs in three modes, controlled by command-line flags:

| Mode | Flag | Purpose |
|---|---|---|
| **Sniffer** | `-v`, `-d`, `-e`, `-X` | Read packets and print them to console (a tcpdump-lite) |
| **Packet Logger** | `-l <dir>`, `-K ASCII`, `-r` | Write packets to disk for offline analysis |
| **NIDS / NIPS** | `-c <conf>`, `-A`, `-D`, `-Q --daq afpacket` | Apply rules and alert (NIDS) or drop (NIPS) |

### Key Parameters

```
-c /etc/snort/snort.conf      # use this config
-T                            # test config and exit
-A console                    # alerts to console (also: cmg, full, fast, none)
-l .                          # log to current directory
-r capture.pcap               # read packets from a pcap file
-r capture.pcap 'tcp port 80' # BPF filter on read
-Q --daq afpacket             # IPS mode (inline drops)
```

### Alert Output Modes

| Mode | What you get |
|---|---|
| `console` | Fast-style alerts on screen, one line per match |
| `cmg` | Full headers and payload (hex + text) |
| `full` | Everything written to alert file, no console output |
| `fast` | Timestamp + 5-tuple to file |
| `none` | Disable alerting, still log packets |

For investigation work, `cmg` is the most informative. For SIEM forwarding, `fast` is the cleanest format to parse.

---

## Reading a Snort Rule

A simplified rule structure:

```
alert tcp any any -> $HOME_NET 445 (msg:"Possible SMB lateral movement"; \
    content:"|FF|SMB"; offset:4; depth:5; sid:1000001; rev:1;)
```

Breaking it down:

- `alert` — action (also `log`, `pass`, `drop` for IPS)
- `tcp any any -> $HOME_NET 445` — protocol, source, destination
- `msg:"..."` — what shows up in the alert
- `content:"|FF|SMB"` — byte pattern in payload (`|FF|` is hex)
- `offset:4; depth:5` — search window in the packet
- `sid:1000001` — unique signature ID
- `rev:1` — rule revision

The art is in the conditions. Tight rules (specific bytes at specific offsets) catch real attacks with low false positives. Loose rules (any payload containing X) catch more but flood your alert console.

### Common Rule Modifiers

| Modifier | Purpose |
|---|---|
| `pcre:"/regex/"` | Regex match on payload |
| `flow:established,to_server` | Match only on established TCP flows in one direction |
| `dsize:>1024` | Match packets larger than 1024 bytes |
| `flags:S` | Match TCP SYN flag (handshake initiation) |
| `threshold: type limit, track by_src, count 5, seconds 60` | Rate-limit alerting |

Threshold-style rules are how you turn a noisy detection into a useful one. Don't alert on every failed login; alert on five failures from the same source in a minute.

---

## A Realistic Investigation Workflow

How a Snort alert turns into an actual investigation:

1. **Alert fires.** Snort flags traffic matching `sid:1000001` in `fast` format. The SIEM ingests it.
2. **Triage.** Pull the matching packet from the pcap (Snort logs the trigger packet) and the surrounding flow. Look at source, destination, time of day, and whether the flow makes business sense.
3. **Pivot.** Cross-reference the source IP against firewall logs, proxy logs, endpoint EDR. Is this part of a larger pattern or a one-off?
4. **Confirm or dismiss.** Either escalate (and start incident response) or document as a false positive and tune the rule.
5. **Tune.** A rule that fires 200 times a day on benign traffic is worse than no rule. Add exceptions, narrow conditions, or rate-limit.

Tuning is the unglamorous half of detection engineering. Good rules look obvious in hindsight; getting them obvious is the work.

---

## Where Snort Fits in a Modern Stack

Snort isn't the only NIDS engine, and rarely runs alone:

- **Suricata** — Snort-compatible rule syntax, multi-threaded, often replaces Snort in performance-sensitive deployments
- **Zeek (formerly Bro)** — Less rule-focused, more script-driven; produces structured logs that pair well with SIEM
- **Commercial NIDS** — Most embed Snort or Suricata signatures, plus their own behavior-based engines

In a typical SOC, you'd see Snort or Suricata generating the alerts, Zeek generating the rich connection logs, and a SIEM (see [Splunk for Blue Team](https://woogi.me/splunk-for-blue-team-spl-queries-and-investigation-patterns) or [Elastic SIEM and KQL](https://woogi.me/elastic-siem-and-kql-the-open-source-alternative-to-splunk)) tying both to host telemetry.

---

## Practical Takeaways

- Start IDS-first, then add IPS rules where false positives are cheap and blocks are valuable
- Signature-based rules are most of what you'll write and tune day to day
- Snort rules are readable. If you can describe the attack in one sentence, you can usually write a rule for it
- Tuning is the job, not an afterthought. A noisy rule is no rule.

Next post in the network series: a walk through Wireshark for the same kind of investigation, but at the per-packet level instead of the alert level.
