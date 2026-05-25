---
title: "Wireshark: Traffic Analysis for IR"
datePublished: 2026-05-25T09:00:00.000Z
cuid: cmpkz72e5000023cu041qgrqx
slug: wireshark-traffic-analysis-for-ir
cover: https://raw.githubusercontent.com/Jung0310-bit/woogi-blog-assets/main/thumbnails/wireshark-traffic-analysis.png
tags: cybersecurity, blue-team, wireshark, network-forensics

---

When a Snort alert fires or a NetFlow anomaly surfaces, the next question is always the same: **what actually happened on the wire?** Wireshark is the answer most blue teamers reach for. This post is a working tour of display filters, scan detection patterns, and stream reconstruction, focused on the moves that show up in real PCAP investigations.

---

## Why Wireshark

A protocol analyzer with a GUI, deep dissectors for 3000+ protocols, and a filter language that lets you slice a million-packet capture down to the dozen that matter. Open-source, cross-platform, and basically the lingua franca for talking about packet-level evidence.

You'll use it for:

- Investigating PCAPs from a NIDS or full-packet-capture device
- Understanding what an alert means at the packet level
- Reconstructing what was sent or downloaded over a session
- Spotting tunneling, scanning, and protocol abuse

---

## Capture Filters vs Display Filters

Two filter systems, often confused.

| Filter Type | When | Syntax | Editable mid-capture |
|---|---|---|---|
| **Capture Filter** | Before capture starts | BPF (`tcp port 80`) | No |
| **Display Filter** | After capture, on existing data | Wireshark's own (`tcp.port == 80`) | Yes, anytime |

Capture filters reduce what you record. Use them when you can't afford to capture everything (high-volume links, limited disk). Display filters narrow what you view. Use them everywhere else.

### Display Filter Operators

| Symbol | Word | Example |
|---|---|---|
| `==` | `eq` | `ip.addr == 10.10.10.111` |
| `!=` | `ne` | `tcp.port != 443` |
| `&&` | `and` | `ip.src == 10.0.0.1 and tcp.port == 80` |
| `\|\|` | `or` | `tcp.port == 80 or tcp.port == 443` |
| `!` | `not` | `not arp` |

Filter bar color tells you about syntax: **green** = valid, **red** = error, **yellow** = ambiguous.

---

## Filters You'll Actually Use

```
ip.addr == 10.10.10.111
ip.src == 10.0.0.5 and ip.dst == 8.8.8.8

tcp.port == 80
http.request.method == "POST"
http.response.code == 200

dns.flags.response == 0          # DNS requests only
dns.qry.type == 1                # A records
dns.qry.name contains "suspicious"

ftp.response.code == 530         # Failed FTP login
ftp.request.command == "USER"    # Username field

tcp.flags.syn == 1 and tcp.flags.ack == 0   # SYN packets

icmp.type == 3 and icmp.code == 3   # ICMP destination unreachable
```

### Advanced Operators

| Operator | Use | Example |
|---|---|---|
| `contains` | Substring match | `http.server contains "Apache"` |
| `matches` | Regex | `http.host matches "\.(php\|html)"` |
| `in` | Set membership | `tcp.port in {80 443 8080}` |
| `upper` / `lower` | Case folding | `lower(http.user_agent) contains "curl"` |

---

## Detecting Common Attacks

### Nmap Scans

| Scan | Filter | Tell |
|---|---|---|
| TCP Connect (`-sT`) | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` | Full handshake, large window |
| SYN Stealth (`-sS`) | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024` | Half-open, small window |
| UDP (`-sU`) | `icmp.type==3 and icmp.code==3` | ICMP "port unreachable" responses |

### ARP Poisoning / MITM

```
arp.duplicate-address-detected
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == <suspect_mac>)
```

Multiple ARP responses for the same IP within a short window is the signature. Confirm by checking whether HTTP traffic routes through an unexpected MAC.

### Tunneling

```
data.len > 64 and icmp                       # ICMP tunneling (oversized payloads)
dns.qry.name.len > 15 and !mdns              # Long DNS labels (encoded payloads)
dns contains "dnscat"                        # Known tunneling tool fingerprint
```

### Cleartext Credential Exposure

```
ftp.request.command == "USER"   # Username in plaintext
ftp.request.command == "PASS"   # Password in plaintext
ftp.response.code == 530        # Failed login (brute force indicator)
```

For HTTP basic auth or unencrypted form posts, follow the TCP stream and read.

---

## Statistics: Where to Start

When you open a fresh PCAP, hit `Statistics` first.

| Menu | Use |
|---|---|
| `Resolved Addresses` | Quick map of IPs to hostnames |
| `Protocol Hierarchy` | What protocols dominate? Anything unexpected? |
| `Conversations` | Top talkers by bytes, packets, duration |
| `Endpoints` | Unique sources and destinations, with optional GeoIP |
| `DNS` / `HTTP` | Per-protocol breakdowns |

A weird Protocol Hierarchy is often the first sign of trouble. ICMP at 30% of total bytes? DNS averaging 200-byte responses? Something's tunneling.

---

## Stream Reconstruction

`Analyse > Follow > TCP Stream` (or UDP/HTTP) reconstructs the application-layer dialogue between two endpoints.

- Client traffic shows in **red**
- Server traffic shows in **blue**
- You can save the reconstructed stream as raw bytes, ASCII, or hex

This is how you read what the attacker sent, what the C2 server replied, or what file got exfiltrated. For HTTPS, you'll need TLS keys (load via `Edit > Preferences > Protocols > TLS`); without keys, the streams are encrypted blobs.

---

## Object Extraction

`File > Export Objects > HTTP/SMB/FTP` lists every transferred file in the capture: hostname, content type, size, filename. One click to extract.

Pair with **Binwalk** to detect embedded or hidden content inside extracted files (a common technique for staging malware inside images).

For carving raw bytes out of arbitrary streams, use **NetworkMiner** alongside Wireshark; it handles the artifact extraction better for non-standard protocols.

---

## A PCAP Investigation Walk-Through

A concrete example. Snort fires `sid:1000247` flagging "possible Cobalt Strike beacon to non-routable destination" on host `10.0.5.42`. The full-packet-capture system saved 30 minutes of context around the alert.

**Step 1: Open the PCAP, scope the noise.**

```
ip.addr == 10.0.5.42
```

5,200 packets. Too many to read directly. Hit Statistics → Conversations.

**Step 2: Identify the suspect destination.**

Sort by bytes. The top external talker is `185.220.101.x` over TCP/443. Volume is small (~80 KB) but the connection count is high (47 connections in 30 minutes). Beacon-like.

**Step 3: Drill into one beacon.**

```
ip.addr == 185.220.101.x and tcp.port == 443
```

47 conversations. `Follow > TCP Stream` on one of them. Without TLS keys, the stream is encrypted. But the timing and packet sizes are visible.

**Step 4: Extract the timing pattern.**

Statistics → I/O Graphs, filter by suspect IP. The connections cluster every ~38 seconds with low jitter. That's a classic beaconing interval (Cobalt Strike default is 60s; this is shorter, possibly tuned).

**Step 5: Cross-reference.**

`185.220.101.0/24` is a known Tor exit range. Any beaconing to Tor from a corporate workstation is a high-confidence indicator.

**Step 6: Pivot to host telemetry.**

Hand off to EDR or Sysmon logs from `10.0.5.42`. What process owns the connection? When did it start? What spawned it? Wireshark shows you the wire; the host telemetry shows you who's talking.

The investigation total: 12 minutes from alert to confirmed compromise. The Wireshark portion was 5 of those minutes.

---

## tshark for Command-Line Workflows

For larger captures, scripted analysis, or pipelining into a SIEM, the GUI is overkill. **tshark** is the same engine, command-line.

```bash
# Display filter from CLI, output as text
tshark -r capture.pcap -Y "http.request.method == POST"

# Specific fields, tab-separated (good for piping)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e http.host

# JSON output for ingestion
tshark -r capture.pcap -T json > capture.json

# Read live from interface, write rotating PCAPs
tshark -i eth0 -b duration:3600 -b files:24 -w hourly.pcap
```

For a SOC pipeline, the typical use is:

1. Continuous capture on critical segments
2. Hourly rotation
3. tshark + a script to extract specific signals (DNS query frequency, TLS SNI list, NetFlow-like summaries)
4. Forward to SIEM as structured events

---

## Common Gotchas

A short list of things that bite analysts new to Wireshark:

- **Packets shown out of order.** TCP reassembly is on by default, but UDP and some application protocols aren't reassembled. If a stream looks fragmented, check `Edit > Preferences > Protocols > <protocol> > Reassemble`.
- **TLS without keys.** You will see encrypted blobs and that's all. There's no analysis path without `(Pre)-Master-Secret log filename` set during capture, OR access to the server's RSA private key.
- **Truncated packets.** If `Frame.cap_len < Frame.len`, your capture engine truncated. Defaults are usually 96 bytes for production deployments. Set the snaplen to 0 (unlimited) for forensic captures.
- **Time zones.** PCAP timestamps are typically UTC, but Wireshark displays in local time by default. Switch to UTC via `View > Time Display Format > UTC` for analyst sanity, especially across teams.
- **Display vs capture filter syntax.** They're different languages. `tcp port 80` is a capture filter. `tcp.port == 80` is a display filter. Mixing them up is the most common beginner mistake.

---

## Practical Workflow

How a typical PCAP investigation runs:

1. **Open the capture, glance at Protocol Hierarchy.** Anomalies surface here fast.
2. **Filter by suspect IP** if one's known from an upstream alert. Otherwise, work top-talkers in `Conversations`.
3. **Drill into the suspect flow.** Apply `Follow Stream` to see what was actually said.
4. **Extract any files transferred.** Hash them, match against threat intel.
5. **Document the indicators.** IPs, domains, file hashes, user-agents, anything that ATT&CK-maps to a technique.

Wireshark is fast once your filter muscle is built. The first 50 captures are slow; the next 500 are quick.

---

## Closing

Wireshark is the per-packet companion to a NIDS like Snort. Snort tells you where to look; Wireshark tells you what was said. Get fluent in the filter language, and PCAP investigations stop being an arcane skill and become a fast lookup.

Next: a shift away from network and into proactive defense. **Threat hunting** is the discipline of looking for compromise before alerts fire.
