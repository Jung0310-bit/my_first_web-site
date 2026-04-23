---
title: "Kill Chain, Diamond Model, Pyramid of Pain: Three Frameworks Every Blue Teamer Should Know"
datePublished: 2026-04-23T09:00:00.000Z
cuid: cmob93rtf000021fl1zk8e8t6
slug: kill-chain-diamond-model-pyramid-of-pain-three-frameworks-every-blue-teamer-should-know
tags: cybersecurity, blue-team, threat-intelligence, diamond-model, kill-chain

---

# Kill Chain, Diamond Model, Pyramid of Pain: Three Frameworks Every Blue Teamer Should Know

ATT&CK gets most of the attention, but there are three other frameworks that every blue teamer should understand. Each solves a different problem: the Cyber Kill Chain gives you a linear attack lifecycle, the Diamond Model relates attack components, and the Pyramid of Pain tells you which detections actually hurt attackers. This post covers all three.

---

## Cyber Kill Chain

Developed by Lockheed Martin in 2011. A seven-stage sequential model describing how attacks progress from recon to objective completion.

### The Seven Stages

All seven must complete for an attack to succeed. Breaking any one disrupts the chain.

```
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives
```

### Stage Breakdown

**1. Reconnaissance** — gathering information about the target.
- OSINT, domain lookups, port scanning, social media profiling
- Tools: theHarvester, Hunter.io, OSINT Framework, Nmap
- Defender: monitor for unusual port scans, unsolicited contact

**2. Weaponization** — creating the payload.
- Combining malware with an exploit (macro-enabled Office docs, backdoors)
- Setting up C2 infrastructure
- Defender: limited visibility — rely on threat intel and hardening

**3. Delivery** — transmitting the payload to the target.
- Spear-phishing, infected USB drives, watering hole attacks
- Defender: email sandboxing, web filtering, user training

**4. Exploitation** — triggering the vulnerability.
- Malicious attachments, phishing links, zero-days, server-side exploits
- Defender: patch management, vulnerability scanning, hardening

**5. Installation** — establishing persistence.
- Web shells, Meterpreter backdoors, service modification, registry run keys
- Timestomping to evade forensics
- Defender: EDR, file integrity monitoring, behavioral analysis

**6. Command & Control (C2)** — maintaining remote access.
- HTTP/HTTPS on ports 80/443 to blend in, DNS tunneling
- Beaconing: consistent communication pattern
- Defender: network traffic analysis, DNS monitoring, C2 blocking

**7. Actions on Objectives** — achieving the end goal.
- Credential theft, lateral movement, exfiltration, ransomware, data destruction
- Defender: DLP, network segmentation, rapid IR

### Limitations of the Kill Chain

- **No updates since 2011** — doesn't reflect modern attack patterns
- **Linear model** — real attacks are iterative; phases repeat
- **Network perimeter focus** — doesn't cover insider threats
- **Too generic** — no technique-level granularity

### Unified Kill Chain (UKC)

Developed by Paul Pols in 2017 to address CKC limitations. Combines Kill Chain with MITRE ATT&CK into **18 phases** across three macro-phases:

- **Phase In** — initial foothold (8 phases)
- **Phase Through** — network propagation (6 phases)
- **Phase Out** — actions on objectives (4 phases)

UKC is more realistic for modern defense work, but CKC is still used for high-level executive reporting because it's simpler.

---

## Diamond Model

Developed in 2013 by Caltagirone, Pendergast, and Betz. A framework for analyzing intrusions through relationships between four core components.

### The Four Core Features

The components form a diamond shape, edge-connected:

```
        Adversary
           /\
          /  \
         /    \
Infrastructure—Capability
         \    /
          \  /
           \/
         Victim
```

Every intrusion event has all four.

**Adversary** — the actor behind the attack.
- **Operator** — individual(s) executing the intrusion
- **Customer** — entity benefiting from the attack (may be different from operator)

**Victim** — the target (always present).
- **Persona** — people/organizations targeted
- **Assets** — attack surface: networks, email, hosts, IPs, accounts

**Capability** — skills, tools, and TTPs used.
- Ranges from basic (password guessing) to advanced (zero-day, custom malware)
- Includes the "adversary arsenal" — the complete set of capabilities

**Infrastructure** — physical or logical systems for delivery and control.
- **Type 1** — owned directly by the adversary
- **Type 2** — intermediary (malware staging, compromised email, malicious domains)
- Service providers (ISPs, registrars) support both types

### Additional Axes

Two extra axes extend the core diamond:

**Socio-Political** — the adversary's motivation.
- Financial gain
- Hacktivism
- Espionage
- Reputation / community acceptance

**Technology** — how capability and infrastructure interact.
- Example: watering-hole attack combines compromised website (infrastructure) with drive-by exploit (capability)

### Meta-Features

Six optional additions for context:

| Meta-Feature | Description |
|-------------|-------------|
| **Timestamp** | When the event occurred |
| **Phase** | Kill Chain stage (for alignment) |
| **Result** | Success, Failure, or Unknown |
| **Direction** | Event flow (Victim→Infra, Infra→Victim, etc.) |
| **Methodology** | General classification (phishing, DDoS, port scan) |
| **Resources** | External requirements (software, creds, funds, access) |

### Practical Use

**Pivoting** — use one known feature to discover others. Example:
1. Known IP (infrastructure) → WHOIS lookup → adversary identification
2. Adversary → other known infrastructure → new campaigns

**Campaign tracking** — correlate multiple events across time to identify ongoing campaigns.

**Communication** — explain incidents to non-technical audiences using the diamond structure.

**Forecasting** — predict adversary behavior based on patterns.

---

## Pyramid of Pain

Created by David J. Bianco. Visualizes how difficult it is for adversaries to change different types of indicators when defenders detect them.

The higher you push detection, the more pain you cause the attacker.

### The Seven Levels

Note: Bianco's original Pyramid of Pain has six tiers because Host Artifacts and Network Artifacts share the "Annoying" level. Here I split them for clarity.

```
         ┌─────────┐
         │  TTPs   │  ← Tough!
         ├─────────┤
         │  Tools  │  ← Challenging
         ├─────────┤
         │ Network │
         │Artifacts│  ← Annoying
         ├─────────┤
         │  Host   │
         │Artifacts│  ← Annoying
         ├─────────┤
         │ Domain  │
         │  Names  │  ← Simple
         ├─────────┤
         │   IP    │
         │Addresses│  ← Easy
         ├─────────┤
         │  Hash   │
         │ Values  │  ← Trivial
         └─────────┘
```

### Layer Breakdown

**1. Hash Values — Trivial**
- Single character change = different hash
- Attackers trivially modify files to evade hash-based detection
- Use for: specific sample identification in reports
- Tools: VirusTotal, Metadefender

**2. IP Addresses — Easy**
- Attackers switch IPs via VPN, TOR, proxies
- **Fast Flux** — rapid IP rotation via DNS
- Defender: firewall blocklists (necessary but insufficient)

**3. Domain Names — Simple**
- Changing domains requires purchase and DNS setup
- But: lax DNS providers and automation make it easier than expected
- **Punycode attacks** — non-ASCII chars mimicking legit domains (e.g., `аdidas.de` vs `adidas.de`)
- **URL shorteners** hide destinations (append `+` to bit.ly to reveal)
- Defender: proxy logs, DNS filtering

**4. Host Artifacts — Annoying**
- Traces on the system: registry values, processes, dropped files
- Example: suspicious process spawned from Word, files in specific directories
- Detection forces attackers to revise tools and methodology
- Defender: EDR detection rules, file integrity monitoring

**5. Network Artifacts — Annoying**
- Observable patterns in network traffic
- Unusual User-Agent strings, C2 beaconing patterns, URI patterns in POSTs
- Example: Emotet downloader traffic patterns
- Detection methods: Wireshark PCAP analysis, Snort IDS
- Blocking custom User-Agents disrupts operations

**6. Tools — Challenging**
- Malicious macros, backdoors, custom exes, password crackers, exploit kits
- Detecting tools forces attackers to abandon or retool
- Methods: YARA rules, AV signatures, SSDeep fuzzy hashing
- Resources: MalwareBazaar, Malshare, SOC Prime

**7. TTPs — Tough (Apex)**
- Tactics, Techniques, and Procedures — mapped to MITRE ATT&CK
- Covers the full spectrum of adversary behavior
- Detecting TTPs leaves almost no room to maneuver
- Example: Detecting Pass-the-Hash via Windows Event Logs halts lateral movement

### Strategic Implications

| Layer | Pain to Attacker | Defender Action |
|-------|------------------|----------------|
| Hash Values | None | Block specific hashes |
| IP Addresses | Low | Firewall/proxy blocklists |
| Domain Names | Moderate | DNS filtering |
| Host Artifacts | Moderate-High | EDR rules, FIM |
| Network Artifacts | Moderate-High | IDS signatures |
| Tools | High | YARA, AV, fuzzy hashing |
| TTPs | Maximum | Behavioral detection, ATT&CK-mapped rules |

**Push detection upward.** Hash and IP blocking are necessary but insufficient. TTP-level behavioral detection is the most durable defense.

---

## Using All Three Frameworks Together

These frameworks don't compete — they complement each other.

| Framework | What It Answers |
|-----------|----------------|
| **Kill Chain** | What stage is the attack in? |
| **Diamond Model** | What are the relationships between components? |
| **Pyramid of Pain** | How durable is my detection? |
| **MITRE ATT&CK** | What specific technique is being used? |

### Example: Investigating a Phishing-to-Ransomware Incident

**Kill Chain mapping:**
1. Recon — LinkedIn scraping for emails
2. Weaponization — malicious Excel with macro
3. Delivery — phishing email
4. Exploitation — user enabled macro
5. Installation — Cobalt Strike beacon
6. C2 — HTTPS beaconing to attacker domain
7. Actions on Objectives — ransomware deployment

**Diamond Model analysis:**
- Adversary: FIN7 (based on TTPs and infrastructure overlap)
- Victim: Finance team at our company (spear-phishing target)
- Capability: Cobalt Strike, custom loader, known ransomware family
- Infrastructure: bit.ly redirect → compromised WordPress → C2 server

**Pyramid of Pain check** for our detections:
- Hash of initial dropper → Trivial (attacker will change it)
- C2 IP → Easy (will rotate)
- C2 domain → Simple (will register new one)
- Cobalt Strike beacon pattern → Network Artifact (Annoying)
- Cobalt Strike binary detection → Tool (Challenging)
- Macro-enabled Office doc execution chain → TTP (Tough)

**Action:** Build detections at the TTP level (macro execution → PowerShell → network beaconing). That's what actually hurts the attacker.

---

## Key Takeaways

- **Kill Chain** — linear attack progression, good for high-level thinking
- **Unified Kill Chain (UKC)** — modern replacement, 18 phases, realistic
- **Diamond Model** — relational analysis, great for pivoting and campaign tracking
- **Pyramid of Pain** — tells you which detections actually hurt attackers
- **Push detection up the pyramid** — TTPs cause maximum pain
- Use frameworks **together**, not competitively
- Map every incident across all frameworks for complete analysis
- Kill Chain for executives, Diamond Model for analysts, Pyramid of Pain for detection engineers
