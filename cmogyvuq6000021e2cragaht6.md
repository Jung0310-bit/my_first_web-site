---
title: "Digital Forensics Fundamentals: Evidence to Analysis"
datePublished: 2026-04-27T09:00:00.000Z
cuid: cmogyvuq6000021e2cragaht6
slug: digital-forensics-fundamentals-evidence-to-analysis
tags: cybersecurity, forensics, digital-forensics, blue-team, dfir

---

# Digital Forensics Fundamentals: Evidence to Analysis

Digital forensics is the part of blue team work where mistakes are permanent. Modify a disk, lose a memory snapshot, break the chain of custody — evidence becomes inadmissible. This post covers the fundamentals: the forensic process, evidence collection, order of volatility, and the tools that actually work.

---

## What is Digital Forensics?

Digital forensics is the scientific examination of digital devices and data to uncover evidence of incidents, intrusions, or criminal activity. It applies to:

- Computers and servers
- Mobile devices
- Network traffic
- Volatile memory (RAM)

When combined with Incident Response, the discipline is **DFIR** — Digital Forensics and Incident Response.

---

## The Five-Step Process

Every forensic investigation follows the same steps.

1. **Identification** — locate potential evidence sources, custodians, data locations
2. **Preservation** — protect ESI (Electronically Stored Information), prevent tampering
3. **Collection** — acquire evidence through imaging, copying, or capturing
4. **Analysis** — systematically examine artifacts to uncover findings
5. **Reporting** — produce detailed, reproducible reports

The order matters. You can't analyze what you didn't preserve.

---

## Order of Volatility (RFC 3227)

Collect evidence from most volatile to least volatile. Everything higher in this list disappears faster.

1. **Registers & Cache** — most volatile, changes constantly (rarely captured)
2. **Memory (RAM)** — active processes, network connections, encryption keys
3. **Disk (HDD/SSD)** — persistent but can be overwritten (SSD TRIM)
4. **Remote Logging** — log rotation may cause data loss
5. **Physical Configuration** — least volatile

**Practical order:**
```
Memory image → Triage image → Full disk image
```

Memory first because it's gone the moment the system powers off.

---

## Memory Acquisition

### Live Acquisition (System Powered On)

Three factors when choosing a tool:

- **Footprint** — smaller is better (less chance of overwriting evidence in RAM)
- **Mode** — kernel-mode tools access more memory and bypass anti-debugging
- **Speed** — faster acquisition reduces the chance of memory state changing mid-capture

### Common Tools

| Tool | Mode | Output |
|------|------|--------|
| **DumpIt** | Kernel | `.dmp` / `.raw` |
| **BelkaSoft RAM Capturer** | Kernel | `.mem` |
| **FTK Imager** | User | `.mem` (with optional pagefile) |

### FTK Imager Workflow

1. `File → Capture Memory`
2. Choose save location
3. Optionally include pagefile
4. Run — wait for completion
5. Analyze with **Volatility**

### Dead Acquisition (System Powered Off)

When RAM is unavailable, partial memory data may exist in:

- **hiberfil.sys** — full RAM snapshot from hibernation (size ≈ RAM size)
- **pagefile.sys** — paged-out RAM data (partial, may contain credentials/artifacts)
- **C:\Windows\MEMORY.DMP** — memory state at time of BSOD

### Linux Memory Acquisition

- **LiME** (Linux Memory Extractor) for live acquisition
- Swap partition/file is the Linux equivalent of pagefile

---

## Disk Acquisition

### Write-Blocking (Non-Negotiable)

**Critical rule: never modify original evidence during acquisition.**

- **Hardware write-blockers** (e.g., Tableau)
  - OS-independent, physically prevent writes
  - Preferred for legal proceedings
- **Software write-blockers**
  - OS-level, less reliable
  - More accessible but riskier

### Powering Off

When removing a disk, **pull the power cable** — don't do a clean shutdown. A clean shutdown modifies timestamps and overwrites files. Pulling power preserves the state.

### Full Disk Imaging Workflow

**FTK Imager:**
1. `File → Create Disk Image`
2. Source: `Physical Drive`
3. Fill evidence metadata (case #, examiner, notes)
4. Set output format and location
5. Verify hashes after imaging

**Linux:**
```bash
# Bit-by-bit copy with progress
dd if=/dev/sda of=/mnt/evidence/sda.dd bs=4M conv=noerror,sync status=progress

# Hash the image during copy (tee branches the data stream)
dd if=/dev/sda | tee /mnt/evidence/sda.dd | sha256sum
```

Forensic tools like EnCase and FTK add metadata and chain of custody info automatically — prefer those when acquiring for legal use.

### Image Formats

| Format | Description |
|--------|-------------|
| **Raw (.dd/.img)** | Bit-for-bit copy, no metadata |
| **E01 (EnCase)** | Compressed, with metadata and chain of custody |
| **AFF4** | Advanced Forensics Format, modern |
| **VHD/VMDK** | Virtual machine formats |

---

## Triage Imaging

Full disk imaging takes hours. Multi-TB drives take days. When you're under time pressure, collect only the high-value artifacts.

### Key Windows Artifacts to Collect

- **Event logs** — `%WinDir%\System32\winevt\Logs`
- **Registry hives** — SAM, SYSTEM, SOFTWARE, DEFAULT, NTUSER.DAT, USRCLASS.DAT, Amcache.hve
- **Memory artifacts** — pagefile.sys, hiberfil.sys, CrashDumps
- **User profiles** — `C:\Users\<username>`
- **File system artifacts** — `$MFT`, `$UsnJrnl`
- **Prefetch** — evidence of program execution
- **Browser data** — history, cache, cookies
- **Recycle Bin**

### KAPE (Kroll Artifact Parser and Extractor)

The go-to tool for triage collection:

- GUI and CLI versions
- Supports targeted artifact collection
- Deployable at scale via PowerShell
- Has pre-built "Targets" (what to collect) and "Modules" (how to process)

**Typical KAPE workflow:**
```
kape.exe --tsource C: --target KapeTriage --tdest D:\evidence\
```

---

## Mounting Forensic Images

After acquisition, you need to analyze the image without modifying it.

- **Arsenal Image Mounter** — supports raw, E01, AFF4, VHD, VMDK. Has "Write temporary" mode for safe analysis.
- **FTK Imager** — can also mount and browse images
- Note: host OS must support the image's filesystem (ext4 images need extra utilities on Windows)

---

## Evidence Integrity

### Hashing

Generate hashes **before and after** any handling to confirm no changes.

| Algorithm | Security Level | Windows | Linux |
|-----------|---------------|---------|-------|
| MD5 | Low (collision risk) | `Get-FileHash -Algorithm MD5 <file>` | `md5sum <file>` |
| SHA1 | Medium | `Get-FileHash -Algorithm SHA1 <file>` | `sha1sum <file>` |
| SHA256 | High (preferred) | `Get-FileHash <file>` | `sha256sum <file>` |

**Best practice:** calculate at least two different hashes for critical evidence. If one has a collision, the other catches it.

### Chain of Custody

Log every step:

- **What** — the evidence item
- **When** — date and time
- **Where** — physical or logical location
- **Who** — the person handling it

Record all transfers, acquisitions, examiner details, storage procedures. Use tamper-proof bags, labels, and photographs. Keep evidence locked; only authorized personnel access it.

### ACPO Principles

The four UK Association of Chief Police Officers principles that govern digital evidence handling:

1. **Do not change data** on a digital device that could be evidence
2. **Access by competent individuals only** — and they must explain their actions
3. **Maintain a reproducible audit trail** of all procedures
4. **Lead investigator ensures** all guidelines are followed

These exist because forensic evidence has to survive court challenges.

---

## Equipment Checklist

A properly equipped forensic kit includes:

- **Forensic workstation** (CAINE, DEFT, or custom)
- **Hardware write-blockers** — including specialized ones for phones, IoT
- **Blank hard drives** — at least the size of the original
- **Electrostatic evidence bags** and tamper-proof stickers
- **Grounding bracelets** (ESD protection)
- **Faraday bags/boxes** (signal blocking for mobile devices)
- **Labels and camera** for documentation
- **Dedicated flash drives** with forensic tools (EnCase, FTK, CSILinux)

---

## Sub-Domains of Digital Forensics

Digital forensics breaks down into several specializations:

| Sub-Domain | Focus |
|-----------|-------|
| **Memory Forensics** | Analysis of RAM dumps for processes, connections, malware, persistence |
| **Disk Forensics** | Windows/Linux artifacts, registry, event logs, file system |
| **Network Forensics** | Packet captures, flow data, protocol analysis |
| **Mobile Forensics** | Phones, tablets, IoT devices |
| **Cloud Forensics** | AWS/Azure/GCP logs, cloud storage, containers |

Each has its own tools and methodologies — but they all share the fundamentals above.

---

## Key Tools at a Glance

| Tool | Purpose |
|------|---------|
| **Volatility (2 & 3)** | Memory dump analysis framework |
| **Autopsy** | Disk image analysis and artifact extraction |
| **FTK Imager** | Memory capture and disk imaging |
| **KAPE** | Triage artifact collection |
| **Registry Explorer** | Windows registry analysis |
| **Timeline Explorer** | CSV-based timeline analysis |
| **Arsenal Image Mounter** | Mount forensic images safely |

---

## Key Takeaways

- Digital forensics = **Identification → Preservation → Collection → Analysis → Reporting**
- **Order of Volatility** — memory first, disk last
- **Pull power, don't clean shutdown** — timestamps matter
- Always use **write-blockers** during acquisition
- **Hash before and after** — prove evidence integrity
- **Chain of custody** is everything — document who touched what, when
- **Triage imaging** (via KAPE) when full imaging isn't practical
- **Two hashes are better than one** — MD5 + SHA256 minimum
- ACPO principles exist because evidence has to survive court
- Every sub-domain shares the same fundamentals
