---
title: "Memory Forensics with Volatility: Finding What Attackers Hide in RAM"
datePublished: 2026-04-30T09:00:00.000Z
cuid: cmol976rv000021dc4dc0ek9w
slug: memory-forensics-with-volatility-finding-what-attackers-hide-in-ram
tags: cybersecurity, blue-team, volatility, dfir, memory-forensics

---

# Memory Forensics with Volatility: Finding What Attackers Hide in RAM

Disk forensics misses the stuff that matters most. Fileless malware, running processes, C2 connections, encryption keys, hidden rootkits — these live in RAM and disappear the moment the system powers off. This post covers memory forensics with Volatility, the de facto tool for analyzing memory dumps.

---

## Why Memory Forensics Matters

Modern attackers know disk forensics exists. They adapt.

- **Fileless malware** — runs exclusively in memory, no executable on disk
- **Volatile data** — processes, network connections, credentials, encryption keys — all lost on shutdown
- **Rootkits** — hide from Task Manager, Process Explorer, even the OS API
- **Speed** — memory dumps are smaller than disk images; faster to acquire and analyze

If you're only doing disk forensics, you're missing half the picture.

---

## What You Can Find in Memory

| Artifact | Forensic Value |
|----------|----------------|
| **Processes & Threads** | Active/hidden programs, parent-child relationships, injection |
| **Network Connections** | C2 communication, lateral movement, exfiltration |
| **Loaded Modules (DLLs)** | Malicious code injection, rootkit drivers |
| **Registry Keys** | Persistence mechanisms, system config |
| **File System (MFT)** | File creation/deletion/modification timeline |
| **Malware Binaries** | Extractable for reverse engineering |
| **Command History** | What the attacker actually typed |
| **Clipboard & Screenshots** | What was visible on the screen |
| **Credentials & Keys** | Plaintext passwords, SSL keys |

---

## Volatility: The Tool

**Volatility** is the primary open-source framework for memory forensics.

- Developer: The Volatility Foundation
- Open-source, Python
- Two versions: Vol2 (Python 2) and Vol3 (Python 3)

### Volatility 2 vs Volatility 3

| Aspect | Volatility 2 | Volatility 3 |
|--------|-------------|-------------|
| **Python** | Python 2 | Python 3 |
| **Profile** | Required (`--profile=Win7SP1x64`) | Auto-detected via symbol tables |
| **Plugin naming** | Generic (`pslist`) | OS-specific (`windows.pslist`) |
| **Maturity** | Full plugin library | Still porting plugins |
| **Command** | `vol.py -f dump.mem --profile=X plugin` | `python3 vol.py -f dump.mem windows.plugin` |

Vol2 has more plugins but is dying. Vol3 is the future. Most blue teamers still use Vol2 because the plugins they need haven't been ported yet.

### Volatility Workbench (GUI)

Standalone Windows GUI for Vol3. No Python install needed. Useful when you want to avoid command-line friction.

---

## Process Analysis Workflow

The first thing you check in any memory dump is the process list.

### 1. List Processes

```bash
# Volatility 2
vol.py -f dump.mem --profile=Win7SP1x64 pslist

# Volatility 3
python3 vol.py -f dump.mem windows.pslist
```

`pslist` enumerates processes from `PsActiveProcessHead`. Key fields: PID, PPID, start/exit time, session, Wow64 flag.

### 2. View Process Tree

```bash
vol.py -f dump.mem --profile=Win7SP1x64 pstree
```

`pstree` shows the parent-child relationships. This is where you catch anomalies:

- `cmd.exe` spawned by `winword.exe` → someone opened a malicious doc
- `powershell.exe` spawned by `excel.exe` → macro execution
- `lsass.exe` with unexpected child processes → credential dumping

### 3. Detect Hidden Processes

Attackers hide processes by unlinking them from `PsActiveProcessHead`. Standard tools can't see them. Volatility can.

```bash
# Scan raw memory for process structures
vol.py -f dump.mem --profile=Win7SP1x64 psscan

# Cross-reference 7 different enumeration methods
vol.py -f dump.mem --profile=Win7SP1x64 psxview
```

`psxview` is the killer. It shows a process across seven different views: `pslist`, `psscan`, `thrdproc`, `pspcid`, `csrss`, `session`, `deskthrd`. A process that shows `False` in pslist but `True` in psscan is a strong indicator of rootkit activity.

### 4. Identify Anomalies

**Singleton violations** — core Windows processes should only have one instance:

- `lsass.exe` — one instance only
- `services.exe` — one instance only
- `wininit.exe` — one instance only
- `csrss.exe` — one per session

Duplicates suggest malware impersonation.

**Suspicious paths** — legitimate Windows processes run from specific locations:

- `lsass.exe` must be in `C:\Windows\System32\`
- Not `C:\Users\Public\`, not `C:\Temp\`

**Code injection** — use `malfind` to detect injected code:

```bash
vol.py -f dump.mem --profile=Win7SP1x64 malfind
```

Look for:
- `PAGE_EXECUTE_READWRITE` memory regions (should be rare in normal processes)
- `MZ` headers in process memory outside the main executable (injected PE)

---

## Network Connection Analysis

The `netscan` plugin scans for pool tags (`TcpL`, `TcpE`, `UdpA`) to extract connection data.

```bash
vol.py -f dump.mem --profile=Win7SP1x64 netscan
```

You get:
- Source/destination IP and port
- Protocol (TCP/UDP) and connection state
- Associated process PID and name
- Connection creation time

**What to look for:**
- Connections to unknown external IPs
- Beaconing patterns (repeated connections to same host)
- Processes making connections they shouldn't (notepad.exe opening TCP to internet)
- Listening ports on unusual numbers

This is how you trace **C2 servers** and **lateral movement**.

---

## Persistence Detection via Memory

Most persistence techniques leave registry traces. Even for memory-only malware, the "how does it come back after reboot" question usually has a registry answer.

### Key Registry Locations

Use `printkey` to inspect specific keys:

```bash
vol.py -f dump.mem --profile=Win7SP1x64 printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Common persistence keys to check:**

- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — Run keys
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` — RunOnce keys
- `SYSTEM\CurrentControlSet\Services` — Service persistence
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` — Scheduled tasks
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` — `Userinit`, `Shell` hijacking
- `AppInit_DLLs` — loads malicious DLLs into every process linking User32.dll

Compare against a known-clean baseline to spot malicious additions.

---

## File Artifacts in Memory

The NTFS `$MFT` is cached in memory. Volatility can parse it to get file activity without examining the disk.

```bash
# Scan for file objects
vol.py -f dump.mem --profile=Win7SP1x64 filescan

# Extract files from memory
vol.py -f dump.mem --profile=Win7SP1x64 dumpfiles -n --dump-dir=./extracted/

# Parse MFT entries
vol.py -f dump.mem --profile=Win7SP1x64 mftparser
```

This gives you file names, timestamps, paths, deletion status — without touching the disk.

---

## Memory Sources Beyond Live RAM

Even without a memory dump, you might find memory remnants in these files:

| Source | Description |
|--------|-------------|
| **pagefile.sys** | Paged-out RAM data; may contain forensic remnants |
| **hiberfil.sys** | Full RAM snapshot from hibernation; great for dead acquisition |
| **MEMORY.DMP** | Created during BSOD; partial memory content |

Volatility can analyze `hiberfil.sys` directly — no need to convert it first.

---

## Essential Volatility Plugin Reference

### System Information
```
imageinfo              # Identify OS profile (Vol2)
kdbgscan               # Scan for KDBG signatures
```

### Process Analysis
```
pslist                 # List processes
pstree                 # Process tree
psscan                 # Scan for hidden processes
psxview                # Cross-view detection
cmdline -p PID         # Command-line args
procdump -p PID        # Dump process executable
```

### Network
```
netscan                # Active/closed connections (Win7+)
connections            # Active connections (WinXP/2003)
connscan               # Connection scan (legacy)
```

### Malware Detection
```
malfind                # Detect injected code
ssdt                   # SSDT hooks (rootkit detection)
modules                # Loaded kernel modules
modscan                # Scan for hidden modules
moddump                # Dump kernel driver to disk
```

### Persistence & Registry
```
printkey -K "path"     # Print registry key values
hivelist               # List registry hives
```

### Files
```
filescan               # Scan for file objects
dumpfiles -n --dump-dir=./  # Extract files
mftparser              # Parse MFT entries
```

### Timeline & History
```
timeliner              # Build chronological timeline
iehistory              # IE browsing history
cmdscan                # Command history (CMD)
consoles               # Console contents
```

---

## Standard Investigation Workflow

Here's the order I typically run Volatility plugins:

```
1. imageinfo              # Identify profile
2. pslist                 # Baseline processes
3. pstree                 # Parent-child anomalies
4. psscan                 # Hidden processes
5. psxview                # Cross-view detection
6. netscan                # Network connections
7. cmdline                # Suspicious command-line args
8. malfind                # Code injection
9. printkey               # Persistence keys
10. filescan + dumpfiles  # Suspicious files
11. procdump              # Extract malicious process
12. strings on dumps      # Find IOCs (URLs, IPs, keys)
```

Anomalies flag the targets for deeper investigation. Dump and analyze.

---

## What to Do With Suspicious Findings

When you find something suspicious in memory:

1. **Dump the process** → `procdump -p <PID> --dump-dir=./`
2. **Extract strings** → `strings -a <dumped_file>` (look for URLs, IPs, credentials)
3. **Hash it** → SHA256
4. **Check VirusTotal** → see if it's known
5. **Run YARA rules** → check for malware families
6. **Reverse engineer** if necessary (IDA, Ghidra, x64dbg)

---

## Key Takeaways

- **Memory forensics catches what disk forensics misses** — fileless malware, live processes, C2 connections
- **Always acquire memory first** — it's the most volatile
- **pstree first** — process tree anomalies give you the fastest wins
- **psxview** is the best hidden process detection — cross-references 7 methods
- **netscan** to find C2 — look for connections to unknown IPs
- **malfind** catches injected code — look for `PAGE_EXECUTE_READWRITE` + MZ
- **printkey** to check persistence — compare against clean baseline
- **Singleton violations** (duplicate lsass.exe, etc.) = likely compromise
- Vol2 has more plugins, Vol3 is the future — use what fits your case
- Even without a dump, check `hiberfil.sys` and `pagefile.sys`
