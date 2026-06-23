---
title: "Malware Analysis Fundamentals"
datePublished: 2026-06-23T09:00:00.000Z
cuid: cmqqeyyjs000024ca69mbg1rs
slug: malware-analysis-fundamentals
cover: https://raw.githubusercontent.com/Jung0310-bit/woogi-blog-assets/main/thumbnails/malware-analysis-fundamentals.png
tags: malware, cybersecurity, blue-team, yara

---

When a hash hits VirusTotal with one detection out of seventy, that's not enough to call it malicious. When it hits zero, that's also not enough to call it clean. **Malware analysis** is the work that fills the gap. This post covers the three approaches (static, dynamic, memory) and the practical workflow that ties them together.

---

## Why Malware Analysis Matters

Automated defenses miss things. When a SOC pulls a suspicious binary from an endpoint or email gateway, an analyst has to determine:

- Is it actually malicious?
- What does it do (host changes, network calls, data theft)?
- How do you detect it on other systems in the environment?
- How do you remediate where it landed?

The output of analysis feeds detection rules, IR actions, and threat intel sharing. It's a core SOC function, sitting at the boundary between detection and response.

---

## Three Analysis Approaches

| Approach | When | Strength | Limit |
|---|---|---|---|
| **Static** | Always start here | Safe (no execution), fast on simple samples | Packed/obfuscated samples reveal little |
| **Dynamic** | Static is inconclusive | Reveals real behavior | Requires sandbox; sample may detect VM and lie dormant |
| **Memory** | Live system or post-execution | Catches fileless and injected malware | Requires RAM acquisition, advanced tooling |

Most real investigations use all three.

---

## Static Analysis

Examine the sample without running it.

### Hash Identification

```
sha256sum sample.exe
```

Submit to VirusTotal, MalwareBazaar, or your internal threat intel platform. A known-bad hash answers the question fast. A clean hash doesn't prove much (could be a fresh sample), but it changes the priority.

### String Extraction

```
strings -n 6 sample.exe | less
strings -e l sample.exe          # UTF-16 strings (Windows binaries)
```

Look for:

- URLs and IP addresses (potential C2)
- Registry paths (persistence mechanisms)
- File paths (drop locations, target files)
- Commands (`powershell -enc`, `cmd /c`, `wmic`)
- Bitcoin wallets, cryptocurrency strings
- Error messages or debug strings (sometimes name the framework or family)

### PE Structure Analysis

For Windows binaries, the Portable Executable (PE) header reveals capabilities without running code.

Using Python's `pefile` module or PEStudio:

- **Imports** tell you what APIs the malware uses (`CreateRemoteThread` = injection, `WSAStartup` = networking, `RegSetValueEx` = registry persistence)
- **Sections** with weird names (`.cba`, `.text1`) or high entropy suggest packing
- **Resources** can hide secondary payloads
- **Compile time** sometimes survives obfuscation; useful for attribution timelines

### YARA Rule Matching

[YARA](https://woogi.me/) rules define string and binary patterns to identify malware families.

```
rule SuspiciousPowerShell {
    strings:
        $a = "FromBase64String"
        $b = "Invoke-Expression"
        $c = "DownloadString"
    condition:
        2 of them
}
```

Tools that automate this:

- **LOKI / THOR** — IOC scanners with built-in YARA rules
- **yarGen** — generates rules by finding strings unique to malware
- **Valhalla** — online feed of curated rules, searchable by ATT&CK technique

---

## Dynamic Analysis

Run the sample in a controlled environment, observe what happens.

### Sandbox Execution

**Cuckoo Sandbox** is the open-source standard. Run a sample, get a report covering:

- Process creation and tree
- File system changes (created, modified, deleted)
- Registry modifications
- Network connections (DNS queries, HTTP, raw TCP)
- API call traces

Cuckoo can also auto-generate YARA rules from the observed behaviors.

Commercial alternatives: ANY.RUN, Joe Sandbox, Hybrid Analysis. Free tiers exist; useful for one-off triage.

### Network Monitoring

The sample's network activity is often the most revealing:

- **C2 callbacks** — beaconing pattern, destination, protocol
- **DNS queries** — resolution to attacker domains, DGA patterns
- **HTTP requests** — user-agent, URI patterns, exfil
- **TLS** — certificate details (often self-signed for C2)

Capture full PCAP during sandbox execution; analyze with [Wireshark](https://woogi.me/wireshark-traffic-analysis-for-ir).

### Behavioral Indicators

Map observed behaviors to the **Pyramid of Pain** (covered in [Kill Chain, Diamond Model, Pyramid of Pain](https://woogi.me/kill-chain-diamond-model-pyramid-of-pain-three-frameworks-every-blue-teamer-should-know)):

- **Hash** — trivial to change
- **IP / domain** — easy to rotate
- **Network artifact** (user-agent, beacon interval) — annoying to change
- **Tool** (Cobalt Strike, Mimikatz) — challenging
- **TTP** (DLL search-order hijacking, process injection) — tough

Detection that anchors on TTPs survives sample mutation. Detection that anchors on hashes does not.

---

## Memory Analysis

For malware that never touches disk (fileless attacks, code injection), memory is the only place evidence lives. See [Memory Forensics with Volatility](https://woogi.me/memory-forensics-with-volatility-finding-what-attackers-hide-in-ram) for the full toolchain.

### Volatility Plugins for Malware

| Plugin | Use |
|---|---|
| `pslist` / `pstree` / `psscan` | Running and hidden processes |
| `malfind` | Detect injected code (`PAGE_EXECUTE_READWRITE` regions with MZ headers in legitimate processes) |
| `ssdt` | Hooked kernel functions (rootkit indicator) |
| `modscan` | Hidden kernel modules |
| `netscan` | Active connections with process attribution |
| `cmdline` | Process command-line arguments |

### What to Look For

- **Singleton violations** — multiple `lsass.exe` or `svchost.exe` instances often mean impersonation
- **Unsigned modules** loaded into trusted processes
- **Network connections** from processes that shouldn't be making them (calculator phoning home, etc.)
- **Suspicious parent-child relationships** — Office spawning PowerShell, services spawning cmd.exe

---

## Practical Workflow

Standard triage flow:

1. **Triage** — hash the sample, check VT/MalwareBazaar/internal feeds. If known, move to detection rule deployment fast.
2. **Static** — strings, PE inspection, YARA matching. Often answers "is this packed?" and "is this a known family?".
3. **Dynamic** — Cuckoo run, observe behavior, capture network. Don't run on real systems.
4. **Memory** — if you have a live system or memory dump from the affected host, run Volatility. Especially important if static was inconclusive (packed sample) or dynamic failed (sample detected the VM).
5. **Document** — IOCs (hashes, IPs, domains, file paths, registry keys), MITRE ATT&CK mapping, behavioral summary, recommended detection rules.
6. **Share** — internal threat intel platform, ISAC if you have one, MalwareBazaar for community defense.

The output is a self-contained report someone else can act on without re-doing the analysis.

---

## Static Analysis: A Sample Walk-Through

A typical first-pass static analysis on an unknown Windows binary `suspicious.exe`.

### Step 1: Hash and Reputation

```bash
sha256sum suspicious.exe
# 3a7bd3e2360a6e ...

# Submit to VirusTotal
curl -X POST "https://www.virustotal.com/api/v3/files" \
  -H "x-apikey: <KEY>" \
  -F "file=@suspicious.exe"
```

Result: 3 / 72 detections, mostly heuristic. Inconclusive — proceed with deeper analysis.

### Step 2: Strings

```bash
strings -n 6 suspicious.exe | head -50
```

Notable findings:

```
GetProcAddress
LoadLibraryA
WriteProcessMemory
CreateRemoteThread
VirtualAllocEx
http://185.x.x.x/checkin
mozilla/5.0
\Software\Microsoft\Windows\CurrentVersion\Run
```

The Windows API imports suggest **process injection** capability (`WriteProcessMemory`, `CreateRemoteThread`, `VirtualAllocEx`). The HTTP URL is a likely C2 endpoint. The registry path is a common autorun persistence mechanism.

Static signal: this is malicious. Strong probability of injection-based malware with C2 callbacks and registry persistence.

### Step 3: PE Inspection

```python
import pefile

pe = pefile.PE("suspicious.exe")
print(f"Compile time: {pe.FILE_HEADER.TimeDateStamp}")
print(f"Sections:")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode()
    entropy = s.get_entropy()
    print(f"  {name}  entropy={entropy:.2f}  rawsize={s.SizeOfRawData}")
```

Output:

```
Compile time: 1577836800 (2020-01-01)
Sections:
  .text  entropy=6.45  rawsize=12288
  .rdata entropy=4.23  rawsize=4096
  .data  entropy=2.14  rawsize=2048
  .rsrc  entropy=7.95  rawsize=49152
```

Note the suspiciously high entropy on `.rsrc` (7.95 — close to 8.0 = pure random). High entropy in resources usually means an embedded encrypted or compressed payload. Combined with the strings, this is likely a stage-1 loader carrying a stage-2 encrypted in resources.

### Step 4: YARA Match

```bash
yara -r ~/yara-rules/ suspicious.exe
```

Matches:

```
APT_Generic_Loader_2024 (matched: $api_combo, $reg_persist)
Suspected_Cobalt_Strike_Beacon (matched: $beacon_config_block)
```

Now we have a likely family: Cobalt Strike loader. Time to move to dynamic analysis to confirm the network behavior and extract the C2 config.

That's static, end-to-end. ~15 minutes of work. Often this is enough to write a high-confidence detection rule and brief IR.

---

## Reading a Cuckoo Report

Dynamic analysis output from Cuckoo is dense. The high-value sections:

### Process Tree

```
suspicious.exe (PID 4321)
├── cmd.exe (PID 4322)
│   └── powershell.exe (PID 4323) -EncodedCommand <base64>
├── rundll32.exe (PID 4324) <weird DLL>
└── (injected into) explorer.exe (PID 1234)
```

Look for:

- Unusual children: rundll32 spawned from a non-Microsoft binary, powershell with encoded commands, schtasks creating persistence
- Process injection markers: `(injected into)` notations from Cuckoo's hooks

### Network Activity

```
DNS:
  185-220-101-x.tor-relay.example → 185.220.101.x  (anomalous)
HTTP:
  POST http://185.220.101.x/checkin (User-Agent: Mozilla/5.0 ...)
  Body length: 142 bytes (encrypted/compressed)
```

Beacon-like: short, periodic, to suspicious destination. Capture the C2 URL, beacon interval, user-agent for detection rules.

### File System Changes

```
Created: C:\Users\Public\update.exe  (copy of self)
Created: C:\ProgramData\config.bin  (encrypted)
Modified: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService
```

Persistence via Run key. Drop location in `Public` (no user context needed).

### Mapping to ATT&CK

Tag the behaviors:

- T1055 (Process Injection) — confirmed by Cuckoo hook
- T1547.001 (Registry Run Keys) — explicit registry write
- T1071.001 (Application Layer Protocol: Web) — HTTP C2

Each tag becomes a detection rule. ATT&CK mapping is the deliverable that turns analysis into reusable defensive knowledge.

---

## Tradecraft Notes

A few practical lessons:

- **Never analyze on a live system.** Always use a dedicated VM, ideally air-gapped or behind a transparent proxy.
- **Take snapshots.** Sandbox VMs should revert between samples. Cross-contamination is real.
- **Time matters.** Some malware is time-bombed or geofenced. Cuckoo lets you set a fake date and locale.
- **Read the strings before you run anything.** A 5-second `strings` pass often saves a 30-minute Cuckoo run.
- **Trust artifacts more than detections.** Antivirus tells you it found "TR/AD.GenericKD.12345." That's a label, not a description. Behaviors and IOCs are the truth.

---

## Tools Worth Owning

| Tool | Use |
|---|---|
| **PEStudio** | Static PE analysis with built-in suspicious-trait flagging |
| **Strings / FLOSS** | String extraction (FLOSS handles obfuscated strings) |
| **YARA + LOKI** | Pattern matching at scale |
| **Cuckoo Sandbox** | Open-source dynamic analysis |
| **Volatility** | Memory analysis, the standard reference |
| **Wireshark** | Network traffic from sandbox runs |
| **CyberChef** | Decoding base64, hex, XOR, and other transformations |

---

## Closing

Malware analysis is the deepest of the blue team disciplines, in the sense that it goes all the way down to assembly when needed. But 80% of practical SOC work happens at the levels covered above (hash + strings + PE + dynamic + memory), without touching a disassembler.

The series continues from here with deeper dives into specific tools, sample walkthroughs, and detection engineering patterns.
