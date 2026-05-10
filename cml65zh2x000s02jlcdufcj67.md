---
title: "[ProjectX] E101: Vulnerable Environment Setup & Wazuh Monitoring"
datePublished: Tue Feb 03 2026 05:34:49 GMT+0000 (Coordinated Universal Time)
cuid: cml65zh2x000s02jlcdufcj67
slug: projectx-e101-building-a-secure-homelab-environment
cover: https://raw.githubusercontent.com/Jung0310-bit/woogi-blog-assets/main/thumbnails/projectx-s01e01-magazine.png

---

*This homelab project is included in the ProjectX course by Grant Collins.*

This is **S01 E01** of ProjectX, my homelab series for testing blue team tooling end to end. The goal of this episode: build a small Active Directory environment with deliberate weaknesses, deploy Wazuh on the agent-monitored hosts, and confirm detection coverage across five attacker scenarios. The thesis: **what you don't monitor is what attackers exploit.**

## What You'll Build

| Component | Role |
|---|---|
| `project-x-dc` | Windows Server domain controller. RDP enabled, sensitive file in place |
| `project-x-win-client` | Windows 10 workstation. WinRM enabled, insecure guest logons |
| `project-x-corp-svr` | Linux server, MailHog SMTP. **No Wazuh agent** (the blind spot) |
| `project-x-linux-client` | Linux client with Wazuh agent + email poller |
| `attacker` | Kali for SSH brute-force, RDP, file exfiltration via SCP |

## Detection Coverage Validated

| # | Scenario | MITRE | Wazuh Rule | Source |
|---|---|---|---|---|
| 1 | SSH brute-force | T1110.001 | 5710 family | sshd auth failure |
| 2 | WinRM activation | T1021.006 | 60106 | Event 4624 (Kerberos) |
| 3 | RDP login | T1021.001 | 92653 | Event 4624 (User32) |
| 4 | Sensitive file modification | T1565, T1083 | 100002 (custom) | syscheck FIM |
| 5 | SMB guest logon | T1078 | TBD | network logs |

---

## Network Topology & Attack Scenario

![Lab network topology showing attacker, AD domain controller, Linux client, Linux corp-svr, and Windows workstation](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/5a00b679-5450-406a-b885-cfaecc484457.png align="center")

## VM System

In the course, virtual machines (VMs) are used, but I prefer using **Proxmox VE** to save resources.

![Proxmox VE web UI showing the lab VMs](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/a0565cb1-5139-468e-ac35-beabae8dde2d.png align="center")

## Overall Purpose of the Homelab

- **Comparison of detection integration**: `corp-svr` (without EDR) vs. `linux-client` (with Wazuh agent)
- The blind-spot story is the lesson. Anything happening on the unmonitored host is invisible to a SOC.

## Configure a Vulnerability

### Open SSH `[T1110.001 Brute Force: Password Guessing]`

- `PasswordAuthentication yes`: allows users to log in with a standard password rather than an SSH key.
    
    - **Why insecure**: vulnerable to brute-force attacks.
        
        ![sshd_config with PasswordAuthentication yes](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/b2fd7b5d-2953-4b06-b8f1-76a992b67ac5.png align="center")
        
- `PermitRootLogin yes`: allows the `root` account to log in directly via SSH.
    
    - **Why insecure**: attackers only need to guess one password to gain full control of the machine.
        
        ![sshd_config with PermitRootLogin yes](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/fc4c0393-2641-4c01-b680-0e56bed94247.png align="center")
        
- **Weak password**: set the root password to `november` using `sudo passwd root`.
    

#### Create Detection Alert for SSH in Wazuh

- To create a detection alert, use an SSH authentication failure sample. From the screenshot, you can extract the **decoder name** and **rule groups**.
    
    ![Wazuh discover view showing sshd auth failure sample event](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/3f3cf2ed-9bb6-41d3-92ed-a78d95d4dafd.png align="center")
    
- Using the sample, build the detection query.
    

![Wazuh discover query for SSH auth failures](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/ddf68e36-bb8a-47f5-bffb-b033f24fcfbe.png align="center")

![Wazuh alert triggered on SSH brute-force attempt](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/34d01192-71ed-4fec-91e4-9c4a97488fa3.png align="center")

### Enable WinRM on `win-client` `[T1021.006 Remote Services: WinRM]`

- **What is WinRM**: allows administrators to remotely manage Windows systems, similar to how SSH works for Linux.
    
- Enable WinRM via PowerShell:
    
    ```powershell
    powershell -ep bypass Enable-PSRemoting -force
    winrm quickconfig -transport:https
    Set-Item wsman:\localhost\client\trustedhosts *
    net localgroup "Remote Management Users" /add administrator
    Restart-Service WinRM
    ```
    

#### How to Detect WinRM Activation

- Event ID `4624` with a `logonProcessName` of `Kerberos`
- Wazuh Rule ID: `60106`
- Description: `Windows Logon Success`

![Wazuh discover showing Event 4624 Kerberos logon](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/3bc199c3-36c3-48f5-a42b-eef1bd15d999.png align="center")

- From the sample, create a data filter for the alert.
    
    ![Wazuh data filter configuration for WinRM detection](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/fa650fc0-9024-48d5-8e78-5cae613c5670.png align="center")
    

### Configure SMTP Email Inbox Connection

`[project-x-corp-svr]` → `[project-x-linux-client]`

![MailHog SMTP server running in Docker on corp-svr](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/9bf44539-8e13-47d8-b42a-ed3f4bf0aa33.png align="center")

![MailHog web UI showing intercepted emails](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/cf9f23b2-7e74-412d-bdec-ba0357654755.png align="center")

- Docker is used to host and orchestrate **MailHog**, which acts as the **SMTP server** for the lab environment.
    
- The `email_poller.sh` script runs on the **client machine** (`[project-x-linux-client]`) to interact with the MailHog server.
    
    ![email_poller.sh script polling MailHog from linux-client](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/2360c336-8d3e-4a67-ad1e-656a3053fb56.png align="center")
    
- `[project-x-corp-svr]` is intentionally unmanaged to demonstrate the security 'blind spot' that occurs when monitoring tools are absent. **This is the central lesson of the lab.**
    

### Enable RDP on `[project-x-dc]` `[T1021.001 Remote Services: RDP]`

![Windows Server enabling RDP via System Properties](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/3c2c1bfd-0423-4573-a7f3-73acda5a2320.png align="center")

#### How to Detect RDP Connection in Wazuh

- Default Wazuh rule for RDP: `92653`
    
    ![Wazuh rule 92653 detail in dashboard](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/455b1eb8-53b2-4506-b5f7-6cedbdd1463b.png align="center")
    
- Or query: `data.win.system.eventID: 4624 AND data.win.eventdata.logonProcessName: User32`
    
    - Successful authentication (Windows Security Event ID): `4624`
    - Unsuccessful authentication (Windows Security Event ID): `4625`
    - The value `User32` in the `logonProcessName` field indicates the use of the `User32.dll` library, which handles RDP logins.

### Setup "Sensitive File" in `[project-x-dc]` `[T1565 Data Manipulation, T1083 File Discovery]`

![ProductionFiles folder containing secrets.txt under Administrator's Documents](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/98ce7158-c167-43d8-88ac-23f95a4268ad.png align="center")

Create a `secrets.txt` file under `Administrator > Documents > ProductionFiles`.

#### Detect File Modifications in Wazuh

![Wazuh agent configuration overview](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/7234c536-d8de-4539-8375-9df1237695cf.png align="center")

- Under `Server management > Endpoint Groups > Windows > agent.conf`
- Add the syscheck block to enable file monitoring:

```xml
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    C:\Users\Administrator\Documents\ProductionFiles
  </directories>
  <frequency>60</frequency>
</syscheck>
```

![agent.conf with syscheck FIM directives](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/7da70594-1388-4749-b275-642df56ae5c0.png align="center")

- `check_all="yes"`: check multiple file properties including the file's **hash** (MD5, SHA1, SHA256), permissions, owner, group, and size.
- `report_changes="yes"`: when a text file is modified, Wazuh sends an alert with the diff.

![File Integrity Monitoring inventory tab in Wazuh](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/8920d3a8-6bb9-457e-9e2b-87f9ae99acad.png align="center")

Under `File Integration Monitoring > Inventory`, you can see all monitored files including `secrets.txt`.

#### Create Detection Alert for File Modification

Under the `rules` tab, find `local_rules.xml` and add this rule:

```xml
<group name="syscheck">
  <rule id="100002" level="10">
    <field name="file">secrets.txt</field>
    <match>modified</match>
    <description>File integrity monitoring alert: modification detected on sensitive file</description>
  </rule>
</group>
```

![local_rules.xml with custom rule 100002](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/565f4071-3b46-468d-bd85-bd8085170050.png align="center")

- Save and restart the Wazuh manager.
- Under `Alerting > Monitors > Create Monitor`, configure:

![Wazuh monitor configuration for file modification](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/4d601830-ef07-4a0c-a0a6-62c64a08a081.png align="center")

- `full_log contains secrets.txt`: ensures we look at events specifically related to `secrets.txt`.
- `syscheck.event is modified`: when a file change is detected, Wazuh categorizes the type of action that occurred.

![Trigger condition for the file modification monitor](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/1b29ac50-c23e-4768-be37-54704686d6fa.png align="center")

Configure the `Trigger Condition` so the monitor fires on every match.

### Exfiltration Setup on Attacker Machine `[T1048 Exfiltration Over Alternative Protocol]`

`scp` is the canonical Linux file copy tool over SSH. It uses the same auth as SSH, which means once an attacker has credentials (or a key), exfiltration is one command away.

![SCP destination folder on attacker box ready to receive secrets](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/400d18ca-2504-48ef-a793-1dbd1e54196a.png align="center")

- Create a destination folder on the attacker host where `secrets.txt` content will land.
- Wazuh detects this only if the **destination** is monitored. Outbound SCP from a non-agent host (`corp-svr`) is invisible at the network edge unless we add a separate firewall or log source. **The blind spot strikes again.**

### Enable Insecure Guest Logons for `[project-x-win-client]` `[T1078 Valid Accounts]`

![GPO editor showing Enable insecure guest logons set to Enabled](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/ebe64dc8-caae-435f-b174-eaeada269ec8.png align="center")

- Under `File Explorer > C:\Windows\System32 > gpedit (Run as Administrator) > Computer Configuration > Administrative Templates > Network > Lanman Workstation > "Enable insecure guest logons" > "Enabled"`.
- Effect: allows the workstation to connect to shared network resources (e.g., an SMB share) using a guest account with **zero authentication required**.

![Same setting via command-line registry edit](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/d4cd28e6-bc16-44f9-be0c-49076bdbf48f.png align="center")

- Equivalent command-line registry edit (alternative to GPO).

---

## What I Asked Myself While Building This

Pillar 2 of analyst work is asking better questions, not running more tools. Building this lab forced me to externalize the questions I'd otherwise glaze past:

- **"What am I missing?"**: when `corp-svr` got no agent on purpose, the question became: *if I were an analyst on a real SOC and this host went silent for a week, would I notice?* Probably not. The lab's whole point is to make that gap visceral.

- **"Why this rule, and not five others?"**: Wazuh ships with thousands of default rules. Picking `92653` for RDP and writing custom `100002` for FIM forced a justification: this rule fires on the actual attacker action, not on incidental noise around it.

- **"What happened before this?"**: when the SSH brute-force alert fires, the alert itself is uninteresting. What's interesting is the host's auth log 30 minutes earlier (recon? credential spraying from a different IP?). The lab teaches you to look at the alert AND the context window around it.

- **"Why now? Why this host?"**: `corp-svr` runs MailHog. Why is it the host without an agent? Because in a real org, "the SMTP test box" or "the legacy server nobody owns" is exactly the kind of host that gets skipped during agent rollout. This lab is a small version of that organizational pattern.

These are interview questions disguised as lab notes. If you can answer them about your own homelab, you can answer them about a real SOC environment.

## What This Episode Validated

- **Wazuh agent-side telemetry catches**: SSH auth failures, WinRM activation, RDP logins, FIM events on monitored hosts.
- **Custom rules + alerts work end to end**: `syscheck > local_rules.xml > Monitor > Trigger`. The chain holds.
- **The agent-LESS host (`corp-svr`) is the blind spot**. Anything happening on it goes unobserved by the SOC. Outbound SCP from this host disappears once it leaves the box. That is the lesson.
- **Compromised vs. monitored is the wrong framing**. The right framing is **monitored vs. unmonitored**. An unmonitored host doesn't care whether it's compromised because we wouldn't know either way.

## What's Next

**E02** picks up where this leaves off. We simulate the actual attack chain across these hosts, watch what the Wazuh dashboard surfaces, and identify what slips through. The blind spot becomes the entry point.
