---
title: "[ProjectX] E101: Vulnerable Environment Setup & Wazuh Monitoring"
datePublished: Tue Feb 03 2026 05:34:49 GMT+0000 (Coordinated Universal Time)
cuid: cml65zh2x000s02jlcdufcj67
slug: projectx-e101-building-a-secure-homelab-environment
cover: https://raw.githubusercontent.com/Jung0310-bit/woogi-blog-assets/main/thumbnails/projectx-s01e01.png

---

*This homelab project is included in the ProjectX course by Grant Collins.*

## Network Topolgy & Attack Scenario

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/5a00b679-5450-406a-b885-cfaecc484457.png align="center")

## VM System

In the course, virtual machines (VMs) are used, but I prefer using **Proxmox VE** to save resources.

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/a0565cb1-5139-468e-ac35-beabae8dde2d.png align="center")

## Overall Purpose of homelab project

*   Comparison of Detection Integration: `corp-svr`(without EDR) vs. `linux-client` (with Wazuh Agent)
    

## Configure a Vulnerability

### Open SSH

*   `PasswordAuthentication yes` : Allows users to log in using a standard password rather than a secure SSH key.
    
    *   **Why Insecure?**: Vulnerable to brute-force attacks.
        
        ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/b2fd7b5d-2953-4b06-b8f1-76a992b67ac5.png align="center")
        
*   `PermitRootLogin yes` : Allows the "root" account to log in directly via SSH.
    
    *   **Why Insecure?**: Attackers only need to guess one password to gain full control of the machine.
        
        ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/fc4c0393-2641-4c01-b680-0e56bed94247.png align="center")
        
*   **Weak Password**: Set the root password to `november` using `sudo passwd root` .
    

#### Create Detection Alert for ssh in Wazuh

*   To create a detection alert, use an SSH authentication failure sample.  
    \- From the screenshot, can get **decoder name**, **rule groups**.
    
    ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/3f3cf2ed-9bb6-41d3-92ed-a78d95d4dafd.png align="center")
    
*   Using the sample, create a query.
    

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/ddf68e36-bb8a-47f5-bffb-b033f24fcfbe.png align="center")

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/34d01192-71ed-4fec-91e4-9c4a97488fa3.png align="center")

### Enable WinRM on `win-client`

*   **What is WinRM?**: allows administrators to remotely manage Windows systems, similar to how SSH works for Linux.
    
*   enable WinRM codeline  
    `powershell -ep bypass Enable-PSRemoting -force winrm quickconfig -transport:https Set-Item wsman:\localhost\client\trustedhosts * net localgroup "Remote Management Users" /add administrator Restart-Service WinRM` .
    

##### **How to detect activation of WinRM**

\- Event ID `4624` with a `logonProcessName` of Kerberos  
\- Wazuh Rule ID: `60106`  
\- Description: User: `Windows Logon Success`

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/3bc199c3-36c3-48f5-a42b-eef1bd15d999.png align="center")

*   From the sample above, make data filter for alerts
    
    ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/fa650fc0-9024-48d5-8e78-5cae613c5670.png align="center")
    

### Configure SMTP Email Inbox Connection

`[project-x-corp-svr]` -> `[project-x-linux-client]`

![Run MailHog](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/9bf44539-8e13-47d8-b42a-ed3f4bf0aa33.png align="center")

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/cf9f23b2-7e74-412d-bdec-ba0357654755.png align="center")

*   Docker is used to host and orchestrate **MailHog**, which acts as the **SMTP server** for the lab environment.
    
*   The `email_poller.sh` script is run on the **client machine** (`[project-x-linux-client]`) to interact with the MailHog server.
    
    ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/2360c336-8d3e-4a67-ad1e-656a3053fb56.png align="center")
    
*   `[project-x-corp-svr]` is intentionally unmanaged to demonstrate the security 'blind spot' that occurs when monitoring tools are absent.
    

### Enable RDP on `[project-x-dc]`

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/3c2c1bfd-0423-4573-a7f3-73acda5a2320.png align="center")

#### How to detect RDP connection in Wazuh

*   Default Wazuh Rule to detect RDP: `92653`
    
    ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/455b1eb8-53b2-4506-b5f7-6cedbdd1463b.png align="center")
    
*   or query `data.win.system.eventID: 4624 AND` `data.win.eventdata.logonProcessName: User32` .
    
    *   Successful authentication of Windows Security Event ID: `4624` .
        
    *   UnSuccessful authentication of Windows Security Event ID: `4625` .
        
    *   The value `User32` in the `logonProcessName` field indicates the use of the `User32.dll` library, which handles RDP logins.
        

### Setup “Sensitive File” in `[project-x-dc]`

*   ![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/98ce7158-c167-43d8-88ac-23f95a4268ad.png align="center")
    
    make `secrets.txt` file under `Administrator > Documents > ProductionFiles` .
    

#### Detect file modifications in Wazuh

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/7234c536-d8de-4539-8375-9df1237695cf.png align="center")

*   Under `Server management > Endpoint Groups > Windows > agent.conf`
    
*   Put below codeblock to make file monitoring
    

```plaintext
<syscheck>
  <directories check_all="yes" report_changes="yes"
  realtime="yes">C:\Users\Administrator\Documents\ProductionFiles
  </directories>
  <frequency>60</frequency>
 </syscheck>
```

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/7da70594-1388-4749-b275-642df56ae5c0.png align="center")

*   `check_all="yes"` : check multiple file properties including file's **hash** (MD5, SHA1, and SHA256), permissions, owner, group, and size
    
*   `report_changes="yes"` : When a text file is modified, Wazuh will actually send the alert
    

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/8920d3a8-6bb9-457e-9e2b-87f9ae99acad.png align="center")

*   Under `File Integration Monitoring`'s `Inventory` tab, can see monitoring files inculding `secrets.txt`
    

#### Create Detection Alert for File Modification

*   Under `rules` tab, find `local_rules.xml` and adds below code
    

```plaintext
<group name="syscheck">
 <rule id="100002" level="10">
 <field name="file">secrets.txt</field>
 <match>modified</match>
 <description>File integrity monitoring alert - access to
sensitive.txt file detected</description>
 </rule>
</group>
```

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/565f4071-3b46-468d-bd85-bd8085170050.png align="center")

*   save and restart
    
*   Under `Alerting > Monitors > Create Monitor`, write configuration
    

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/4d601830-ef07-4a0c-a0a6-62c64a08a081.png align="center")

*   `full_log contains secrets.txt` : ensures looking at events specifically related to `secrets.txt` .
    
*   `syscheck.event is modified` : When a file change is detected, Wazuh categorizes the type of action that occurred.
    

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/1b29ac50-c23e-4768-be37-54704686d6fa.png align="center")

*   and also configure `Trigger Condition`
    

### Exfiltration Setup on Attacker Machine

*   `scp` : allow copy files and directories between two systems through ssh
    

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/400d18ca-2504-48ef-a793-1dbd1e54196a.png align="center")

*   create a file where to copy `secrets.txt` content
    

### Enable Insecure guest logons for \[project-x-client\]

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/ebe64dc8-caae-435f-b174-eaeada269ec8.png align="center")

*   Under `File Explorer Window > C:\Windows\System32 > gpedit(Run as Administrator) > Computer Configuration > Administrative Template > Network > Lanman Workstation > "Enable insecure guest logons" > “Enabled”` -> allows the workstation to connect to shared network resources (like an SMB share) using a guest account with **zero authentication required**.
    

![](https://cdn.hashnode.com/uploads/covers/697fe23ce91977696c393c3e/d4cd28e6-bc16-44f9-be0c-49076bdbf48f.png align="center")

*   also with command line