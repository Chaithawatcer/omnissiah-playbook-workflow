---
threat_name: Credential Dumping
technique_ids: ["T1003.001", "T1078", "T1550.002"]
severity: Critical
source_doc: Credential_Dumping_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เตรียม **Mimikatz** (บน sandbox/red team machine) เพื่อ understand attack technique และ test detection
- ติดตั้ง **Sysmon** พร้อม config ที่ enable Event ID 10 (ProcessAccess) กำหนด target process `lsass.exe`
- เปิด **Windows Credential Guard** (สำหรับ Windows 10/Server 2016+) เพื่อป้องกัน LSASS dump
- ติดตั้ง **Defender for Identity / Microsoft Sentinel** พร้อม alert rule สำหรับ LSASS access
- เตรียม **procdump.exe** (Sysinternals) สำหรับ legitimate memory dump ใน forensic process
- เตรียม script ตรวจสอบ **Protected Users Security Group** ใน AD
- มี **offline password cracking tool** (hashcat) บน air-gapped machine สำหรับ test hash strength

### Sub: team_roles
- **Incident Commander**: ประเมินขอบเขตความเสี่ยง — credential ระดับไหนถูก dump
- **Windows/AD Specialist**: reset password, disable compromised account, ตรวจสอบ Kerberos ticket
- **SOC Analyst (L2/L3)**: hunt ด้วย Sysmon Event ID 10, ตรวจสอบ lateral movement ที่ใช้ credential ที่ dump
- **Threat Intelligence Analyst**: ระบุ malware family ที่ใช้ technique นี้ (Mimikatz, SharpKatz, SafetyKatz)
- **Forensic Analyst**: collect memory dump ของ LSASS อย่างถูกต้องตาม chain of custody
- **CISO**: ประเมิน business risk จาก credential exposure และตัดสินใจ scope of password reset

### Sub: comm_plan
- แจ้ง **AD Admin** ทันทีเพื่อ reset krbtgt account password (สำคัญมากสำหรับ Pass-the-Hash/Golden Ticket)
- แจ้ง **executive team** หาก credential ของผู้บริหารถูก compromise
- ใช้ **out-of-band communication** (Signal/โทรศัพท์) เพราะ attacker อาจ intercept email
- แจ้ง **แผนก HR** หาก service account credential ของระบบ HR ถูก dump
- ประสาน **legal team** เพื่อ assess ผลกระทบและ data breach notification obligation

## Phase: detection
### Sub: log_sources
- **Sysmon Event ID 10 (ProcessAccess)**: process ใดก็ตามที่ open handle ไปยัง `lsass.exe` ด้วย `PROCESS_VM_READ`
- **Windows Security Event ID 4656**: request handle to LSASS object
- **Windows Security Event ID 4624**: Logon Type 9 (NewCredentials) บ่งบอก Pass-the-Hash
- **Windows Security Event ID 4672**: Special privilege logon (SeDebugPrivilege) ซึ่ง Mimikatz ต้องใช้
- **Windows Defender Event Log**: alert เรื่อง `Mimikatz`, `WCE`, `PWDumpX` signatures
- **Sysmon Event ID 7 (ImageLoad)**: `comsvcs.dll` loaded โดย process ที่ไม่ใช่ `dllhost.exe`
- **EDR (CrowdStrike/Sentinel One)**: alert สำหรับ LSASS memory access หรือ credential access behavior

### Sub: detection_queries
**Splunk — ตรวจ LSASS Process Access (Sysmon Event ID 10):**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT (SourceImage LIKE "%MsMpEng.exe%" OR SourceImage LIKE "%svchost.exe%" OR SourceImage LIKE "%csrss.exe%")
| table _time, ComputerName, SourceImage, SourceProcessId, GrantedAccess
| sort -_time
```

**Splunk — ตรวจ SeDebugPrivilege (Event ID 4672):**
```spl
index=windows_security EventCode=4672
| where PrivilegeList LIKE "*SeDebugPrivilege*"
| stats count by Account_Name, Workstation_Name, _time
| where count > 1
```

**Splunk — ตรวจ comsvcs.dll dump technique:**
```spl
index=sysmon EventCode=1
| where CommandLine LIKE "*comsvcs*" AND CommandLine LIKE "*MiniDump*"
| table _time, ComputerName, Image, CommandLine, User
```

**CLI — PowerShell ตรวจ process ที่ access LSASS:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object {$_.Message -match "lsass.exe" -and $_.Message -notmatch "MsMpEng"} |
  Select-Object TimeCreated, Message | Format-List
```

**CLI — ตรวจหา dump file ที่ถูกสร้าง:**
```powershell
Get-ChildItem -Path C:\ -Recurse -Include "*.dmp","lsass*","dump*" -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
  Select-Object FullName, LastWriteTime, Length
```

**Splunk — ตรวจ Pass-the-Hash (Logon Type 9 + NTLM):**
```spl
index=windows_security EventCode=4624 Logon_Type=9
| where AuthenticationPackageName="NTLM"
| stats count by Account_Name, src_ip, Workstation_Name
| where count > 3
```

### Sub: ioc_list
- **Sysmon Event ID 10**: `GrantedAccess=0x1010` หรือ `0x1410` ไปยัง `lsass.exe` จาก process ที่ไม่ใช่ system
- **Process name**: `mimikatz.exe`, `mimitray.exe`, `wce.exe`, `pwdump.exe`, `procdump.exe` (ในบริบทที่ผิดปกติ)
- **Command line**: `procdump -ma lsass.exe`, `rundll32 comsvcs.dll MiniDump <pid> lsass.dmp full`
- **File creation**: ไฟล์ `.dmp` ใน temp directory หรือ C2 staging directory
- **Registry**: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` ถูก set `UseLogonCredential=1`
- **Event ID 4673**: ใช้ `SeDebugPrivilege` จาก process ที่ไม่ใช่ debugger
- **Outbound**: lsass dump file ถูก transfer ผ่าน SMB, FTP, หรือ HTTP ออกไปยัง C2

### Sub: scope_analysis
- ระบุ **ประเภท credential ที่อาจถูก dump**: NTLM hash, Kerberos TGT, plaintext password (WDigest), DPAPI keys
- ตรวจสอบว่า **domain admin credential** ถูก dump หรือไม่ — ถ้าใช่ ถือเป็น full domain compromise
- Hunt หา **lateral movement** ที่ใช้ credential ที่ dump: Event ID 4648 (explicit credential logon), 4624 Type 3/9
- ตรวจสอบ **machine ทุก เครื่อง** ที่ compromised user เคย login เพราะ credential อาจถูก cache
- ตรวจ **krbtgt password age**: ถ้าไม่เปลี่ยนนาน อาจมี Golden Ticket attack ตามมา
- ประเมินว่า attacker ได้ **cloud credential** (Azure AD token, AWS IAM key) ที่ cached บน machine ด้วยหรือไม่

## Phase: containment
### Sub: short_term
1. **Isolate เครื่องที่ถูก compromise** จาก network ทันที: ปิด network adapter หรือ ย้ายเข้า VLAN กักกัน
2. **Reset password** ของ account ที่ถูก dump ทุก account โดยเฉพาะ privileged account
3. **Reset krbtgt account password 2 ครั้ง** (ต้องทำ 2 รอบเพื่อ invalidate Kerberos ticket ทั้งหมด):
   ```powershell
   Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (Read-Host -AsSecureString)
   ```
4. **Revoke Kerberos TGT** ทั้งหมดสำหรับ compromised account: `klist purge` บนทุกเครื่อง
5. **เปิด Protected Users Security Group** สำหรับ privileged account เพื่อบังคับ Kerberos และ block NTLM
6. **Block SMB outbound** จากเครื่องที่ถูก compromise เพื่อหยุด hash relay: `netsh advfirewall firewall add rule name="Block SMB Out" dir=out action=block protocol=TCP remoteport=445`
7. **Force logoff** session ของ compromised account ทุก session

### Sub: long_term
- เปิดใช้ **Windows Credential Guard** บน Windows 10/Server 2016+ เพื่อ protect LSASS ด้วย virtualization
- ปิด **WDigest** ใน registry: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` → `UseLogonCredential = 0`
- ใช้ **LAPS (Local Administrator Password Solution)** เพื่อ randomize local admin password ทุกเครื่อง
- Implement **Privileged Access Workstation (PAW)** สำหรับ admin account
- ตรวจสอบและจำกัด **SeDebugPrivilege** ในทุก machine

### Sub: evidence_preservation
- ทำ **memory dump** ของ compromised machine: `winpmem_mini.exe -o C:\evidence\memory.dmp`
- Export **Sysmon Event ID 10 logs** ช่วง incident: `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\evidence\sysmon.evtx`
- เก็บ **Security Event Log** (Event 4624, 4625, 4648, 4672): `wevtutil epl Security C:\evidence\security.evtx`
- Hash ทุก evidence file และบันทึกใน chain of custody document
- เก็บ **dump file** (ถ้าพบ) พร้อม hash เพื่อ analyze offline

## Phase: eradication
### Sub: process_removal
- Kill **malware process** ที่ใช้ dump credential:
  ```powershell
  Get-Process | Where-Object {$_.Name -match "mimikatz|wce|pwdump"} | Stop-Process -Force
  ```
- ตรวจสอบ **injected process**: `Get-Process | Where-Object {$_.Modules.FileName -match "\.tmp|AppData"}`
- Scan ด้วย **Windows Defender / EDR** offline scan หาก malware ซ่อนตัวใน rootkit

### Sub: persistence_removal
- ลบ **scheduled task** ที่ถูกสร้างสำหรับ re-dump credential:
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Actions.Execute -match "mimikatz|procdump|rundll32"} | Unregister-ScheduledTask
  ```
- ตรวจสอบ **registry Run keys** และ **startup folder**: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- ลบ **malware payload** จาก disk รวมถึง dump files ที่ยังหลงเหลือ
- Reset **service account password** ทุกตัวที่อาจถูก dump

### Sub: patching
- อัปเดต **Windows** เพื่อ patch vulnerabilities ที่ Mimikatz exploit (KB ที่เกี่ยวข้อง)
- เปิด **Windows Defender Credential Guard** via Group Policy
- ติดตั้ง **Microsoft Defender for Identity** สำหรับ detect Mimikatz-like behavior บน domain level
- ทบทวน **local admin rights**: ลด จำนวน user ที่มี local admin บนเครื่อง

## Phase: post_incident
### Sub: lessons_learned
- วิเคราะห์ว่า **Credential Guard** เปิดอยู่หรือไม่ และทำไมถึงไม่เปิด
- ประเมินว่า **SIEM alert** สำหรับ LSASS process access ทำงานหรือไม่ก่อน incident
- ตรวจสอบว่า **attacker ได้ privilege escalation** มาได้อย่างไร ก่อนจะถึงขั้น dump credential
- วิเคราะห์ว่า **dwell time** นานเท่าไหร่ก่อนตรวจพบ
- ประเมิน **ผลกระทบจาก credential ที่ถูก dump** ต่อระบบอื่น (lateral movement scope)

### Sub: improvements
- **บังคับ Credential Guard** ผ่าน Group Policy บน workstation และ server ทุกเครื่อง
- Deploy **Microsoft Defender for Identity** หรือ equivalent สำหรับ detect LSASS attacks
- เพิ่ม **SIEM rule** สำหรับ Sysmon Event ID 10 ที่มี `GrantedAccess=0x1010` ไปยัง lsass.exe
- **Implement LAPS** เพื่อลด blast radius จาก local admin credential
- ทบทวน **Tier model** สำหรับ Active Directory administration
