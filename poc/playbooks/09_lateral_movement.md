---
threat_name: Lateral Movement
technique_ids: ["T1550.002", "T1021.001", "T1021.002"]
severity: Critical
source_doc: Lateral_Movement_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เตรียม **BloodHound / SharpHound** บน sandbox สำหรับ map AD attack path และ identify pivot points
- ติดตั้ง **Sysmon** พร้อม config ที่ log Event ID 3 (Network Connection), Event ID 1 (Process Create)
- เปิด **Windows Security Audit Policy** สำหรับ Event ID 4648, 4624, 4625, 4768, 4769
- ติดตั้ง **Zeek (Bro)** สำหรับ monitor SMB traffic pattern ระหว่าง host
- เตรียม **Impacket toolkit** (psexec.py, wmiexec.py) บน sandbox สำหรับ understand technique
- มี **AD topology diagram** แสดง trust relationship, privileged account, และ high-value target
- เตรียม **network segmentation diagram** เพื่อ assess containment boundary

### Sub: team_roles
- **Incident Commander**: ตัดสินใจ scope ของ network isolation เพื่อหยุด lateral movement
- **Active Directory Specialist**: ตรวจสอบ authentication event, ระบุ compromised credential ที่ใช้ pivot
- **Network Security Engineer**: block SMB, RDP, WMI traffic ระหว่าง segments ที่ผิดปกติ
- **SOC Analyst (L2/L3)**: hunt ด้วย Event ID 4648, สร้าง timeline ของ pivot path
- **Threat Intelligence**: ระบุ technique ที่ใช้ (Pass-the-Hash, Pass-the-Ticket, WMI, PSExec)
- **Forensic Analyst**: เก็บ evidence จากทุก machine ที่ attacker เข้าถึง

### Sub: comm_plan
- แจ้ง **AD Admin** ทันทีเพื่อ reset credential และ monitor privileged account
- แจ้ง **network team** เพื่อ segment เครื่องที่ถูก compromise ออก
- ส่ง **P1 Critical Alert** เนื่องจาก lateral movement บ่งบอกว่า attacker มี foothold หลาย machine
- ประสาน **business owner** ของ system ที่ถูก pivot เข้าไป เพื่อประเมิน impact
- สร้าง **master timeline** รวม event จากทุก machine ที่ถูก pivot เข้า

## Phase: detection
### Sub: log_sources
- **Windows Security Event ID 4648**: การ login โดยใช้ explicit credential (RunAs, PSExec, net use)
- **Windows Security Event ID 4624 Type 3**: Network logon จาก machine อื่น
- **Windows Security Event ID 4624 Type 10**: RemoteInteractive (RDP) logon
- **Sysmon Event ID 1**: `psexesvc.exe`, `wmiprvse.exe`, `mstsc.exe` spawn process ผิดปกติ
- **Sysmon Event ID 3**: SMB connection (port 445) จาก workstation ไปยัง workstation (non-server)
- **Windows Security Event ID 4769**: Kerberos service ticket request (Pass-the-Ticket detection)
- **Zeek SMB log**: การ access file share ผิดปกติ, ADMIN$ หรือ C$ share access

### Sub: detection_queries
**Splunk — ตรวจ Pass-the-Hash (Event ID 4624 Type 3 + NTLM จาก unusual source):**
```spl
index=windows_security EventCode=4624 Logon_Type=3 AuthenticationPackageName=NTLM
| where NOT (src_ip="127.0.0.1" OR src_ip="::1")
| stats count by src_ip, Account_Name, Workstation_Name, dest_host
| where count > 5
| sort -count
```

**Splunk — ตรวจ Explicit Credential Logon (Event ID 4648 — PSExec/WMI):**
```spl
index=windows_security EventCode=4648
| where TargetServerName != ComputerName
| stats count by SubjectUserName, TargetUserName, TargetServerName, ProcessName
| where count > 2
| sort -count
```

**Splunk — ตรวจ Admin Share Access (C$, ADMIN$):**
```spl
index=windows_security EventCode=5140
| where ShareName IN ("\\\\*\\ADMIN$","\\\\*\\C$","\\\\*\\IPC$")
| stats count by SubjectUserName, IpAddress, ShareName, ComputerName
| sort -count
```

**CLI — ตรวจ SMB connection ผิดปกติด้วย Zeek:**
```bash
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log | awk '$3==445' | sort | uniq -c | sort -rn | head 20
```

**Splunk — ตรวจ PSExec (Sysmon Event ID 1 + psexesvc.exe):**
```spl
index=sysmon EventCode=1
| where Image LIKE "%psexesvc.exe%" OR ParentImage LIKE "%psexec.exe%"
| table _time, ComputerName, Image, CommandLine, User, ParentImage
```

**Splunk — ตรวจ WMI lateral movement (wmiprvse spawn process):**
```spl
index=sysmon EventCode=1
| where ParentImage LIKE "%WmiPrvSE.exe%"
  AND NOT (Image LIKE "%WmiPrvSE.exe%" OR Image LIKE "%svchost.exe%")
| table _time, ComputerName, ParentImage, Image, CommandLine
```

### Sub: ioc_list
- **Event ID 4648**: SubjectUserName ≠ TargetUserName (ใช้ credential คนอื่น login)
- **Event ID 4624 Type 9**: NewCredentials logon — บ่งบอก Pass-the-Hash เมื่อ paired กับ NTLM
- **Kerberos error 0x20**: ticket expired, อาจบ่งบอก Pass-the-Ticket ที่ใช้ old ticket
- **Process**: `psexesvc.exe` ปรากฏบน target machine, `wmiprvse.exe` spawn command shell
- **SMB access**: Workstation-to-Workstation SMB (port 445) ซึ่งไม่ใช่ file server access ปกติ
- **Time anomaly**: lateral movement เกิดรวดเร็วหลัง initial compromise ภายใน 1-2 ชั่วโมง
- **Account**: Service account หรือ Domain Admin ถูกใช้บน machine ที่ไม่ควรมี (unusual workstation)

### Sub: scope_analysis
- สร้าง **lateral movement map**: Machine A → Machine B → Machine C โดย map จาก Event 4648/4624
- ระบุ **credential ที่ถูกใช้**: account ชื่ออะไร, มี privilege ระดับไหน บน machine ใดบ้าง
- ตรวจสอบ **high-value target** ที่ถูก pivot เข้า: Domain Controller, File Server, Database Server
- ระบุว่า attacker อยู่ใน **machine ใดบ้าง** ณ ปัจจุบัน และต้องการ isolate กี่ เครื่อง
- ตรวจสอบ **จุดเริ่มต้น (patient zero)**: machine แรกที่ถูก compromise และเริ่ม pivot
- ประเมิน **blast radius**: ถ้า attacker ถึง DC แล้ว ต้องถือว่า full domain compromise

## Phase: containment
### Sub: short_term
1. **Isolate machine ทุกเครื่อง** ที่ระบุว่า attacker เข้าถึง โดยย้ายเข้า quarantine VLAN
2. **Block SMB (port 445) และ WMI (port 135, 49152-65535)** ระหว่าง workstation-to-workstation ที่ Firewall/switch ACL
3. **Disable account** ที่ถูก compromise ซึ่งใช้ lateral movement: `Disable-ADAccount -Identity <username>`
4. **Reset krbtgt password** หากสงสัยว่ามี Pass-the-Ticket หรือ Golden Ticket
5. **Block RDP (port 3389)** จาก workstation ไปยัง workstation ชั่วคราว
6. **Revoke Kerberos TGT** สำหรับ compromised account: Force re-authentication
7. **ปิด PsExec/WMI remote execution** ผ่าน Group Policy สำหรับ non-admin machine

### Sub: long_term
- Implement **network micro-segmentation**: ไม่อนุญาต workstation-to-workstation communication
- ใช้ **LAPS** เพื่อ randomize local admin password ป้องกัน lateral movement ด้วย same credential
- Deploy **Privileged Access Workstation (PAW)** สำหรับ admin task เท่านั้น
- เปิดใช้ **SMB Signing** บน domain: ป้องกัน relay attack
- ทบทวน **AD Tier Model**: Tier 0 (DC), Tier 1 (Servers), Tier 2 (Workstations) ต้องแยก credential

### Sub: evidence_preservation
- Export **Windows Security Event Log** จากทุก machine ที่เกี่ยวข้อง: `wevtutil epl Security C:\evidence\security_<hostname>.evtx`
- เก็บ **Sysmon log** (Event 1, 3, 7, 8) จากทุก machine
- ทำ **memory dump** ของ machine ที่ attacker อาจยังอยู่
- บันทึก **active network connection** ก่อน isolate: `netstat -anbo > C:\evidence\netstat.txt`
- เก็บ **SMB/Zeek log** ที่แสดง lateral movement pattern

## Phase: eradication
### Sub: process_removal
- ลบ **psexesvc.exe** ที่อาจถูก drop บน target machine:
  ```powershell
  Get-ChildItem -Path C:\Windows -Name "psexesvc.exe" | Remove-Item -Force
  ```
- Kill **remote shell process** ที่ถูกสร้างผ่าน WMI หรือ PSExec:
  ```powershell
  Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -match "cmd.exe|powershell"} | Select-Object ProcessId, CommandLine
  ```
- ลบ **service ที่สร้างโดย PSExec**: `sc.exe query | findstr PSEXESVC`

### Sub: persistence_removal
- ตรวจสอบ **new local user** ที่ attacker สร้างบน machine ที่ถูก pivot: `Get-LocalUser`
- ลบ **scheduled task** ที่ถูกสร้างบน remote machine ผ่าน lateral movement
- ตรวจสอบ **registry Run key** บนทุก machine ที่ถูก compromise
- Reset **service account password** ที่ถูกใช้ในการ lateral movement

### Sub: patching
- อัปเดต **Windows** เพื่อ patch NTLM relay vulnerability (MS17-010, PrintNightmare ถ้ายังไม่ patch)
- เปิด **SMB Signing** และ **LDAP Signing** ผ่าน Group Policy
- ปิด **NTLM authentication** บน network level หากเป็นไปได้ (ใช้ Kerberos เท่านั้น)
- ทบทวน **local admin account**: ลด account ที่มี local admin บนหลาย machine

## Phase: post_incident
### Sub: lessons_learned
- วิเคราะห์ว่า **network segmentation** เพียงพอที่จะหยุด lateral movement หรือไม่
- ตรวจสอบว่า **LAPS** ถูก deploy ก่อน incident หรือไม่ — ถ้าไม่มี attacker ใช้ same local admin password
- ประเมิน **dwell time** และ machine ที่ถูก pivot กี่ เครื่อง
- วิเคราะห์ว่า **SIEM alert** สำหรับ Event ID 4648 ทำงานถูกต้องหรือไม่
- ตรวจสอบว่า attacker ถึง **Domain Controller** หรือไม่

### Sub: improvements
- **Deploy LAPS** บนทุก workstation และ server ภายใน 30 วัน
- Implement **network micro-segmentation** ด้วย VLAN หรือ host-based firewall
- เพิ่ม **SIEM detection** สำหรับ Workstation-to-Workstation SMB และ explicit credential logon
- ทำ **AD Tiering** และ enforce credential isolation ระหว่าง Tier
- จัด **Purple Team exercise** เพื่อ validate detection ของ lateral movement technique
