---
threat_name: Log Tampering
technique_ids: ["T1070.001", "T1562.001", "T1562.002"]
severity: Critical
source_doc: Log_Tampering_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- ส่ง log ทุก event ไปยัง **centralized SIEM/syslog server** แบบ real-time (ทันที) เพื่อป้องกัน local log deletion
- ติดตั้ง **Wazuh / OSSEC** สำหรับ File Integrity Monitoring (FIM) บน log directory
- เตรียม **immutable log storage**: ส่ง log ไปยัง Write-Once storage (S3 with Object Lock, Azure Immutable Blob)
- เปิด **Windows Security Audit Policy** สำหรับ Event ID 1102 (Security Log Cleared) และ 4719 (Audit Policy Changed)
- ติดตั้ง **Sysmon** พร้อม config log service start/stop และ process termination
- เตรียม **backup ของ Windows Event Log** บน schedule ที่ถี่ (ทุก 15 นาที)
- มี **log integrity verification** mechanism (เช่น hash chain หรือ blockchain-based log)

### Sub: team_roles
- **Incident Commander**: ประเมิน scope ของ log ที่ถูก tamper และ assess impact ต่อ forensic capability
- **SOC Analyst (L2/L3)**: ตรวจสอบ SIEM สำหรับ Event 1102/104 และ audit policy change
- **Windows/System Admin**: ตรวจสอบว่า Windows Defender, audit policy, logging service ยังทำงานอยู่หรือไม่
- **Forensic Analyst**: ประเมิน extent ของ log loss, พยายาม recover จาก VSS shadow copy หรือ SIEM
- **Threat Intelligence**: ระบุ technique ที่ attacker ใช้ (wevtutil, PowerShell, sc.exe, reg.exe)
- **Legal/Compliance**: ประเมินผลกระทบต่อ compliance audit trail และ regulatory obligation

### Sub: comm_plan
- แจ้ง **Legal และ Compliance** ทันทีเมื่อพบว่า Security Event Log ถูก clear — อาจมีผลต่อ regulatory audit
- ส่ง **P1 Critical Alert**: log tampering บ่งบอกว่า attacker พยายาม cover tracks หลัง compromise
- แจ้ง **SIEM admin** เพื่อยืนยันว่า centralized log ยังสมบูรณ์และไม่ถูก tamper
- ประสาน **ทีม forensic** เพื่อ recover log จากทุก source ที่เป็นไปได้ก่อนที่จะ overwrite
- บันทึก **timeline ของ log gap**: ช่วงเวลาใดที่ log หายไปและเกี่ยวข้องกับ activity อะไร

## Phase: detection
### Sub: log_sources
- **Windows Security Event ID 1102**: Security audit log was cleared (สำคัญมาก — ต้อง alert ทันที)
- **Windows System Event ID 104**: Event log was cleared (สำหรับ log ประเภทอื่น เช่น System, Application)
- **Windows Security Event ID 4719**: System audit policy was changed (attacker ปิด audit)
- **Windows Security Event ID 4688**: Process creation ของ `wevtutil.exe cl`, `powershell Clear-EventLog`
- **Sysmon Event ID 1**: `sc.exe stop`, `net stop`, `wevtutil.exe cl` execution
- **Windows Defender Event ID 5001/5010**: Real-time protection disabled / scanning disabled
- **Sysmon Event ID 12/13**: Registry modification ที่ปิด Windows Defender หรือ audit policy

### Sub: detection_queries
**Splunk — ตรวจ Security Log Cleared (Event ID 1102 — สำคัญสุด):**
```spl
index=windows_security EventCode=1102
| table _time, ComputerName, SubjectUserName, SubjectDomainName, SubjectLogonId
| sort -_time
| eval alert="CRITICAL: Security Event Log Cleared"
```

**Splunk — ตรวจ Event Log Cleared (Event ID 104 — System Log):**
```spl
index=windows_system EventCode=104
| table _time, ComputerName, Message
| sort -_time
```

**Splunk — ตรวจ Audit Policy Changed (Event ID 4719):**
```spl
index=windows_security EventCode=4719
| rex field=Message "(?i)(?P<category>Category:\s+\S+)"
| rex field=Message "(?i)(?P<change>Changes:\s+.+)"
| table _time, ComputerName, SubjectUserName, category, change
| sort -_time
```

**Splunk — ตรวจ wevtutil ใช้ clear log (Event ID 4688 / Sysmon 1):**
```spl
index=sysmon EventCode=1
| where (Image LIKE "%wevtutil.exe%" AND (CommandLine LIKE "%cl %" OR CommandLine LIKE "%clear-log%"))
  OR (Image LIKE "%powershell.exe%" AND CommandLine LIKE "%Clear-EventLog%")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

**Splunk — ตรวจ Windows Defender ถูกปิด (Event ID 5001):**
```spl
index=windows_defender EventCode IN (5001, 5004, 5010, 5012)
| table _time, ComputerName, Message
| sort -_time
| eval alert="Windows Defender Disabled"
```

**Splunk — ตรวจ Security Service ถูกหยุด (Sysmon Event ID 1):**
```spl
index=sysmon EventCode=1
| where (CommandLine LIKE "%sc stop%"  OR CommandLine LIKE "%net stop%")
  AND (CommandLine LIKE "%WinDefend%"  OR CommandLine LIKE "%EventLog%"
       OR CommandLine LIKE "%Sysmon%"  OR CommandLine LIKE "%wuauserv%"
       OR CommandLine LIKE "%MpsSvc%"  OR CommandLine LIKE "%Sense%")
| table _time, ComputerName, User, CommandLine, ParentImage
```

**CLI — ตรวจ audit policy ปัจจุบัน:**
```powershell
auditpol /get /category:* | Select-String -Pattern "Logon|Object Access|Policy Change|Account Management"
```

**CLI — ตรวจ Windows Defender status:**
```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, NISEnabled
```

### Sub: ioc_list
- **Event ID 1102**: Security log cleared — ถ้า trigger ต้อง investigate ทันทีไม่มีข้อยกเว้น
- **Event ID 4719**: Audit policy disabled (เช่น ปิด Logon Events, Object Access auditing)
- **Command**: `wevtutil cl Security`, `wevtutil cl System`, `Clear-EventLog -LogName Security`
- **Service stop**: `sc stop WinDefend`, `sc stop Sysmon`, `net stop EventLog`, `sc stop mpssvc`
- **Registry**: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1`
- **Defender exclusion**: `Add-MpPreference -ExclusionPath "C:\malware"` เพื่อ bypass scanning
- **Log gap**: ใน SIEM มี time gap ในข้อมูลจาก host เฉพาะที่ไม่ควรมี gap

### Sub: scope_analysis
- ระบุ **log ที่ถูก clear**: Security, System, Application, PowerShell, Sysmon, Defender
- ประเมิน **time window ที่ log หาย**: เทียบกับ SIEM — ช่วงเวลาใดที่ attacker ไม่มีใน centralized log
- ตรวจสอบว่า **centralized SIEM** ได้รับ log ก่อน local log ถูกลบหรือไม่
- ระบุ **account ที่ใช้ clear log**: attacker ใช้ account อะไร (Event 1102 บันทึก SubjectUser)
- ตรวจสอบว่า **audit policy** ถูกปิดก่อน attack activity เพื่อ hide tracks
- ประเมินว่า **security tool อื่น** ถูกปิดด้วยหรือไม่: Defender, Sysmon, IDS agent, DLP agent

## Phase: containment
### Sub: short_term
1. **ยืนยัน SIEM ยังได้รับ log** จาก host ที่ถูก tamper — ถ้าไม่ได้รับ ให้ isolate ทันที
2. **เปิด audit policy** กลับทันที: `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`
3. **เปิด Windows Defender Real-time Protection**:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   Start-Service -Name WinDefend
   ```
4. **เปิด Sysmon** กลับถ้าถูก stop: `sc start Sysmon64`
5. **Isolate machine** ที่ถูก tamper log เพื่อ prevent further evidence destruction
6. **Lock account** ที่ใช้ clear log (จาก Event 1102 SubjectUser)
7. **Block Firewall** outbound จาก machine เพื่อหยุด attacker access

### Sub: long_term
- ส่ง log ไปยัง **SIEM แบบ real-time** และไม่ให้ attacker สามารถ delete ได้จาก source เพียงอย่างเดียว
- ใช้ **immutable log storage**: S3 Object Lock, Azure WORM storage, Splunk Audit Trail
- ตั้งค่า **Event Log maximum size** ให้ใหญ่พอ และ archive อัตโนมัติ ก่อน clear
- ใช้ **Protected Event Logging** สำหรับ PowerShell (encrypt log ด้วย certificate)
- Implement **Log integrity chain**: hash แต่ละ log entry และ verify หาก chain break

### Sub: evidence_preservation
- ดึง **log ที่ยังเหลือจาก SIEM** ก่อนที่จะ expire
- พยายาม recover log จาก **VSS Shadow Copy**: `vssadmin list shadows` และ mount shadow copy
- ทำ **disk image** ของ machine เพื่อ recover deleted log files ด้วย forensic tool (Autopsy, FTK)
- บันทึก **ช่วงเวลาที่ log หาย** (gap analysis) เป็น evidence ว่ามีการ tamper
- Export **Event 1102/4719** จาก SIEM ที่บันทึกไว้ก่อนถูก clear

## Phase: eradication
### Sub: process_removal
- ลบ **malware/tool** ที่ attacker ใช้ clear log (wevtutil เป็น legitimate tool แต่ script ที่ call มันอาจไม่ใช่):
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Actions.Arguments -match "wevtutil.*cl|Clear-EventLog"} | Unregister-ScheduledTask
  ```
- ตรวจสอบ **process ที่ยังรันอยู่** ที่ปิด security tool: `Get-Service WinDefend,Sysmon64,EventLog | Select-Object Status`
- Kill และลบ **attacker process** ที่ยังเหลืออยู่บน system

### Sub: persistence_removal
- ลบ **registry key** ที่ปิด Windows Defender:
  ```powershell
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
  ```
- ลบ **Defender exclusion** ที่ attacker เพิ่ม: `Remove-MpPreference -ExclusionPath "C:\malware"`
- Restore **audit policy** ให้ครบถ้วน: `auditpol /restore /file:C:\baseline\auditpolicy.csv`
- ตรวจสอบ **scheduled task** ที่อาจ run wevtutil.exe cl เป็น periodic task

### Sub: patching
- Enforce **Protected Users Security Group** สำหรับ account ที่มี permission clear log
- ปรับ **DACL ของ Event Log** เพื่อป้องกัน unauthorized clear (โดยปกติ admin เท่านั้นที่ clear ได้)
- ใช้ **Group Policy** บังคับ Windows Defender เปิดตลอดเวลา: `Computer Config → Admin Templates → Windows Defender Antivirus`
- Deploy **Sysmon** บนทุก machine พร้อม service protection (ไม่ให้ stop โดย non-admin)

## Phase: post_incident
### Sub: lessons_learned
- ตรวจสอบว่า **centralized SIEM** ได้รับ log ก่อน tamper สำเร็จหรือไม่ — นี่คือ critical control
- ประเมิน **ช่วงเวลา forensic blind spot**: log หายไปนานเท่าไหร่และ attacker ทำอะไรได้บ้างในช่วงนั้น
- วิเคราะห์ว่า attacker **ใช้สิทธิ์อะไร** ในการ clear log — ต้องมีสิทธิ์ admin
- ตรวจสอบว่า **alert สำหรับ Event 1102** มีอยู่ใน SIEM และ trigger ทันทีหรือไม่
- ประเมินว่า **compliance audit trail** ได้รับผลกระทบอย่างไร (PCI DSS, ISO 27001 ต้องการ log retention)

### Sub: improvements
- **บังคับ centralized log forwarding** ก่อนเขียน local log — ใช้ Windows Event Forwarding (WEF) หรือ agent
- เพิ่ม **SIEM alert ระดับ P1** สำหรับ Event 1102 และ 4719 ทุก occurrence
- ใช้ **immutable log storage** สำหรับ security-critical log ทั้งหมด
- ทำ **log retention audit** ทุก 6 เดือน เพื่อ verify ว่า log ครบถ้วนตาม policy
- Implement **security tool health monitoring**: alert เมื่อ Defender, Sysmon, SIEM agent หยุดทำงาน
