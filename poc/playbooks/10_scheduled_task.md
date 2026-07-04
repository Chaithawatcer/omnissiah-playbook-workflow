---
threat_name: Scheduled Task
technique_ids: ["T1053.005", "T1547.001", "T1059.001"]
severity: High
source_doc: Scheduled_Task_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เปิด **Windows Security Audit Policy** สำหรับ Event ID 4698 (Task Created), 4699 (Task Deleted), 4702 (Task Modified)
- ติดตั้ง **Sysmon** พร้อม config ที่ log Event ID 1 (Process Create สำหรับ schtasks.exe)
- เตรียม **Autoruns (Sysinternals)** สำหรับ enumerate และ audit scheduled task และ registry persistence
- เตรียม PowerShell script ดึง task ทั้งหมดพร้อม action, trigger, และ run-as user
- มี **baseline snapshot** ของ scheduled task ที่ legitimate บนทุก server type
- เตรียม **Registry analysis tool** (RegRipper, Registry Explorer) สำหรับ Run key analysis
- เตรียม **hash database** ของ legitimate Windows scheduled task binary

### Sub: team_roles
- **Incident Commander**: ตัดสินใจ disable task ทันที vs ปล่อยให้ทำงานเพื่อ gather more evidence
- **Windows Endpoint Specialist**: enumerate scheduled task, ระบุ malicious task, disable/delete
- **SOC Analyst (L2/L3)**: correlate Event 4698 กับ process execution, ระบุ user ที่สร้าง task
- **Malware Analyst**: วิเคราะห์ payload ที่ task เรียกใช้ (PowerShell, binary, script)
- **Active Directory Admin**: ตรวจสอบว่า task ถูกสร้างผ่าน GPO หรือ local action
- **Forensic Analyst**: เก็บ task XML definition และ execution history

### Sub: comm_plan
- แจ้ง **Windows Admin** ทันทีเมื่อพบ task ที่ไม่อยู่ใน baseline
- ส่ง **P2 Alert** ไปยัง CISO — scheduled task persistence บ่งบอกว่า attacker ต้องการ stay persistent
- แจ้ง **application owner** หาก malicious task ถูกสร้างบน production server
- บันทึก **task name, path, action, trigger, author** ทุก malicious task ใน incident ticket
- ประสาน **threat intelligence** เพื่อ identify malware family จาก task name/payload pattern

## Phase: detection
### Sub: log_sources
- **Windows Security Event ID 4698**: Task Created — บันทึก task name, XML definition, user ที่สร้าง
- **Windows Security Event ID 4699**: Task Deleted — attacker อาจลบ task หลัง execute เพื่อ cover tracks
- **Windows Security Event ID 4702**: Task Modified — modification ของ task ที่มีอยู่แล้ว
- **Sysmon Event ID 1**: `schtasks.exe /create` หรือ task binary execution โดย `taskeng.exe`/`taskhostw.exe`
- **Windows Task Scheduler Event Log**: `Microsoft-Windows-TaskScheduler/Operational` — Event 100 (Task Started), 200 (Task Completed)
- **Registry**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\` — task metadata
- **File System**: `C:\Windows\System32\Tasks\` และ `C:\Windows\SysWOW64\Tasks\` — XML task definition files

### Sub: ioc_list
- **Task name ผิดปกติ**: ชื่อที่ mimics system task เช่น `WindowsUpdate`, `SystemMaintenance`, `MicrosoftEdgeUpdate`
- **Task path**: task ที่สร้างใน root `\` แทน `\Microsoft\Windows\` (task จริงอยู่ใน subfolder)
- **Command**: `powershell.exe -enc`, `cmd.exe /c`, `mshta.exe`, `wscript.exe`, `regsvr32.exe /s /u /i:`
- **Run-as**: task ที่ run as `SYSTEM` หรือ Domain Admin โดย user ทั่วไปเป็นคนสร้าง
- **Trigger**: task ที่ trigger ทุกนาที, ทุก 5 นาที, หรือ on system startup + on user logon พร้อมกัน
- **Event ID 4699**: task ถูกลบทันทีหลังรัน — บ่งบอก self-deleting persistence
- **Registry**: value ใหม่ใน Run key ที่ไม่มีใน baseline, โดยเฉพาะที่ชี้ไปยัง `%TEMP%` หรือ `%APPDATA%`

## Phase: containment
### Sub: short_term
1. **Disable malicious task** ทันที: `Disable-ScheduledTask -TaskName "<task_name>" -TaskPath "<path>"`
2. **Block network connection** ที่ task พยายามสร้าง (C2 IP/domain) ที่ Firewall
3. **Kill process** ที่ถูก spawn โดย malicious task: `Stop-Process -Name <process_name> -Force`
4. **Disable account** ที่สร้าง task หาก account ถูก compromise
5. **ตรวจสอบ GPO** ว่ามี task ถูกแจกจ่ายผ่าน Group Policy หรือไม่: `Get-GPO -All | Get-GPOReport -ReportType XML`
6. **Isolate machine** ที่มี malicious task ในระหว่าง investigate
7. **Monitor task execution event** (Event ID 200) เพื่อยืนยันว่า task ไม่รันอีก

### Sub: long_term
- ใช้ **AppLocker / WDAC** เพื่อ whitelist binary ที่ scheduled task สามารถรันได้
- Implement **Scheduled Task audit policy** ที่ alert ทุก task ที่สร้างโดย non-admin
- ทบทวน **GPO** ทุก GPO ที่มี scheduled task และ verify ว่า legitimate
- จำกัด **สิทธิ์สร้าง Scheduled Task**: ให้เฉพาะ admin เท่านั้นที่สร้างได้บน production server

### Sub: evidence_preservation
- Export **Task XML definition**: `Export-ScheduledTask -TaskName "<name>" -TaskPath "<path>" > C:\evidence\task.xml`
- Export **Windows Security Event Log** (Event 4698, 4699, 4702): `wevtutil epl Security C:\evidence\security.evtx`
- Export **Task Scheduler Operational Log**: `wevtutil epl "Microsoft-Windows-TaskScheduler/Operational" C:\evidence\taskscheduler.evtx`
- เก็บ **Registry snapshot** ของ Run keys: `reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\evidence\runkeys.reg`
- บันทึก **hash ของ payload file** ที่ task เรียกใช้

## Phase: eradication
### Sub: process_removal
- Delete malicious scheduled task:
  ```powershell
  Unregister-ScheduledTask -TaskName "<malicious_task>" -TaskPath "\" -Confirm:$false
  ```
- ลบ **task file** จาก file system: `Remove-Item "C:\Windows\System32\Tasks\<task_name>" -Force`
- Kill process ที่ถูก spawn โดย task และยังคงทำงานอยู่

### Sub: persistence_removal
- ลบ **Registry Run key** ที่ malicious: `Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<value_name>"`
- ตรวจสอบ **Startup folder**: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
- ตรวจสอบ **WMI subscription** ที่อาจถูกสร้างเพิ่มเติม
- ลบ **payload file** ที่ task ใช้รัน (บันทึก hash ก่อนลบ)

### Sub: patching
- อัปเดต **Windows** patch ที่ attacker ใช้ exploit เพื่อ initial access
- ทบทวน **Scheduled Task permission**: ใช้ GPO จำกัด task creation
- อัปเดต **AV/EDR signature** สำหรับ malware payload ที่ตรวจพบ
- Audit **GPO ทั้งหมด** ที่มี scheduled task definition

## Phase: post_incident
### Sub: lessons_learned
- ตรวจสอบว่า **Event ID 4698 alerting** ถูก configure ใน SIEM ก่อน incident หรือไม่
- วิเคราะห์ว่า **Autoruns baseline** มีการทำอยู่แล้วหรือไม่ เพื่อ detect deviation
- ประเมินว่า task ทำงานนาน **เท่าไหร่** ก่อนถูกตรวจพบ (dwell time)
- วิเคราะห์ว่า **payload ที่ task รัน** สร้างความเสียหายอะไรบ้างในระหว่างนั้น
- ตรวจสอบว่า **GPO** ถูก audit อย่างสม่ำเสมอหรือไม่

### Sub: improvements
- **Enable Scheduled Task audit** (Event 4698/4699/4702) บนทุก server และ workstation
- Deploy **Autoruns periodic scan** และ compare กับ baseline อัตโนมัติ
- เพิ่ม **SIEM alert** สำหรับ task ที่ run PowerShell, cmd, หรือ script interpreter
- ใช้ **AppLocker** เพื่อ block suspicious binary ที่ task พยายาม execute
- ทำ **baseline audit** ของ scheduled task ทุก 3 เดือน
