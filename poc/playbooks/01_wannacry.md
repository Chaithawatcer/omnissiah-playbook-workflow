---
threat_name: WannaCry Ransomware
technique_ids: ["T1486", "T1190", "T1021.002"]
severity: Critical
source_doc: WannaCry_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
เครื่องมือที่ต้องเตรียมก่อนรับมือ WannaCry:
- Nmap: ใช้สแกนหาเครื่องที่มีช่องโหว่ MS17-010 | คำสั่งเช็ค: `nmap -V`
- Wireshark / tshark: ดักจับ SMB traffic ผิดปกติ | คำสั่งเช็ค: `tshark -v`
- EDR Console (CrowdStrike / Defender for Endpoint): ใช้ Isolate Host | ตรวจสอบ: เข้า portal ยืนยัน agent online
- PowerShell (Admin): รัน command ตรวจสอบและกำจัด | คำสั่งเช็ค: `$PSVersionTable.PSVersion`
- Backup Verification Tool: ยืนยัน backup offline ล่าสุด | คำสั่งเช็ค: ตรวจ timestamp ของ backup ล่าสุด

### Sub: team_roles
บทบาทของทีมในการรับมือ WannaCry:
- L1 SOC Analyst: เฝ้าระวัง alert จาก EDR/SIEM โดยเฉพาะ process ชื่อ mssecsvc.exe, tasksche.exe และไฟล์นามสกุล .wncry
- L2 Incident Handler: รับ escalation ตัดสินใจ Isolate เครื่อง ประสาน Network Team
- L3 / Forensics: วิเคราะห์หลักฐานใน RAM dump และ disk image
- Network Engineer: ตั้งกฎ Firewall block port 445 ระหว่าง VLAN ทันทีเมื่อได้รับการประสาน
- IT Manager: อนุมัติการ shutdown service และประสาน Business Owner

### Sub: comm_plan
แผนการสื่อสารฉุกเฉินสำหรับ WannaCry:
- ถ้าพบเครื่อง 1-5 เครื่อง: แจ้ง L2 Incident Handler ภายใน 15 นาที
- ถ้าพบเครื่องมากกว่า 5 เครื่องหรือข้ามหลาย subnet: escalate ไป IT Manager และ CISO ทันที
- ห้ามแจ้งข่าวในช่องทางสาธารณะ (Slack ทั่วไป) ใช้ช่อง #incident-response ที่ จำกัดสิทธิ์เท่านั้น
- สร้าง War Room call ทันทีถ้าระดับความรุนแรงเป็น Critical

## Phase: detection
### Sub: log_sources
Log source ที่ต้องตรวจสอบเมื่อสงสัย WannaCry:
- Process Creation Log (Sysmon Event ID 1): ค้นหา process ชื่อ mssecsvc.exe, tasksche.exe, @WanaDecryptor@.exe
- Windows Event Log (Security, Event ID 4688): ค้นหา process ที่ถูก spawn จาก services.exe ที่ผิดปกติ
- Network Traffic Log (Firewall / IDS): ค้นหา SMB traffic (port 445) ปริมาณสูงผิดปกติจากเครื่องเดียว
- DNS Log: ค้นหาการ query โดเมน Kill Switch (iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com)
- File System Audit Log: ค้นหาการสร้างไฟล์นามสกุล .wncry จำนวนมากในเวลาสั้น

### Sub: detection_queries
Detection queries และ SIEM rules สำหรับ WannaCry:
- ค้นหาไฟล์ถูกเข้ารหัส: `cmd.exe /c dir /s /b C:\*.wncry`
- ค้นหา process มัลแวร์: `Get-Process | Where-Object {$_.Name -in @("tasksche","mssecsvc","@WanaDecryptor@")}`
- SIEM Query (SMB Scan): `index=network dest_port=445 | stats count by src_ip | where count > 100`
- SIEM Query (Process): `index=sysmon EventCode=1 Image="*tasksche.exe" OR Image="*mssecsvc.exe"`
- DNS Kill Switch Check: `index=dns query="*iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea*"`
- ค้นหาการ Spawn process ผิดปกติ: `index=sysmon EventCode=1 ParentImage="*services.exe" Image!="*svchost.exe"`

### Sub: ioc_list
IOC ที่เกี่ยวข้องกับ WannaCry:
- Process names: mssecsvc.exe, tasksche.exe, @WanaDecryptor@.exe, @Please_Read_Me@.bat
- File extensions: .wncry, .wncryt, .wncrypt
- Mutex: MsWinZonesCacheCounterMutexA
- Registry Key: HKLM\SOFTWARE\WannaCryptor
- Network: ใช้ SMB port 445 ในการสแกนและแพร่กระจาย, เชื่อมต่อ TOR สำหรับการจ่ายค่าไถ่
- Kill Switch Domain: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com (ถ้า resolve ได้ มัลแวร์จะหยุดทำงาน)

### Sub: scope_analysis
วิธีประเมินขอบเขตการแพร่กระจายของ WannaCry:
- ตรวจสอบ SMB Connection log เพื่อนับจำนวนเครื่องที่ได้รับ SMB request จากเครื่องต้นเหตุ
- ใช้ Nmap สแกน subnet ทั้งหมดเพื่อหาเครื่องที่มีพอร์ต 445 เปิดและมีช่องโหว่ MS17-010
- ตรวจสอบ EDR telemetry ว่ามีเครื่องไหน alert เรื่อง suspicious SMB activity บ้าง
- ประเมิน: ถ้ากระจายแค่ใน VLAN เดียว = ควบคุมได้ ถ้าข้าม VLAN = Critical escalate ทันที

## Phase: containment
### Sub: short_term
ขั้นตอน short-term containment ฉุกเฉินสำหรับ WannaCry:
- ขั้นตอนที่ 1 - Isolate Host: สั่ง Host Isolation ผ่าน EDR ทันที (หรือดึงสาย LAN / ปิด Wi-Fi ถ้าไม่มี EDR) ห้ามปิดเครื่อง!
- ขั้นตอนที่ 2 - Block SMB: สั่ง Firewall บล็อก Inbound + Outbound พอร์ต 445 และ 139 ระหว่าง VLAN ทันที
- ขั้นตอนที่ 3 - DNS Kill Switch: ตรวจสอบให้แน่ใจว่า DNS Server สามารถ Resolve Kill Switch Domain ได้ (ห้ามบล็อก domain นี้!)
- ขั้นตอนที่ 4 - Disable SMBv1: รัน PowerShell: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`
- คำเตือน: ห้ามปิดเครื่อง (Reboot/Shutdown) เพราะจะทำลายหลักฐานใน RAM

### Sub: long_term
Long-term containment เพื่อป้องกันการแพร่กระจายซ้ำ:
- ตั้ง Windows Firewall via GPO ปิดกั้น Inbound SMB (port 445, 139) บน Workstation ทุกเครื่อง
- Disable SMBv1 บน Server ทุกเครื่องผ่าน Group Policy
- Isolate VLAN ที่ได้รับผลกระทบออกจากส่วนอื่นของเครือข่ายชั่วคราว
- ตั้ง IDS/IPS rule เพื่อตรวจจับและบล็อก SMB Exploitation attempts

### Sub: evidence_preservation
การเก็บรักษาหลักฐานสำหรับ WannaCry:
- ทำ RAM Dump ก่อนทำอะไรทั้งนั้น (อาจมี encryption key อยู่ใน RAM): `winpmem_mini_x64_rc2.exe memdump.raw`
- ถ่าย Disk Image ของเครื่องที่ติดเชื้อก่อน re-image: ใช้ FTK Imager หรือ dd
- Export Windows Event Logs ทั้งหมดก่อน clear: `wevtutil epl System C:\evidence\system.evtx`
- เก็บ screenshot ของหน้าต่างเรียกค่าไถ่
- บันทึก timestamp ของเหตุการณ์ทั้งหมด

## Phase: eradication
### Sub: process_removal
การกำจัด process และ service ของ WannaCry:
- หยุด Service: `sc stop mssecsvc2.0` และ `sc delete mssecsvc2.0`
- Kill process: `taskkill /F /IM tasksche.exe` และ `taskkill /F /IM @WanaDecryptor@.exe`
- ลบ Scheduled Task: `schtasks /Delete /TN "Microsoft\Windows\tasksche" /F`

### Sub: persistence_removal
ลบ persistence ที่ WannaCry ฝังไว้:
- ลบ Registry Key: `Remove-ItemProperty -Path "HKLM:\SOFTWARE\" -Name "WannaCryptor"`
- ลบไฟล์มัลแวร์: ค้นหาและลบไฟล์ tasksche.exe, mssecsvc.exe ในโฟลเดอร์ System
- ลบไฟล์ที่เกี่ยวข้อง: @WanaDecryptor@.exe, @Please_Read_Me@.bat, .wncrypt files

### Sub: patching
การ patch ช่องโหว่ต้นเหตุและกู้คืนระบบ:
- ติดตั้ง Security Patch MS17-010 (KB4013389) บนทุกเครื่อง Windows ในองค์กร
- ยืนยัน patch ด้วย: `nmap -p 445 --script smb-vuln-ms17-010 <subnet>`
- กู้คืนไฟล์จาก Offline Backup (ห้ามใช้ Backup ที่เชื่อมต่ออยู่ตอนโดนโจมตี)
- Re-image เครื่องที่ติดเชื้อแล้วกู้คืนจาก clean backup

## Phase: post_incident
### Sub: lessons_learned
บทเรียนที่ได้จากเหตุการณ์ WannaCry:
- ช่องโหว่หลักคือการไม่ได้ติดตั้ง patch MS17-010 ที่ Microsoft ออกมาแล้วหลายเดือน
- การขาด Network Segmentation ทำให้มัลแวร์แพร่กระจายข้าม VLAN ได้รวดเร็ว
- ไม่มี Offline Backup ที่พร้อมใช้งาน ทำให้การกู้คืนล่าช้า
- การตรวจจับล่าช้าเพราะไม่มี EDR ที่ detect SMB exploitation ได้

### Sub: improvements
การปรับปรุงเพื่อป้องกันการเกิดซ้ำ:
- บังคับ Patch Management ทุก 30 วัน และ Emergency Patch ภายใน 72 ชั่วโมงสำหรับ Critical CVE
- ติดตั้ง Network Segmentation (Micro-segmentation) ห้าม Workstation คุยกันผ่าน SMB โดยตรง
- ทำ Offline Backup Drill ทุกไตรมาสเพื่อยืนยันว่า Backup กู้คืนได้จริง
- Deploy EDR ที่ครอบคลุมทุก endpoint และตั้ง Alert สำหรับ Lateral Movement via SMB
