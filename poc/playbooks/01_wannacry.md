---
threat_name: WannaCry Ransomware
technique_ids: ["T1210", "T1570", "T1486", "T1490", "T1489", "T1543.003"]
severity: Critical
source_doc: WannaCry_IR_Playbook_v2
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
### Sub: log_sources [T1486, T1210, T1570]
Log source ที่ต้องตรวจสอบเมื่อสงสัย WannaCry:
- Process Creation Log (Sysmon Event ID 1): ค้นหา process ชื่อ mssecsvc.exe, tasksche.exe, @WanaDecryptor@.exe
- Windows Event Log (Security, Event ID 4688): ค้นหา process ที่ถูก spawn จาก services.exe ที่ผิดปกติ
- Network Traffic Log (Firewall / IDS): ค้นหา SMB traffic (port 445) ปริมาณสูงผิดปกติจากเครื่องเดียว (EternalBlue exploit + การคัดลอกตัวเอง)
- DNS Log: ค้นหาการ query โดเมน Kill Switch (iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com)
- File System Audit Log: ค้นหาการสร้างไฟล์นามสกุล .wncry จำนวนมากในเวลาสั้น

### Sub: ioc_list [T1486, T1543.003]
IOC ที่เกี่ยวข้องกับ WannaCry:
- Process names: mssecsvc.exe, tasksche.exe, @WanaDecryptor@.exe, @Please_Read_Me@.bat
- Service: mssecsvc2.0 (Windows service ที่ worm สร้างเพื่อ persistence)
- File extensions: .wncry, .wncryt, .wncrypt
- Mutex: MsWinZonesCacheCounterMutexA
- Registry Key: HKLM\SOFTWARE\WannaCryptor
- Network: ใช้ SMB port 445 ในการสแกนและแพร่กระจาย, เชื่อมต่อ TOR สำหรับการจ่ายค่าไถ่
- Kill Switch Domain: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com (ถ้า resolve ได้ มัลแวร์จะหยุดทำงาน)

## Phase: containment
### Sub: short_term_block_spread [T1210, T1570]
ขั้นตอน short-term containment หยุดการแพร่กระจายผ่าน SMB:
- Isolate Host: สั่ง Host Isolation ผ่าน EDR ทันที (หรือดึงสาย LAN / ปิด Wi-Fi ถ้าไม่มี EDR) ห้ามปิดเครื่อง!
- Block SMB: สั่ง Firewall บล็อก Inbound + Outbound พอร์ต 445 และ 139 ระหว่าง VLAN ทันที (ตัดทั้ง exploit และการคัดลอกตัวเอง)
- DNS Kill Switch: ตรวจสอบให้แน่ใจว่า DNS Server สามารถ Resolve Kill Switch Domain ได้ (ห้ามบล็อก domain นี้!)
- คำเตือน: ห้ามปิดเครื่อง (Reboot/Shutdown) เพราะจะทำลายหลักฐานใน RAM

### Sub: short_term_patch_vuln [T1210]
ปิดช่องโหว่ MS17-010 ระหว่าง containment ระยะสั้น:
- Disable SMBv1: รัน PowerShell: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`

### Sub: long_term_segmentation [T1210, T1570]
Long-term containment ลดพื้นผิวการแพร่กระจายผ่าน SMB:
- ตั้ง Windows Firewall via GPO ปิดกั้น Inbound SMB (port 445, 139) บน Workstation ทุกเครื่อง
- Isolate VLAN ที่ได้รับผลกระทบออกจากส่วนอื่นของเครือข่ายชั่วคราว

### Sub: long_term_hardening [T1210]
Long-term hardening ปิดช่องโหว่ MS17-010 ถาวร:
- Disable SMBv1 บน Server ทุกเครื่องผ่าน Group Policy
- ตั้ง IDS/IPS rule เพื่อตรวจจับและบล็อกการ exploit SMB (SMB Exploitation attempts)

### Sub: evidence_preservation [T1486]
การเก็บรักษาหลักฐานสำหรับ WannaCry:
- ทำ RAM Dump ก่อนทำอะไรทั้งนั้น (อาจมี encryption key อยู่ใน RAM): `winpmem_mini_x64_rc2.exe memdump.raw`
- ถ่าย Disk Image ของเครื่องที่ติดเชื้อก่อน re-image: ใช้ FTK Imager หรือ dd
- Export Windows Event Logs ทั้งหมดก่อน clear: `wevtutil epl System C:\evidence\system.evtx`
- เก็บ screenshot ของหน้าต่างเรียกค่าไถ่
- บันทึก timestamp ของเหตุการณ์ทั้งหมด

## Phase: eradication
### Sub: process_removal [T1486, T1543.003]
การกำจัด process และ service ของ WannaCry:
- หยุด Service: `sc stop mssecsvc2.0` และ `sc delete mssecsvc2.0`
- Kill process: `taskkill /F /IM tasksche.exe` และ `taskkill /F /IM @WanaDecryptor@.exe`
- ลบ Scheduled Task: `schtasks /Delete /TN "Microsoft\Windows\tasksche" /F`

### Sub: persistence_removal [T1543.003]
ลบ persistence ที่ WannaCry ฝังไว้:
- ลบ Registry Key: `Remove-ItemProperty -Path "HKLM:\SOFTWARE\" -Name "WannaCryptor"`
- ลบ service แปลกปลอม mssecsvc2.0 และไฟล์มัลแวร์: ค้นหาและลบไฟล์ tasksche.exe, mssecsvc.exe ในโฟลเดอร์ System
- ลบไฟล์ที่เกี่ยวข้อง: @WanaDecryptor@.exe, @Please_Read_Me@.bat, .wncrypt files

### Sub: patch_ms17010 [T1210]
การ patch ช่องโหว่ต้นเหตุ (MS17-010):
- ติดตั้ง Security Patch MS17-010 (KB4013389) บนทุกเครื่อง Windows ในองค์กร
- ยืนยัน patch ด้วย: `nmap -p 445 --script smb-vuln-ms17-010 <subnet>`

### Sub: recovery_restore [T1486, T1490]
การกู้คืนข้อมูลที่ถูกเข้ารหัส:
- กู้คืนไฟล์จาก Offline Backup (ห้ามใช้ Backup ที่เชื่อมต่ออยู่ตอนโดนโจมตี) — WannaCry ลบ Shadow Copy จึงกู้ local ไม่ได้
- Re-image เครื่องที่ติดเชื้อแล้วกู้คืนจาก clean backup
- เปิด System Protection / Shadow Copy กลับหลังกู้ระบบ

## Phase: post_incident
### Sub: lessons_learned
บทเรียนที่ได้จากเหตุการณ์ WannaCry:
- ช่องโหว่หลักคือการไม่ได้ติดตั้ง patch MS17-010 ที่ Microsoft ออกมาแล้วหลายเดือน
- การขาด Network Segmentation ทำให้มัลแวร์แพร่กระจายข้าม VLAN ได้รวดเร็ว
- ไม่มี Offline Backup ที่พร้อมใช้งาน ทำให้การกู้คืนล่าช้า (ยิ่ง WannaCry ลบ Shadow Copy)
- การตรวจจับล่าช้าเพราะไม่มี EDR ที่ detect SMB exploitation ได้

### Sub: improvements
การปรับปรุงเพื่อป้องกันการเกิดซ้ำ:
- บังคับ Patch Management ทุก 30 วัน และ Emergency Patch ภายใน 72 ชั่วโมงสำหรับ Critical CVE
- ติดตั้ง Network Segmentation (Micro-segmentation) ห้าม Workstation คุยกันผ่าน SMB โดยตรง
- ทำ Offline Backup Drill ทุกไตรมาสเพื่อยืนยันว่า Backup กู้คืนได้จริง
- Deploy EDR ที่ครอบคลุมทุก endpoint และตั้ง Alert สำหรับ SMB exploitation และการหยุด service เป็นชุด