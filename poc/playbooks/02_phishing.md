---
threat_name: Phishing
technique_ids: ["T1566.001", "T1204.002", "T1059.001"]
severity: High
source_doc: Phishing_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
เครื่องมือที่ต้องเตรียมสำหรับรับมือ Phishing:
- Email Security Gateway Console (Proofpoint / Mimecast): ค้นหาและ quarantine email ต้นเหตุ | เช็ค: เข้า portal ยืนยัน access
- PowerShell + Exchange Online Module: ดึง email headers และ attachment info | เช็ค: `Get-Command Get-MessageTrace`
- Sandbox (Any.run / Cuckoo): วิเคราะห์ไฟล์แนบในสภาพแวดล้อมที่ปลอดภัย | เช็ค: ยืนยัน API key และ quota
- EDR Console: ตรวจสอบ process ที่ spawn จาก mail client | เช็ค: ยืนยัน agent running บนเครื่องเป้าหมาย
- VirusTotal API: ตรวจสอบ file hash และ URL | เช็ค: `curl https://www.virustotal.com/api/v3/`

### Sub: team_roles
บทบาทของทีมในการรับมือ Phishing:
- L1 SOC Analyst: รับ report จากผู้ใช้หรือ Email Gateway Alert ตรวจสอบเบื้องต้นว่าเป็น Phishing จริงหรือไม่
- L2 Incident Handler: วิเคราะห์ email header, attachment, URL ใน sandbox ประเมินขอบเขต
- Email Admin: ดำเนินการ quarantine email และ recall email ที่ส่งแล้ว
- HR / Communications: แจ้งพนักงานเรื่องการโจมตีและวิธีระวังตัว

### Sub: comm_plan
แผนการสื่อสารสำหรับ Phishing incident:
- รับ report จากผู้ใช้ผ่าน: security@company.com หรือ "Report Phishing" button ใน Outlook
- ถ้าพบว่ามีผู้ใช้คลิกลิงก์หรือเปิดไฟล์: escalate ไป L2 ทันที ไม่รอ
- ถ้ามีข้อมูล credential รั่วไหล: แจ้ง IT Admin reset password ทันที

## Phase: detection
### Sub: log_sources
Log source ที่ต้องตรวจสอบสำหรับ Phishing:
- Email Gateway Log: ตรวจ sender domain, SPF/DKIM/DMARC fail, attachment type ผิดปกติ (.exe ใน .zip)
- Process Creation Log (Sysmon Event ID 1): ตรวจ child process ที่ spawn จาก outlook.exe, thunderbird.exe, winword.exe — นี่คือสัญญาณว่าผู้ใช้เปิดไฟล์แนบที่ฝัง macro
- Web Proxy Log: ตรวจ URL ที่ถูกเข้าถึงจาก user หลังได้รับ email (เวลาใกล้เคียงกัน)
- DNS Log: ตรวจ domain ที่ถูก resolve หลังเปิด email (ผิดปกติ, ใหม่, ยาวมาก)
- Authentication Log: ตรวจ login จาก IP ใหม่หลังจากเวลาที่ผู้ใช้เปิด email

### Sub: detection_queries
Detection queries สำหรับ Phishing:
- SIEM ค้นหา child process ของ mail client: `index=sysmon EventCode=1 ParentImage="*OUTLOOK.EXE" (Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*wscript.exe")`
- ค้นหา Office macro execution: `index=sysmon EventCode=1 ParentImage="*WINWORD.EXE" Image="*powershell.exe"`
- ค้นหา URL phishing ใน Proxy Log: `index=proxy status=200 domain IN (threat_intel_feed)`
- PowerShell ตรวจ email ที่ถูก report: `Get-MessageTrace -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) | Where-Object {$_.Subject -like "*urgent*"}`
- ตรวจ DMARC/SPF fail: `index=email authentication_result="fail" | stats count by sender_domain`

### Sub: ioc_list
IOC สำหรับ Phishing:
- Sender domain ที่ปลอมแปลง (typosquat): เช่น company-security@paypa1.com, hr@cornpany.com
- File extension ที่น่าสงสัยใน attachment: .exe ซ่อนใน .zip, .docm, .xlsm, .iso, .lnk
- URL ที่มีลักษณะ redirect หรือ URL shortener เชื่อมไปยัง domain ที่จดทะเบียนใหม่
- Process ที่ spawn จาก mail client: cmd.exe, powershell.exe, wscript.exe, mshta.exe
- PowerShell ที่มี encoded string: `-enc`, `-EncodedCommand`, `-ep bypass`

### Sub: scope_analysis
วิธีประเมินขอบเขตของ Phishing attack:
- ค้นหา email เดิมทั้ง inbox ขององค์กรว่ามีการส่งกี่คน: `Get-MessageTrace -SenderAddress "attacker@evil.com"`
- ตรวจสอบว่ามีผู้ใช้คนไหน click link หรือ download attachment แล้วบ้างจาก Web Proxy/Email Gateway
- ถ้ามีคนเปิด attachment: ตรวจ EDR ว่าเครื่องนั้นมี process ผิดปกติหลังจากนั้นหรือไม่
- ตรวจสอบ credential stuffing: มี login ล้มเหลวหรือ login สำเร็จจาก IP ใหม่หลังเหตุการณ์ไหม

## Phase: containment
### Sub: short_term
ขั้นตอน short-term containment สำหรับ Phishing:
- ขั้นตอนที่ 1 - Block Sender: ใช้ Email Gateway block sender address + sender domain ทันที
- ขั้นตอนที่ 2 - Quarantine Email: Recall และ Quarantine email ทั้งหมดที่ส่งถึงทุก inbox ในองค์กร
- ขั้นตอนที่ 3 - Block Malicious URL: เพิ่ม URL phishing เข้า Web Proxy Blacklist ทันที
- ขั้นตอนที่ 4 - Block Malicious Domain: เพิ่ม domain เข้า DNS Sinkhole / Firewall rule
- ขั้นตอนที่ 5 (ถ้ามีคนคลิก): Isolate เครื่องของผู้ใช้ที่คลิกลิงก์หรือเปิดไฟล์ผ่าน EDR

### Sub: long_term
Long-term containment สำหรับ Phishing:
- เพิ่ม IOC ทั้งหมด (domain, IP, hash) เข้า Threat Intelligence Feed
- บังคับ MFA บน email account ทุก account ที่อาจได้รับผลกระทบ
- Reset password ของผู้ใช้ที่อาจกรอก credential ในหน้า phishing

### Sub: evidence_preservation
การเก็บหลักฐาน Phishing:
- ดาวน์โหลด email ดิบรูปแบบ .eml พร้อม full headers ก่อน quarantine
- บันทึก screenshot ของ phishing page / attachment ก่อน takedown
- เก็บ file hash (MD5, SHA256) ของ attachment ทุกชิ้น
- Export process creation log ของเครื่องที่ผู้ใช้เปิด attachment

## Phase: eradication
### Sub: process_removal
กำจัด malware ที่อาจถูก drop หลังผู้ใช้เปิด phishing attachment:
- ค้นหาและ kill process ผิดปกติที่ spawn จาก mail client: `Get-Process | Where-Object {$_.Parent.Name -like "*outlook*"}`
- ลบ payload ที่ถูก drop ลงใน temp folder: `Remove-Item $env:TEMP\*.exe -Force`
- ตรวจสอบ startup items: `Get-CimInstance Win32_StartupCommand`

### Sub: persistence_removal
ลบ persistence ที่ malware จาก phishing ฝังไว้:
- ตรวจและลบ Registry Run key ที่ผิดปกติ: `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- ลบ Scheduled Task ที่ถูกสร้างโดย malware
- ลบ Office Macro ที่ฝังอยู่ในไฟล์ document หากยังอยู่ในระบบ

### Sub: patching
การป้องกันและกู้คืนหลัง Phishing:
- Reset password ของทุก account ที่อาจได้รับผลกระทบ โดยเฉพาะถ้ามีหน้า credential harvesting
- Enable MFA บน Email และระบบสำคัญทั้งหมด
- Update email security policy: เพิ่ม stricter DMARC/SPF/DKIM enforcement
- Train ผู้ใช้ที่ตกเป็นเหยื่อเกี่ยวกับการระวัง phishing

## Phase: post_incident
### Sub: lessons_learned
บทเรียนจากเหตุการณ์ Phishing:
- ผู้ใช้ขาดการฝึกอบรม Security Awareness ที่เพียงพอ ทำให้หลงเชื่อ email ปลอม
- Email Gateway ไม่ได้ตั้งค่า DMARC policy ให้ reject email ที่ fail SPF/DKIM
- ไม่มี MFA บน email ทำให้แม้ credential รั่วก็ยังถูก takeover ได้

### Sub: improvements
การปรับปรุงหลัง Phishing incident:
- จัด Security Awareness Training อย่างน้อยปีละ 2 ครั้ง พร้อม Phishing Simulation
- บังคับ DMARC policy เป็น p=reject สำหรับ domain ขององค์กร
- Roll out MFA บน email และระบบ critical ทุกตัวภายใน 30 วัน
- เพิ่ม Email Gateway rule สำหรับ attachment ที่เป็น .iso, .img, .lnk, .vbs, .hta
