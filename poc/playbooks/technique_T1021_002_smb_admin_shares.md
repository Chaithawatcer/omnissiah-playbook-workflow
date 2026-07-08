---
threat_name: "Technique: Remote Services - SMB/Windows Admin Shares (T1021.002)"
technique_ids: ["T1021.002"]
severity: High
source_doc: Technique_T1021.002_Reference_v1
---

## Phase: preparation
### Sub: smb_hardening [T1021.002]
- Disable **SMBv1** ทั้งองค์กรผ่าน Group Policy และเปิดใช้ **SMB Signing**
- จำกัด/ปิด administrative share (C$, ADMIN$, IPC$) บนเครื่องที่ไม่จำเป็น
- ทำ **network segmentation** ไม่ให้ workstation คุย SMB (445) หากันโดยตรง

### Sub: detection_readiness [T1021.002]
- เปิด audit **Event ID 5140** (network share access) และ 4624 Type 3 (network logon)
- ติดตั้ง Sysmon เพื่อ log Event ID 3 (network connection) และ process create ของ psexesvc/wmiprvse
- Deploy **LAPS** เพื่อไม่ให้ local admin password ซ้ำกันทุกเครื่อง (กัน pivot ด้วย credential เดียว)

## Phase: detection
### Sub: admin_share_access [T1021.002]
- ตรวจการเข้าถึง **ADMIN$ / C$** ผิดปกติจาก Event ID 5140 โดยเฉพาะ workstation-to-workstation
- ตรวจ 4624 Type 3 จำนวนมากจาก source เดียวไปหลายปลายทาง (pattern การกวาด SMB)
- ตรวจการ mount admin share ด้วย `net use \\host\C$`

### Sub: remote_exec_signals [T1021.002]
- ตรวจ **psexesvc.exe** ปรากฏบนเครื่องปลายทาง (ลายเซ็นของ PsExec)
- ตรวจ `wmiprvse.exe` spawn cmd/powershell (WMI remote execution over SMB)
- ตรวจ SMB traffic (445) ระหว่าง workstation ที่ไม่ใช่การเข้าถึง file server ปกติ

## Phase: containment
### Sub: block_smb [T1021.002]
- Block **SMB (445, 139)** ระหว่าง workstation-to-workstation ที่ firewall/switch ACL ทันที
- Isolate host ต้นทางและปลายทางที่พบการใช้ admin share ผิดปกติ
- ปิด administrative share ชั่วคราวบนเครื่องที่เกี่ยวข้อง

### Sub: preserve_evidence [T1021.002]
- เก็บ Security Event Log (5140, 4624, 4648) และ Sysmon จากทุกเครื่องที่เกี่ยวข้อง
- บันทึก active SMB session/connection ก่อน isolate: `net session`, `netstat -ano`
- เก็บ Zeek/SMB log ที่แสดง pattern การเข้าถึง share

## Phase: eradication
### Sub: remove_remote_exec [T1021.002]
- ลบ **psexesvc.exe** และ service ที่ PsExec สร้างบนเครื่องปลายทาง
- Kill remote shell ที่ถูกสร้างผ่าน WMI/SMB
- ตรวจและลบไฟล์/service ที่ถูก drop ผ่าน admin share

### Sub: remove_smb_persistence [T1021.002]
- ตรวจ scheduled task / service ที่ถูกสร้างบนเครื่องปลายทางผ่าน SMB
- ตรวจ registry Run key บนเครื่องที่ถูกเข้าถึงผ่าน admin share
- ยืนยันว่าไม่มี account ใหม่ถูกสร้างบนเครื่องปลายทาง

## Phase: post_incident
### Sub: segmentation_hardening [T1021.002]
- บังคับ micro-segmentation ไม่ให้ workstation คุย SMB หากันโดยตรง
- Enforce SMB Signing และปิด SMBv1 ให้ครบทุกเครื่อง

### Sub: detection_improvement [T1021.002]
- เพิ่ม SIEM detection สำหรับ workstation-to-workstation SMB และ admin share access ผิดปกติ
- ทบทวนบัญชีที่มี local admin หลายเครื่อง และลดด้วย LAPS