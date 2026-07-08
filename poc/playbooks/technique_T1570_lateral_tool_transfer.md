---
threat_name: "Technique: Lateral Tool Transfer (T1570)"
technique_ids: ["T1570"]
severity: High
source_doc: Technique_T1570_Reference_v1
---

## Phase: preparation
### Sub: monitoring_readiness [T1570]
- เปิด audit การเขียนไฟล์ executable ข้ามเครื่องผ่าน SMB (Event ID 5145 บน file share) และ admin share
- ติดตั้ง Sysmon Event ID 11 (file create) เพื่อจับการวางไฟล์ใหม่จาก remote source

### Sub: segmentation [T1570]
- จำกัด workstation-to-workstation file transfer ผ่าน SMB ด้วย segmentation

## Phase: detection
### Sub: file_transfer_signals [T1570]
- ตรวจการคัดลอกไฟล์ executable ไปยังเครื่องอื่นผ่าน SMB (445) โดยเฉพาะไปยัง ADMIN$/C$
- ตรวจการปรากฏของไฟล์เดียวกัน (hash เดียวกัน) บนหลายเครื่องในเวลาไล่เลี่ยกัน — ลายเซ็นของ worm/tool transfer
- ตรวจ Sysmon Event ID 11 ที่สร้างไฟล์จาก process ที่รับ network connection

### Sub: propagation_scope [T1570]
- Map ว่าไฟล์ถูกกระจายไปกี่เครื่อง เพื่อประเมินขอบเขตการแพร่
- ระบุเครื่องต้นทางที่เป็นแหล่งกระจาย

## Phase: containment
### Sub: block_transfer [T1570]
- Block SMB (445, 139) ระหว่างเครื่องเพื่อหยุดการคัดลอกไฟล์เพิ่ม
- Isolate เครื่องต้นทางที่กระจายไฟล์
- ปิด administrative share ชั่วคราวบนเครื่องที่เกี่ยวข้อง

### Sub: preserve_evidence [T1570]
- เก็บตัวอย่างไฟล์ที่ถูกกระจาย พร้อม hash เพื่อใช้ค้นหาบนเครื่องอื่น
- เก็บ SMB/file-share log ที่แสดงเส้นทางการกระจาย

## Phase: eradication
### Sub: remove_transferred_files [T1570]
- ลบไฟล์ที่ถูกกระจายออกจากทุกเครื่อง (ค้นด้วย hash ที่เก็บไว้)
- ตรวจและลบ scheduled task/service ที่ไฟล์เหล่านั้นสร้างไว้

### Sub: verify_clean [T1570]
- สแกนซ้ำทั้ง network เพื่อยืนยันว่าไม่มีสำเนาไฟล์หลงเหลือ

## Phase: post_incident
### Sub: detection_improvement [T1570]
- เพิ่ม SIEM rule จับการวางไฟล์ executable ข้ามเครื่องผ่าน admin share
### Sub: hardening [T1570]
- Enforce segmentation และปิด admin share ที่ไม่จำเป็น
