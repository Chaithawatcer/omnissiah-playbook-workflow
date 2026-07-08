---
threat_name: "Technique: Create or Modify System Process - Windows Service (T1543.003)"
technique_ids: ["T1543.003"]
severity: High
source_doc: Technique_T1543.003_Reference_v1
---

## Phase: preparation
### Sub: baseline_services [T1543.003]
- จัดทำ baseline ของ Windows service ที่ถูกต้อง เพื่อให้ตรวจจับ service แปลกปลอมได้
- เปิด audit การสร้าง/แก้ไข service (Event ID 7045 = service ใหม่ถูกติดตั้ง)

### Sub: privilege_control [T1543.003]
- จำกัดสิทธิ์การสร้าง service ให้เฉพาะ admin และตรวจ service ที่รันด้วย SYSTEM

## Phase: detection
### Sub: new_service_signals [T1543.003]
- ตรวจ Event ID 7045: การติดตั้ง service ใหม่ที่ชื่อ/path ผิดปกติ (เช่น mssecsvc2.0, path ใน temp)
- ตรวจ service ที่ ImagePath ชี้ไปยังไฟล์ในโฟลเดอร์ผิดปกติ (AppData, Temp, Windows root)
- ตรวจการแก้ไข service ที่มีอยู่ให้ชี้ไป binary อื่น (service hijack)

### Sub: scope_check [T1543.003]
- ระบุว่ามี service แปลกปลอมเดียวกันถูกสร้างบนเครื่องใดบ้าง

## Phase: containment
### Sub: disable_service [T1543.003]
- หยุดและ disable service แปลกปลอม: `sc stop <name>` แล้ว `sc config <name> start= disabled`
- Isolate host ที่พบ service แปลกปลอม

### Sub: preserve_evidence [T1543.003]
- บันทึกค่า service (ImagePath, ชื่อ, account) และ hash ของ binary ก่อนลบ

## Phase: eradication
### Sub: remove_service [T1543.003]
- ลบ service แปลกปลอม: `sc delete <name>` และลบ binary ที่เกี่ยวข้อง
- ตรวจ registry `HKLM\SYSTEM\CurrentControlSet\Services\<name>` ว่าถูกล้างแล้ว

### Sub: verify_persistence [T1543.003]
- ตรวจว่าไม่มี persistence อื่น (Run key, task) ที่จะสร้าง service ขึ้นใหม่

## Phase: post_incident
### Sub: detection_tuning [T1543.003]
- เพิ่ม alert สำหรับ Event ID 7045 ที่ ImagePath อยู่ในโฟลเดอร์ผิดปกติ
### Sub: hardening [T1543.003]
- ทบทวนสิทธิ์การสร้าง service และ baseline service ให้เป็นปัจจุบัน
