---
threat_name: "Technique: Service Stop (T1489)"
technique_ids: ["T1489"]
severity: Medium
source_doc: Technique_T1489_Reference_v1
---

## Phase: preparation
### Sub: baseline_services [T1489]
- จัดทำ baseline ของ critical service (DB, Exchange, backup, AV) ที่ต้องเฝ้าระวังการถูกหยุด
- เปิด audit Service Control Manager (Event ID 7036/7040) และการเรียก `net stop` / `sc stop`

### Sub: protect_services [T1489]
- ตั้ง service recovery ให้ restart อัตโนมัติ และจำกัดสิทธิ์การหยุด critical service

## Phase: detection
### Sub: service_stop_signals [T1489]
- ตรวจการหยุด critical service ผิดปกติ (Event ID 7036 → stopped) โดยเฉพาะ DB/Exchange/AV/backup
- ตรวจการเรียก `net stop`, `sc stop`, `taskkill` ต่อ service สำคัญเป็นชุด (มักทำก่อนเข้ารหัส)
- ตรวจการปิด AV/EDR service ซึ่งเป็นสัญญาณ defense evasion ก่อนโจมตี

### Sub: scope_check [T1489]
- ระบุว่า service ใดถูกหยุดบนเครื่องใดบ้าง เพื่อประเมินผลกระทบต่อบริการ

## Phase: containment
### Sub: isolate_and_hold [T1489]
- Isolate host ที่กำลังหยุด service เป็นชุด เพื่อกันความเสียหายลุกลาม
- อย่าเพิ่ง restart service ทั้งหมดจนกว่าจะยืนยันว่าเครื่องสะอาด (อาจเป็นการเปิดทางให้โจมตีต่อ)

### Sub: preserve_evidence [T1489]
- บันทึก event log การหยุด service และ process ที่สั่งหยุด

## Phase: eradication
### Sub: remove_cause [T1489]
- ยุติ process/มัลแวร์ที่สั่งหยุด service และลบ persistence ที่เกี่ยวข้อง
- ตรวจว่าไม่มี script/task ที่จะสั่งหยุด service ซ้ำ

### Sub: restore_services [T1489]
- Restart critical service ที่ถูกหยุด หลังยืนยันว่าเครื่องสะอาด และตรวจ integrity ของ service

## Phase: post_incident
### Sub: detection_tuning [T1489]
- เพิ่ม alert เมื่อ critical service ถูกหยุดเป็นชุดในเวลาสั้น
### Sub: resilience [T1489]
- ตั้ง auto-recovery ให้ critical service และทบทวนสิทธิ์การหยุด service
