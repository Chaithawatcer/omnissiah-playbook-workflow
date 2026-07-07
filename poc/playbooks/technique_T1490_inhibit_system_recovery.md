---
threat_name: "Technique: Inhibit System Recovery (T1490)"
technique_ids: ["T1490"]
severity: High
source_doc: Technique_T1490_Reference_v1
---

## Phase: preparation
### Sub: backup_protection [T1490]
- มี backup แบบ offline/immutable ที่ ransomware ลบหรือแก้ไม่ได้ (แยกจาก production credential)
- จำกัดสิทธิ์การรัน vssadmin/wbadmin/bcdedit ให้เฉพาะ admin ที่จำเป็น

### Sub: audit_readiness [T1490]
- เปิด audit การเรียก vssadmin, wmic shadowcopy, wbadmin, bcdedit เพื่อจับความพยายามทำลาย recovery

## Phase: detection
### Sub: recovery_tamper_signals [T1490]
- ตรวจคำสั่งลบ Shadow Copy: `vssadmin delete shadows`, `wmic shadowcopy delete`
- ตรวจการปิด Windows recovery: `bcdedit /set recoveryenabled no`, `wbadmin delete catalog`
- ตรวจการหยุด/ปิด service ที่เกี่ยวกับ backup ก่อนการเข้ารหัส

### Sub: scope_check [T1490]
- ตรวจว่าเครื่องใดถูกลบ Shadow Copy ไปแล้วบ้าง เพื่อประเมินว่ากู้คืน local ได้หรือไม่

## Phase: containment
### Sub: protect_remaining_backup [T1490]
- ตัดการเข้าถึง backup repository จากเครื่องที่ติดเชื้อทันที เพื่อกันการลบ backup ที่เหลือ
- Isolate host ที่กำลังรันคำสั่งทำลาย recovery

### Sub: preserve_evidence [T1490]
- บันทึกคำสั่งและ process ที่ทำลาย Shadow Copy ไว้เป็นหลักฐาน

## Phase: eradication
### Sub: stop_recovery_tamper [T1490]
- ยุติ process ที่กำลังลบ Shadow Copy / ปิด recovery
- ตรวจว่าไม่มี persistence ที่จะรันคำสั่งทำลาย recovery ซ้ำ

### Sub: restore_recovery_capability [T1490]
- กู้คืนข้อมูลจาก offline/immutable backup ที่ไม่ถูกแตะต้อง
- เปิด System Protection / Shadow Copy กลับและตั้ง schedule ใหม่

## Phase: post_incident
### Sub: backup_hardening [T1490]
- บังคับ immutable/air-gapped backup และทดสอบ restore ตามรอบ
### Sub: detection_tuning [T1490]
- เพิ่ม alert ทันทีเมื่อมีการเรียก vssadmin delete / bcdedit บน endpoint
