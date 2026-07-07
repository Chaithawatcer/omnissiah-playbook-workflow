---
threat_name: "Technique: Data Encrypted for Impact (T1486)"
technique_ids: ["T1486"]
severity: Critical
source_doc: Technique_T1486_Reference_v1
---

## Phase: preparation
### Sub: backup_strategy [T1486]
- จัดทำ backup แบบ 3-2-1 และต้องมีสำเนา **offline / immutable** อย่างน้อย 1 ชุดที่ ransomware เข้าถึงไม่ได้
- ทดสอบ restore จริงเป็นระยะ (restore drill) เพื่อยืนยันว่ากู้คืนได้ภายใน RTO ที่กำหนด
- แยกสิทธิ์ backup account ออกจาก domain admin เพื่อป้องกันการลบ backup เมื่อถูก compromise

### Sub: detection_readiness [T1486]
- เปิด EDR behavioral rule สำหรับ mass file modification และการเข้ารหัสไฟล์จำนวนมากในเวลาสั้น
- วาง **canary / honeyfile** ในโฟลเดอร์สำคัญ เพื่อ trigger alert เมื่อถูกแก้ไข
- เปิด audit การลบ Volume Shadow Copy (vssadmin/wmic) ซึ่งเป็นพฤติกรรมก่อนเข้ารหัสของ ransomware หลายตระกูล

## Phase: detection
### Sub: mass_encryption_signals [T1486]
- ตรวจ **อัตราการแก้ไขไฟล์ผิดปกติ** (file write/rename rate สูงผิดปกติ) จาก EDR/File Audit
- ตรวจการเปลี่ยนนามสกุลไฟล์เป็น extension แปลก หรือการเพิ่ม header/marker ของการเข้ารหัส
- ตรวจการปรากฏของ **ransom note** (ไฟล์ .txt/.html ซ้ำกันทุกโฟลเดอร์)

### Sub: pre_encryption_behavior [T1486]
- ตรวจการลบ Shadow Copy: `vssadmin delete shadows`, `wmic shadowcopy delete`
- ตรวจการปิด service ที่เกี่ยวกับ backup/AV ก่อนเข้ารหัส
- ตรวจ process ที่เปิดไฟล์จำนวนมากพร้อม read+write (pattern ของ encryptor)

## Phase: containment
### Sub: stop_encryption [T1486]
- **Isolate host ทันที** (EDR isolate / ตัด network) ห้ามปิดเครื่อง เพื่อรักษา encryption key ที่อาจอยู่ใน RAM
- Kill process ที่กำลังเข้ารหัสทันที และ suspend ก่อน kill ถ้า EDR รองรับ (เผื่อ dump key)
- ตัดการเข้าถึง network share/mapped drive เพื่อหยุดการเข้ารหัสไฟล์บน server กลาง

### Sub: preserve_key_evidence [T1486]
- ทำ **RAM dump** ของเครื่องที่กำลังเข้ารหัส (encryption key อาจยังอยู่ใน memory)
- เก็บตัวอย่าง encryptor binary + ransom note เพื่อวิเคราะห์ตระกูลและหาตัวถอดรหัส (เช่น No More Ransom)
- บันทึก timestamp เริ่ม-สิ้นสุดการเข้ารหัส เพื่อประเมินขอบเขตไฟล์ที่เสียหาย

## Phase: eradication
### Sub: remove_ransomware [T1486]
- ลบ encryptor binary และไฟล์ที่เกี่ยวข้องออกจากทุกเครื่องที่ติด
- ลบ persistence ที่ ransomware ใช้ (Scheduled Task, Run key, service)
- สแกนทั้งระบบด้วย EDR/AV offline scan เพื่อยืนยันว่าไม่มี payload ค้าง

### Sub: recovery_from_backup [T1486]
- กู้คืนไฟล์จาก **offline/immutable backup** ที่ยืนยันว่าสะอาด (ห้ามใช้ backup ที่ต่ออยู่ตอนถูกโจมตี)
- Re-image เครื่องที่ติดเชื้อแล้วค่อยกู้ข้อมูล ไม่ควรกู้ทับเครื่องเดิม
- อย่าจ่ายค่าไถ่โดยไม่ประเมิน — ตรวจว่ามี decryptor สาธารณะสำหรับ ransomware ตระกูลนั้นก่อน

## Phase: post_incident
### Sub: backup_hardening [T1486]
- บังคับใช้ immutable/air-gapped backup และทดสอบ restore ตามรอบ
- แยก credential ของระบบ backup ออกจาก production domain โดยเด็ดขาด

### Sub: detection_tuning [T1486]
- ปรับ EDR rule ให้จับ mass file modification และการลบ Shadow Copy ได้เร็วขึ้น
- เพิ่ม canary file และ alert ให้ครอบคลุม file server ที่เป็นเป้าหมายหลัก