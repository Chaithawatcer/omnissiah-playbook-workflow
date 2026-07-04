# 📝 คู่มือการเขียน Playbook ด้วยมือ (Authoring Guide)

> เป้าหมาย: เปลี่ยนเนื้อหาใน `playbooks/*.md` ให้เป็น **ข้อมูลที่คนเขียน/คัดจากแหล่งจริง** ไม่ใช่ที่ AI generate มา
> เพราะ Knowledge Base (KB) นี้คือ "แหล่งความจริง" ที่ระบบ RAG จะดึงไปใช้ — ถ้า KB มั่ว playbook ที่ gen ออกมาก็มั่วตาม

กลยุทธ์ที่ตกลงกัน: **ผสม (Mixed)** — เล่ม/หัวข้อไหนเนื้อหาดีอยู่แล้วก็เก็บไว้ (แค่ปรับฟอร์แมต), เล่ม/หัวข้อไหนแย่หรือมั่วให้เขียนใหม่จากแหล่งอ้างอิงจริง

---

## 1. ฟอร์แมตมาตรฐาน (Canonical Format)

ใช้ [`playbooks/01_wannacry.md`](playbooks/01_wannacry.md) เป็น "ต้นแบบทองคำ" ทุกเล่มต้องหน้าตาแบบนี้:

```markdown
---
threat_name: WannaCry Ransomware
technique_ids: ["T1486", "T1190", "T1021.002"]
severity: Critical
source_doc: WannaCry_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เนื้อหา...

## Phase: detection
### Sub: log_sources [T1486, T1021.002]
- เนื้อหา...
```

### กฎที่ตัว `01_ingest.py` บังคับ (ผิดกฎ = chunk หาย/ดึงไม่เจอ)

| กฎ | รายละเอียด | ถ้าผิด |
|----|-----------|--------|
| **Frontmatter** | ขึ้นต้น+ปิดด้วย `---` มี 4 คีย์: `threat_name`, `technique_ids`, `severity`, `source_doc` | ไม่มี frontmatter → **ทั้งเล่มถูกข้าม** |
| **`technique_ids` เป็น JSON array** | ต้องใช้ **double quote** เท่านั้น เช่น `["T1486", "T1190"]` (single quote พังทันที) | crash ตอน ingest |
| **ชื่อ Phase ต้องตรงเป๊ะ 5 คำ** | `preparation` / `detection` / `containment` / `eradication` / `post_incident` (ตัวเล็กล้วน) | ❌ generator loop 5 phase นี้ — ถ้าเขียน `## Phase: Detection & Analysis` จะกลายเป็น `detection_&_analysis` แล้ว **ดึงไม่เจอ** |
| **เนื้อหาต้องอยู่ใต้ `### Sub:`** | ข้อความที่อยู่หลัง `## Phase:` แต่ก่อน `### Sub:` แรก **ถูกทิ้ง** | เนื้อหาหาย |
| **Sub ห้ามว่าง** | Sub ที่ไม่มีเนื้อหาใต้มัน จะถูกข้าม ไม่กลายเป็น chunk | chunk หาย |
| **แท็ก technique ต้องอยู่ท้ายบรรทัด Sub** | รูปแบบ `### Sub: ชื่อ [T1486, T1021.002]` — regex จับ `[...]` ที่ **ท้ายบรรทัด** เท่านั้น | แท็กไม่ถูกอ่าน |

> รูปแบบ T-code ที่ระบบรู้จัก: `Txxxx` หรือ `Txxxx.yyy` (เช่น `T1486`, `T1021.002`) ใส่หลายตัวใน `[...]` เดียวได้ คั่นด้วย comma

---

## 2. โครง Sub ต่อ Phase (Taxonomy ที่แนะนำ)

ไม่ได้บังคับตายตัว แต่แนะนำให้ยึดชุดนี้เพื่อความสม่ำเสมอ (อิงจาก wannacry + NIST 800-61):

| Phase | Sub ที่แนะนำ | หมายเหตุ |
|-------|-------------|---------|
| **preparation** | `tool_readiness`, `team_roles`, `comm_plan` | มักเป็น generic ต่อทุก threat → **ไม่ต้องแท็ก** (ให้ inherit technique ของทั้งเล่ม) |
| **detection** | `log_sources`, `ioc_list` | **แท็กต่อ technique** เมื่อ log/IOC ต่างกันตาม technique |
| **containment** | `short_term_*`, `long_term_*`, `evidence_preservation` | **แท็กต่อ technique** และ **แตก sub เมื่อขั้นตอนต่างกันตาม technique** (เช่น wannacry แยก `short_term_smb_block [T1021.002]` ออกจาก `short_term_smbv1_disable [T1190]`) |
| **eradication** | `process_removal`, `persistence_removal`, `remediation/patch_*`, `recovery_restore` | แท็กต่อ technique |
| **post_incident** | `lessons_learned`, `improvements` | generic → ไม่ต้องแท็ก |

> ⚠️ **เลิกใช้แล้ว:** `detection_queries` และ `scope_analysis` — ตกลงเอาออก (wannacry เอาออกแล้ว) เพราะเราต้องการ playbook เชิงขั้นตอนอ่านง่าย ไม่ใช่ SIEM query ดิบ ถ้าเจอใน 14 เล่มเดิมให้ลบทิ้ง หรือย่อยเนื้อหาที่มีค่าไปรวมกับ `log_sources`/`ioc_list`

---

## 3. กฎการแท็ก Technique (สำคัญที่สุด)

**ทำไมต้องแท็ก:** ป้องกัน "การดึงมั่ว" — เวลา gen playbook ที่ใช้แค่ `T1021.002` ระบบจะดึงเฉพาะ chunk ที่แท็ก `T1021.002` ไม่ไปหยิบขั้นตอนของ technique อื่นที่บังเอิญอยู่ phase เดียวกันมาปน

**กฎ:**
1. แท็กต้องเป็น **subset ของ `technique_ids` ใน frontmatter** — ถ้าแท็ก technique ที่ไม่ได้ประกาศไว้ ingest จะเตือน `⚠ แท็ก [...] ไม่อยู่ใน frontmatter`
2. **แท็กเมื่อ sub นั้นเจาะจง technique** — ถ้า sub ใช้ได้กับทุก technique ของเล่ม (เช่น team_roles) ไม่ต้องแท็ก มันจะ inherit technique ทั้งเล่มเอง (`technique_source = playbook`)
3. **ถ้าขั้นตอนของ 2 technique ต่างกันจริง ให้แตกเป็นคนละ sub** อย่ายัดรวมแล้วแท็กทั้งคู่ — เพราะเวลาดึงจะได้ตรงกว่า (ดูตัวอย่าง wannacry containment)
4. หนึ่ง sub แท็กได้หลาย technique ถ้าขั้นตอนนั้นใช้ร่วมกันจริงๆ เช่น `[T1486, T1021.002]`

---

## 4. เกณฑ์ตัดสิน "เก็บ vs เขียนใหม่" (Mixed Strategy Rubric)

ไล่ดูทีละ **sub** (ไม่ใช่ทีละเล่ม) แล้วให้คะแนนตามนี้:

**✅ เก็บได้ (แค่ปรับฟอร์แมต + แท็ก)** ถ้า sub นั้น:
- เจาะจงกับ threat/technique จริง (มีชื่อ process, event ID, tool, ขั้นตอนที่ระบุได้)
- ขั้นตอนถูกต้องตามหลัก IR และตรวจสอบกับแหล่งอ้างอิงได้
- ไม่มีข้อมูลที่ "แต่งขึ้น" (เช่น ชื่อเครื่องมือ/คำสั่งที่ไม่มีจริง)

**♻️ เขียนใหม่** ถ้า sub นั้น:
- เนื้อหากลางๆ generic ใช้กับ threat ไหนก็ได้ (สัญญาณว่า AI gen มา)
- มีคำสั่ง/tool/Event ID ที่ดูน่าสงสัยว่าแต่งขึ้น → **ต้องเช็คกับแหล่งจริงก่อน**
- ขัดกับหลัก IR (เช่น สั่ง reboot เครื่อง ransomware ทั้งที่จะทำลายหลักฐานใน RAM)

> เขียนใหม่ = คัดจากแหล่งอ้างอิงในข้อ 5 แล้วเรียบเรียงเป็นขั้นตอน ไม่ใช่ให้ AI แต่งให้

---

## 5. แหล่งอ้างอิงต่อ Phase (Sourcing Checklist)

เป้าหมาย: ทุก sub ต้อง **ground กับแหล่งจริงอย่างน้อย 1 แหล่ง** เขียนที่มากำกับไว้ (ในคอมเมนต์หรือท้าย sub ก็ได้)

### 🔧 Preparation
- **NIST SP 800-61** (Computer Security Incident Handling Guide) — โครงทีม, บทบาท, การเตรียมความพร้อม
- เอกสาร/runbook ขององค์กรเอง + คู่มือ tool จริง (EDR/SIEM/Firewall ที่ใช้)

### 🔍 Detection & Analysis
- **MITRE ATT&CK** — เปิดหน้า technique (เช่น attack.mitre.org/techniques/T1486) → อ่าน section **"Detection" / "Data Sources"** ว่า technique นี้ทิ้งร่องรอยที่ log ไหน
- **Sigma Rules** (github.com/SigmaHQ/sigma) — ดู *ว่าต้องตรวจอะไร* แล้วเรียบเรียงเป็นขั้นตอน (อย่าก็อป query ดิบมา)
- **LOLBAS / Atomic Red Team** — พฤติกรรมจริงของ technique
- Vendor threat report (Mandiant / CrowdStrike / Microsoft) — IOC และพฤติกรรมเฉพาะ threat

### 🛡️ Containment + 🧹 Eradication
- **MITRE ATT&CK — section "Mitigations" (M-codes)** ของแต่ละ technique → มาตรการรับมือที่เป็นทางการ
- **CISA Advisories** (cisa.gov/news-events/cybersecurity-advisories, โดยเฉพาะ #StopRansomware) — ขั้นตอน containment/eradication เฉพาะ threat
- Vendor IR playbook / write-up ของ threat นั้นๆ (เช่น React2Shell, WannaCry มี write-up เยอะ)

### 📚 Post-Incident
- **NIST SP 800-61 — Post-Incident Activity** — โครง lessons learned, metrics, การปรับปรุง

> 💡 ของที่ทำให้ playbook มีค่าจริงคือ **Detection + Mitigation ที่เฉพาะกับ technique** ซึ่ง ATT&CK มีให้ครบทั้งสอง section ต่อ technique อยู่แล้ว — ใช้ให้เต็มที่

---

## 6. Workflow + Checklist ก่อน Ingest

1. **เลือก threat** จาก `technique_mapping.json` (มี technique_ids + description ให้แล้ว)
2. **ตัดสิน** ทีละ sub: เก็บ / เขียนใหม่ (ข้อ 4)
3. **เขียน/คัด** เนื้อหาจากแหล่งอ้างอิง (ข้อ 5) → ใส่ที่มากำกับ
4. **แท็ก technique** ต่อ sub ตามกฎข้อ 3
5. **เช็ค checklist** ก่อน ingest:
   - [ ] frontmatter ครบ 4 คีย์, `technique_ids` เป็น JSON array double-quote
   - [ ] มีครบ 5 phase, ชื่อตรงเป๊ะ (`preparation`/`detection`/`containment`/`eradication`/`post_incident`)
   - [ ] ทุก sub มีเนื้อหา (ไม่ว่าง) และเนื้อหาอยู่ **ใต้** `### Sub:`
   - [ ] แท็กทุกตัวเป็น subset ของ frontmatter `technique_ids`
   - [ ] ไม่มี `detection_queries` / `scope_analysis` หลงเหลือ
6. **รัน** `python 01_ingest.py` → ดูว่าไม่มี ⚠ เตือน และจำนวน chunks สมเหตุสมผล
7. **Spot-check** `python 02_generate.py --threat "<ชื่อ>"` → เช็คว่า retrieval ดึงตรง + coverage เขียว

---

## 7. ตัวอย่างที่ดี (Worked Example)

จาก wannacry — สังเกตว่าแตก sub ตาม technique เพราะขั้นตอนต่างกันจริง:

```markdown
## Phase: containment
### Sub: short_term_smb_block [T1021.002]
ขั้นตอน short-term containment หยุดการแพร่กระจายผ่าน SMB:
- Isolate Host: สั่ง Host Isolation ผ่าน EDR ทันที ... ห้ามปิดเครื่อง!
- Block SMB: บล็อก Inbound/Outbound พอร์ต 445, 139 ระหว่าง VLAN
<!-- source: CISA #StopRansomware WannaCry + ATT&CK T1021.002 Mitigations -->

### Sub: short_term_smbv1_disable [T1190]
ปิดช่องโหว่ MS17-010 ระหว่าง containment ระยะสั้น:
- Disable SMBv1 ผ่าน PowerShell / GPO
<!-- source: Microsoft MS17-010 + ATT&CK T1190 Mitigations -->
```

จุดที่ทำถูก:
- ✅ 2 ขั้นตอนที่คนละ technique (T1021.002 vs T1190) → **แยกเป็นคนละ sub** ไม่ยัดรวม
- ✅ แท็กเป็น subset ของ frontmatter `["T1486", "T1190", "T1021.002"]`
- ✅ เนื้อหาเจาะจง (พอร์ต 445/139, MS17-010, ห้ามปิดเครื่อง) ไม่ generic
- ✅ ใส่ที่มากำกับ

---

*อ้างอิงต้นแบบ: `01_wannacry.md` — เขียนเล่มใหม่ให้เทียบเท่านี้แล้วรัน checklist ข้อ 6 ก่อน commit*
