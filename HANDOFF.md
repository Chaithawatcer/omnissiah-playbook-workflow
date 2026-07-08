# Handoff Log

> อ่านไฟล์นี้ก่อนเริ่มงานทุกครั้ง — เป็น log สรุปงานแต่ละช่วง เขียนไว้ให้ Claude/คนถัดไปเข้าใจ context ได้เร็วโดยไม่ต้องรื้อประวัติแชท
> เพิ่มหัวข้อใหม่ต่อท้ายด้านล่างเมื่อมีงานใหม่ — **ห้ามลบ/แก้ entry เก่า** เขียนหัวข้อใหม่แยกแทน (ถ้า decision เก่าเปลี่ยน ให้เขียน note ใหม่ชี้กลับไปแทนการแก้ของเดิม)
> เอกสารสถาปัตยกรรมหลัก (RAG/ingest/generate) อยู่ที่ [poc/TECHNICAL_ARCHITECTURE.md](poc/TECHNICAL_ARCHITECTURE.md)

---

## 2026-07-08 — MISP/CTI Ingestion Layer

### บริบท / ปัญหาที่แก้

เดิมระบบรับ input เป็น `--threat "WannaCry"` แล้ว lookup `poc/technique_mapping.json` (ไฟล์ static เขียนมือ) เพื่อหา MITRE technique_ids
เป้าหมายคือเปลี่ยน input ให้ดึงจาก **MISP (CTI)** จริง แล้ว map เป็น ATT&CK technique อัตโนมัติ โดยต้องมี **human-in-the-loop ยืนยัน mapping ก่อน generate เสมอ** (ห้าม auto-generate จาก mapping ที่ไม่มีคนเช็ค)

### สถาปัตยกรรมใหม่ (เพิ่ม 1 stage ก่อน `02_generate.py`)

```
MISP event (live API / mock JSON)
   → Galaxy extractor  : ดึง technique_id จาก Galaxy cluster + Tag (mitre-attack-pattern)
   → AI mapper (Gemini) : เสนอ/เสริม technique เพิ่ม; ถ้า Galaxy ว่าง → AI gen ให้ครบทั้งชุด
   → merge (galaxy=approved อัตโนมัติ, ai-only=ต้องอนุมัติ)
   → เขียน output/threat_context_<id>.json  status="pending"
   → 🧑 human review (interactive CLI: a/all/none/add/rm/ok/q)
   → กด "ok" → AI enrichment เขียน description ละเอียด (อิง technique+IOCs ที่อนุมัติแล้ว)
   → status="approved" → auto-chain เรียก 02_generate.py --context <file> ต่อทันที
```

**Design decision สำคัญ:** เลือก "review file" (เขียนไฟล์ JSON ให้ human แก้/อนุมัติ) เป็นหลัก ไม่ใช่ interactive-only เพราะ:
- ได้ audit trail (ใครอนุมัติ เมื่อไหร่ อยู่ใน `review.reviewed_by/reviewed_at`)
- resume ได้ ไม่ต้องดึง MISP ใหม่ทุกครั้งที่แก้ mapping
- `--interactive` เป็น mode เสริมที่ทำงาน "บน" ไฟล์เดียวกัน ไม่ใช่คนละ path

### ไฟล์ที่เพิ่ม/แก้

| ไฟล์ | สถานะ | หน้าที่ |
|---|---|---|
| [poc/00_fetch_misp.py](poc/00_fetch_misp.py) | ใหม่ | MISP fetch → galaxy/AI mapping → human review → enrichment → auto-generate |
| [poc/02_generate.py](poc/02_generate.py) | แก้ | เพิ่ม `--context <json>`, gate `status=="approved"`, inject `description`+IOCs เข้า prompt ทุก phase ผ่าน `intel_text` |
| [poc/sample_misp_event.json](poc/sample_misp_event.json) | ใหม่ | mock MISP event (WannaCry) — ใช้ทดสอบ offline ไม่ต้องมี MISP server |
| [poc/requirements.txt](poc/requirements.txt) | แก้ | เพิ่ม `pymisp` |
| [.gitignore](.gitignore) | แก้ | ignore `poc/chroma_db/`, `poc/output/`, `__pycache__/` (regenerable) |

### วิธีใช้

```bash
cd poc
# offline demo (ไม่ต้องมี MISP/key ใดๆ ยกเว้น GEMINI ถ้าจะ generate จริง)
python 00_fetch_misp.py --mock sample_misp_event.json --interactive

# ต่อ MISP จริง
set MISP_URL=https://misp.example.com
set MISP_KEY=<authkey จากหน้า My Profile > Auth Keys ใน MISP>
set GEMINI_API_KEY=<key>
python 00_fetch_misp.py --event-id 1337 --interactive
```

ในหน้า interactive: พิมพ์ `all` (เลือกทุกเทคนิค) แล้ว `ok` (อนุมัติ) → ระบบเขียน description ด้วย AI แล้วเรียก `02_generate.py` ต่อเองทันที

Flags เสริม: `--no-ai` (ข้าม AI mapping ใช้ galaxy อย่างเดียว), `--no-enrich` (ข้าม AI description), `--no-generate` (แค่สร้าง context ไฟล์ ไม่ต่อ generate อัตโนมัติ), `--auto-approve` (บน `02_generate.py` — ข้าม gate, ใช้เฉพาะ dev/debug)

### Schema ของ `threat_context.json`

```jsonc
{
  "status": "pending" | "approved",   // gate หลัก — 02_generate.py ปฏิเสธถ้าไม่ approved
  "threat_name": "...",
  "severity": "Critical|High|Medium|Low",
  "description": "...",               // AI enrichment เขียนทับตรงนี้หลังอนุมัติ
  "description_source": "event" | "ai",
  "source": { "type": "misp|mock", "misp_event_id", "misp_uuid", "org", "event_date", "fetched_at" },
  "mapping": [
    { "technique_id": "T1486", "name": "...", "source": "galaxy|ai|galaxy+ai|manual",
      "confidence": "high|medium|low", "reason": "...", "approved": true }
  ],
  "iocs": [ { "type", "value", "category", "comment" } ],
  "review": { "reviewed_by": null, "reviewed_at": null, "notes": "" }
}
```
เฉพาะ `mapping[].approved == true` เท่านั้นที่ถูกส่งเข้า `02_generate.py` เป็น `technique_ids`

### สิ่งที่ทดสอบแล้ว (offline, ผ่านหมด)

- Galaxy extraction จาก Tag (`misp-galaxy:mitre-attack-pattern=...`) และ Galaxy cluster (`meta.external_id`) — ดึง T1210/T1486/T1489/T1490 จาก `sample_misp_event.json` ถูกต้อง
- `02_generate.py` ปฏิเสธ context ที่ `status="pending"` (gate ทำงานจริง)
- `02_generate.py --context ... --auto-approve` parse threat_name/technique_ids/severity ถูกต้อง (หยุดที่ missing GEMINI_API_KEY ตามคาด)
- Interactive loop: `all` → `ok` → เขียนไฟล์ approved → auto-chain เรียก `02_generate.py` จริง (หยุดที่ missing key เช่นกัน — subprocess chain ทำงาน)
- `python -m py_compile` ผ่านทั้งสองไฟล์

### สิ่งที่ยังไม่ได้ทดสอบ (ไม่มี credential ในสภาพแวดล้อมนี้)

- `load_event_live()` — เส้นทาง PyMISP จริง (ยังไม่เคยยิงกับ MISP instance จริง) โครงสร้าง JSON ที่ parser คาดหวังอิงตาม MISP REST API มาตรฐาน (`Event.Galaxy[].GalaxyCluster[].meta.external_id`, `Event.Tag[].name`) — ถ้า MISP เวอร์ชัน/config ต่างจากนี้ อาจต้องปรับ `extract_galaxy_techniques()`
- `ai_map_techniques()` และ `ai_enrich_description()` แบบยิง Gemini จริง (โค้ด logic ตรวจแล้ว แต่ไม่มี GEMINI_API_KEY ในเซสชันนี้ให้ยิงจริง)
- End-to-end กับ event ที่ Galaxy ว่างเปล่าจริง (path "AI gen ให้ครบทั้งชุด" — เทสต์ mock มี galaxy อยู่แล้วเลยไม่ได้ผ่าน path นี้)

### Known limitation / ทางเลือกที่ยังไม่ทำ

- **AI enrichment ทำงานเฉพาะใน `00_fetch_misp.py`** — ถ้า user แก้ context.json เองด้วยมือ (ไม่ผ่าน `--interactive`) แล้วเปลี่ยน `status` เป็น `approved` ตรงๆ, `description` จะไม่ถูก AI เขียนทับ (ยังคง `description_source: "event"`) เคยเสนอ user ให้ย้าย enrichment ไปทำใน `02_generate.py` แทน (เช็ค `description_source != "ai"` แล้วเขียนตอน generate) — **ยังไม่ได้ตัดสินใจ/ทำ** รอ user confirm ทิศทาง
- severity mapping จาก `threat_level_id` เป็น heuristic ง่ายๆ (`THREAT_LEVEL_MAP` ใน `poc/00_fetch_misp.py`) — MISP ไม่มีระดับ Critical โดยตรง ตอนนี้ยกเป็น Critical เฉพาะเจอ tag ที่มีคำว่า "critical" ในชื่อ

### Git

Commit ที่เกี่ยวข้อง: `0616568` บน branch `test-generate` (`feat: add MISP/CTI ingestion with AI mapping + human-in-the-loop`)
`poc/chroma_db/` ถูกถอดออกจาก git tracking แล้ว (ยังอยู่ใน local, ignore ใน `.gitignore`) — ถ้า clone ใหม่ต้องรัน `python 01_ingest.py` ก่อนใช้งานเพื่อ build DB ใหม่

---

## 2026-07-08 — อัพเดท architecture.md + DB Inspector GUI + ออกแบบ 3-Input Adapters

### บริบท

เตรียมเขียน proposal ให้อาจารย์เซ็น — อัพเดท `architecture.md` ให้ตรงกับสถานะจริงของโปรเจกต์หลังงาน MISP/CTI + tiered retrieval + technique-centric playbooks ที่เข้ามาในรอบก่อนหน้า

### สิ่งที่ทำ

1. **อัพเดท [architecture.md](architecture.md)** (+134/−40):
   - เปลี่ยนปรัชญาหลักจาก "Fully Automated" → "Automated Generation + Human-in-the-loop Approval"
   - Layer 1 เขียนใหม่: input 3 ช่องทาง + 1 ทางสำรอง (User Report / SIEM Alert / IOC-CTI / Threat Name ตรง) → adapter คนละตัว → schema กลาง `threat_context.json` — เหตุผล "ทางหนีไฟ": 2 ระบบต่อกันหลวม ถ้า CTI layer พังยังเดโม generate ได้
   - Layer 1.5 อัพเดทเป็น pipeline MISP จริง (`00_fetch_misp.py`) + schema เต็ม
   - Layer 2 เพิ่มแหล่ง mapping 3 แบบ (galaxy/ai/manual) + แผน validate T-number ด้วย `mitreattack-python` (MITRE official) — MITRE Software objects เช่น WannaCry=`S0366` ดึง technique ได้ตรงๆ ลดงาน mapping มือ
   - Layer 5 เพิ่มผลปรับจากการทดลองจริง: sub-technique tagging, Hybrid KB, tiered retrieval, กฎ "Fail loudly"
   - Tech stack / Scope / Roadmap อัพเดทตามจริง พร้อมสถานะ ✅/📋 ต่อรายการ
   - เพิ่มส่วน **TI Annotation 2 ระดับ** (ฉบับทางการสำหรับคนทั่วไป / ฉบับเทคนิคสำหรับ IT) เป็น output ตามแผน — retrieve ครั้งเดียว สั่ง LLM 2 รอบคนละ audience
   - เพิ่มตาราง **ประวัติการเปลี่ยนแปลงของสถาปัตยกรรม** ท้ายเอกสาร (ใช้อ้างใน proposal ได้)
2. ทำ Streamlit GUI สำหรับเปิดดู ChromaDB ไว้ใช้ดูเองในเครื่อง (`poc/04_inspect_db.py` — **ไม่ push, อยู่ใน .gitignore**) ถ้าอยากใช้เหมือนกัน: `pip install streamlit` แล้วขอไฟล์ได้

### ออกแบบไว้แต่ยังไม่ implement (คุยกันแล้ว รอเคาะ)

- **3-Input Adapters**: SIEM alert = parse ATT&CK tag ที่มากับ alert (deterministic), IOC = MISP lookup / VT / OTX enrichment (วนกลับเข้า pipeline `00_fetch_misp.py` เดิมได้), User report = reuse `ai_map_techniques()` + บังคับ human approve — ทุกทางเขียน `threat_context.json` เดียวกัน `02_generate.py` ไม่ต้องแก้
- validate T-number ที่ AI เสนอด้วย `mitreattack-python` กันเลขแต่ง

### ⚠️ จุดที่ต้องคุยกัน (พบตอน review งานรอบ `ed0a700`)

1. **BF/RDP collision กลับมา**: `technique_mapping.json` แถว "Brute Force" ถูกเปลี่ยนกลับเป็น `[T1110.001, T1078, T1021.001]` — ขัดกับ frontmatter ใน `04_brute_force.md` ที่ยังเป็น `[T1110.001, T1110.003, T1078]` และชนกับ RDP Brute Force เหมือนก่อนแก้ใน `65f03e0` (ตั้งใจหรือเผลอ revert?)
2. **08_data_exfiltration.md / 11_dns_tunneling.md ถูกลบ** โดยไม่มี technique-centric doc มาแทน — ตอนนี้ T1041/T1048/T1071.004/T1568 ไม่มี chunk ใน KB เลย → gen 2 threat นี้จะขึ้น Zero-Day warning ทุก phase และกระทบตัวเลข "15 threats" ที่จะเขียนใน proposal

### Next steps

- เคลียร์ ⚠️ 2 ข้อกับทีมก่อนเขียน proposal
- รัน `01_ingest.py` ใหม่หลัง pull (playbook เปลี่ยนเยอะ DB เก่าไม่ตรงแล้ว)
- เขียน proposal (สถานะ: ยังไม่เริ่ม)

### Git

Commit รอบนี้อยู่บน branch `test-generate` — ดู `git log` ล่าสุด

---

## 2026-07-08 — ย้าย Human Approve Mapping ไปรวม Review Gate ท้าย (feedback อาจารย์)

### บริบท

อาจารย์ชี้ว่า human gate 2 จุด (อนุมัติ mapping ก่อน generate + review playbook หลัง generate) ทำให้งานคนซ้ำซ้อน → ปรับ design เหลือ **gate เดียวท้ายสุด**: pipeline วิ่งอัตโนมัติจนได้ playbook draft แล้ว reviewer ตรวจ mapping (พร้อมป้าย source/confidence ต่อรายการ) + เนื้อหา playbook พร้อมกันครั้งเดียว

Trade-off ที่ยอมรับ: mapping ผิด → generation เสียเที่ยว (ต้นทุนต่ำ สั่ง regenerate ได้) / หลักที่ไม่เปลี่ยน: ไม่มี playbook เป็น Verified โดยไม่ผ่านคน, ไม่ auto-execute containment/eradication

### สิ่งที่ทำ

- อัพเดท `architecture.md` ทุกจุดที่เกี่ยว: header (v1→v2→v3), overview diagram (ตัด approve gate กลางทาง), Layer 1 (คอลัมน์ "ผลต่อ Review ท้าย"), Layer 1.5 (pipeline ใหม่ + ⚠️ โค้ดยังเป็น v2), Layer 2, roadmap step 7, changelog

### ⚠️ งานที่ตามมา (ยังไม่ทำ — โค้ดยังเป็น design v2)

`00_fetch_misp.py` ยัง review ก่อน generate (interactive CLI + `status=pending` gate ใน `02_generate.py`) — ต้องปรับ:
1. auto-chain เป็น default (mapping ทุกรายการวิ่งผ่านพร้อมป้าย ไม่หยุดรอคน)
2. ป้าย source/confidence ของ mapping ต้องติดไปกับ playbook output ให้ reviewer เห็นตอนตรวจ
3. ย้ายจุดบันทึก `review.reviewed_by/reviewed_at` ไปหลัง generate

---

## 2026-07-08 — ยก TI Feed Annotation เป็น "ระบบที่ 2" ใน architecture (ทางหนีไฟ)

### บริบท

แนวคิดตั้งต้นของทีม: โปรเจกต์มี **2 ระบบจบในตัวเอง** แชร์ CTI ingestion + `threat_context.json` เดียวกัน — (1) Playbook Generator, (2) **TI Feed Annotation** = ทุกครั้งที่ TI feed เข้ามา แปะคำอธิบาย 2 ระดับอัตโนมัติ (ฉบับทางการภาษาคนทั่วไป / ฉบับเทคนิคสำหรับ IT พร้อม T-number+IOC+ลิงก์ playbook) — นี่คือ "ทางหนีไฟ": ระบบใดพังก่อนสอบ อีกระบบยังเดโมได้

เดิม architecture.md สื่อเรื่องนี้ไม่ครบ (เป็นแค่กล่อง "Output เสริม" เล็กๆ) — ยกขึ้นเป็น section เต็ม `## ระบบที่ 2 — TI Feed Annotation System` พร้อม diagram 2 ระบบ, วิธีทำ (reuse `ai_enrich_description()` pattern — LLM 2 รอบคนละ audience จาก context เดียว), และตารางสถานการณ์ทางหนีไฟ 3 แบบ + เพิ่ม branch ใน overview diagram + changelog

### สถานะ

ระบบที่ 2 ยังเป็น 📋 แผน (ยังไม่ implement) — โครงหนักๆ ที่ต้อง reuse มีครบแล้วใน `00_fetch_misp.py`
