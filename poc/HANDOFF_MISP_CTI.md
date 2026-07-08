# Handoff: MISP/CTI Ingestion Layer

> อ่านไฟล์นี้ก่อนแก้ไขอะไรที่เกี่ยวกับ `00_fetch_misp.py` — สรุปสิ่งที่ทำไปแล้ว เหตุผล และสิ่งที่ยังไม่ได้ทดสอบจริง
> เอกสารสถาปัตยกรรมเดิม (RAG/ingest/generate) อยู่ที่ [TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md) — ไฟล์นี้เสริมเฉพาะส่วน CTI input ที่เพิ่มใหม่

## บริบท / ปัญหาที่แก้

เดิมระบบรับ input เป็น `--threat "WannaCry"` แล้ว lookup `technique_mapping.json` (ไฟล์ static เขียนมือ) เพื่อหา MITRE technique_ids
เป้าหมายคือเปลี่ยน input ให้ดึงจาก **MISP (CTI)** จริง แล้ว map เป็น ATT&CK technique อัตโนมัติ โดยต้องมี **human-in-the-loop ยืนยัน mapping ก่อน generate เสมอ** (ห้าม auto-generate จาก mapping ที่ไม่มีคนเช็ค)

## สถาปัตยกรรมใหม่ (เพิ่ม 1 stage ก่อน `02_generate.py`)

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

## ไฟล์ที่เพิ่ม/แก้

| ไฟล์ | สถานะ | หน้าที่ |
|---|---|---|
| [00_fetch_misp.py](00_fetch_misp.py) | ใหม่ | MISP fetch → galaxy/AI mapping → human review → enrichment → auto-generate |
| [02_generate.py](02_generate.py) | แก้ | เพิ่ม `--context <json>`, gate `status=="approved"`, inject `description`+IOCs เข้า prompt ทุก phase ผ่าน `intel_text` |
| [sample_misp_event.json](sample_misp_event.json) | ใหม่ | mock MISP event (WannaCry) — ใช้ทดสอบ offline ไม่ต้องมี MISP server |
| [requirements.txt](requirements.txt) | แก้ | เพิ่ม `pymisp` |
| [../.gitignore](../.gitignore) | แก้ | ignore `poc/chroma_db/`, `poc/output/`, `__pycache__/` (regenerable) |

## วิธีใช้

```bash
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

## Schema ของ `threat_context.json`

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

## สิ่งที่ทดสอบแล้ว (offline, ผ่านหมด)

- Galaxy extraction จาก Tag (`misp-galaxy:mitre-attack-pattern=...`) และ Galaxy cluster (`meta.external_id`) — ดึง T1210/T1486/T1489/T1490 จาก `sample_misp_event.json` ถูกต้อง
- `02_generate.py` ปฏิเสธ context ที่ `status="pending"` (gate ทำงานจริง)
- `02_generate.py --context ... --auto-approve` parse threat_name/technique_ids/severity ถูกต้อง (หยุดที่ missing GEMINI_API_KEY ตามคาด)
- Interactive loop: `all` → `ok` → เขียนไฟล์ approved → auto-chain เรียก `02_generate.py` จริง (หยุดที่ missing key เช่นกัน — subprocess chain ทำงาน)
- `python -m py_compile` ผ่านทั้งสองไฟล์

## สิ่งที่ยังไม่ได้ทดสอบ (ไม่มี credential ในสภาพแวดล้อมนี้)

- `load_event_live()` — เส้นทาง PyMISP จริง (ยังไม่เคยยิงกับ MISP instance จริง) โครงสร้าง JSON ที่ parser คาดหวังอิงตาม MISP REST API มาตรฐาน (`Event.Galaxy[].GalaxyCluster[].meta.external_id`, `Event.Tag[].name`) — ถ้า MISP เวอร์ชัน/config ต่างจากนี้ อาจต้องปรับ `extract_galaxy_techniques()`
- `ai_map_techniques()` และ `ai_enrich_description()` แบบยิง Gemini จริง (โค้ด logic ตรวจแล้ว แต่ไม่มี GEMINI_API_KEY ในเซสชันนี้ให้ยิงจริง)
- End-to-end กับ event ที่ Galaxy ว่างเปล่าจริง (path "AI gen ให้ครบทั้งชุด" — เทสต์ mock มี galaxy อยู่แล้วเลยไม่ได้ผ่าน path นี้)

## Known limitation / ทางเลือกที่ยังไม่ทำ

- **AI enrichment ทำงานเฉพาะใน `00_fetch_misp.py`** — ถ้า user แก้ context.json เองด้วยมือ (ไม่ผ่าน `--interactive`) แล้วเปลี่ยน `status` เป็น `approved` ตรงๆ, `description` จะไม่ถูก AI เขียนทับ (ยังคง `description_source: "event"`) เคยเสนอ user ให้ย้าย enrichment ไปทำใน `02_generate.py` แทน (เช็ค `description_source != "ai"` แล้วเขียนตอน generate) — **ยังไม่ได้ตัดสินใจ/ทำ** รอ user confirm ทิศทาง
- severity mapping จาก `threat_level_id` เป็น heuristic ง่ายๆ (`THREAT_LEVEL_MAP` ใน `00_fetch_misp.py`) — MISP ไม่มีระดับ Critical โดยตรง ตอนนี้ยกเป็น Critical เฉพาะเจอ tag ที่มีคำว่า "critical" ในชื่อ

## Git

Commit ล่าสุดที่ push: `0616568` บน branch `test-generate` (`feat: add MISP/CTI ingestion with AI mapping + human-in-the-loop`)
`poc/chroma_db/` ถูกถอดออกจาก git tracking แล้ว (ยังอยู่ใน local, ignore ใน `.gitignore`) — ถ้า clone ใหม่ต้องรัน `python 01_ingest.py` ก่อนใช้งานเพื่อ build DB ใหม่
