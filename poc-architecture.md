# 🔬 PoC Code Architecture: RAG + Vector DB + LLM อธิบายจากโค้ดจริง

> เอกสารนี้อธิบาย **สิ่งที่ implement จริงใน `poc/`** (ตรงข้ามกับ [architecture.md](architecture.md) ที่เป็นภาพรวมระบบเต็ม/อนาคต — n8n, Playbook Store, Dedup ฯลฯ ซึ่งบางส่วนยังไม่ได้สร้าง)
>
> จุดประสงค์ของ PoC นี้ (ตามที่อาจารย์มอบหมาย) คือ **ศึกษาว่า RAG + Vector Database + LLM ทำงานร่วมกันยังไง** ไม่ใช่การสร้างระบบ production เอกสารนี้จึงเน้นอธิบาย "แต่ละองค์ประกอบทำหน้าที่อะไร ด้วยวิธีไหน" อ้างอิงโค้ดบรรทัดจริง

---

## ภาพรวม: 3 องค์ประกอบ ใครทำหน้าที่อะไร

```
[15 playbooks .md]
      │  (1) ตัดเป็น chunk + แปะ metadata          ← 01_ingest.py
      ▼
[Embedding model]  ข้อความ → เวกเตอร์ 384 มิติ       ← sentence-transformers (local, ไม่ใช้ API)
      ▼
[ChromaDB]  เก็บ เวกเตอร์ + ข้อความ + metadata        ← Vector DB = "ความจำที่ค้นตามความหมายได้"
      ▼
      │  (2) ตอน generate: วนทีละ phase (5 รอบ)
      │      ยิง query + filter 2 ชั้น → ได้ chunk ที่เกี่ยว   ← "R" (Retrieval) ของ RAG — query_rag()
      ▼
[Gemini LLM]  อ่าน chunk ที่ retrieve มา + คำสั่งประจำ phase
      แล้ว "เรียบเรียงใหม่" เป็นตาราง                    ← "G" (Generation) — generate_section()
      ▼
[โค้ดล้วน]  ประกอบ 5 phase เข้า template → ไฟล์ .md      ← assemble_playbook()
```

หลักการสั้นๆ: **Vector DB คือความจำ, RAG คือวิธีเลือกความรู้ที่เกี่ยวมาป้อน, LLM คือปากที่เรียบเรียง** — LLM ไม่ได้ตัดสินใจว่าจะใช้ความรู้อะไร RAG เลือกให้แล้ว LLM แค่สังเคราะห์เป็นภาษา (garbage in → garbage out)

---

## 1. Vector Database (ChromaDB) — คลังความรู้ที่ค้นด้วยความหมาย

**หน้าที่:** เก็บความรู้จาก playbook 15 เล่ม (ปัจจุบัน 200 chunks) ในรูปแบบที่ค้นหาแบบ "ความหมายใกล้เคียงกัน" ได้ ไม่ใช่แค่ค้นคำตรงตัว

**วิธีทำงาน (`01_ingest.py`):**

1. **Parse frontmatter** — อ่าน YAML header ของแต่ละไฟล์ (`threat_name`, `technique_ids`, `severity`, `source_doc`)
2. **Chunking ตามโครงสร้าง** — ตัดตาม `## Phase:` และ `### Sub:` ไม่ตัดกลางประโยค เพื่อให้ 1 ขั้นตอนอยู่ครบในก้อนเดียว (1 sub = 1 chunk)
3. **Sub-technique tagging** — ถ้าหัวข้อ sub มีแท็กท้ายบรรทัดแบบ `### Sub: log_sources [T1486, T1021.002]` ระบบจะดึง technique เฉพาะของ sub นั้นแทนที่จะใช้ technique ของทั้งเล่ม (ละเอียดกว่า ลดการดึงข้ามเล่มที่ไม่เกี่ยว)
4. **Embedding** — แปลง chunk แต่ละอันเป็นเวกเตอร์ด้วย `DefaultEmbeddingFunction` (sentence-transformers `all-MiniLM-L6-v2`) รันในเครื่อง ไม่เรียก API ข้อความที่ความหมายใกล้กันจะได้เวกเตอร์ที่ "ชี้ทิศทางใกล้กัน"
5. **จัดเก็บ** — เก็บ 3 อย่างคู่กันต่อ 1 chunk: เวกเตอร์ + ข้อความต้นฉบับ + **metadata** (`phase`, `technique_ids`, `threat_name`, `source_doc`, `technique_source`) ตั้ง distance metric เป็น cosine similarity (`hnsw:space: cosine`)

```python
collection = client.create_collection(
    name=COLLECTION_NAME,
    embedding_function=EMBEDDING_FN,
    metadata={"hnsw:space": "cosine"}
)
```

**สิ่งที่ Vector DB ทำไม่ได้:** มันไม่ "เข้าใจ" หรือ "เขียน" อะไร — แค่หาของที่เวกเตอร์ใกล้กันเท่านั้น ความถูกต้องขึ้นกับคุณภาพของ chunk + metadata ที่ป้อนเข้าไปล้วนๆ

---

## 2. RAG (Retrieval-Augmented Generation) — ตัวเลือกความรู้มาป้อน LLM

RAG ไม่ใช่ซอฟต์แวร์ตัวเดียว แต่เป็น**สถาปัตยกรรม**: "ค้นก่อน แล้วให้ LLM เขียนโดยอิงของที่ค้นได้" หัวใจอยู่ที่ `query_rag()` ใน `02_generate.py`

### กรอง 2 ชั้น (ไม่พึ่ง semantic similarity อย่างเดียว)

```python
where_filter = {"phase": {"$eq": phase}}
results = collection.query(
    query_texts=[query],
    n_results=30,                          # ดึงมาเผื่อกรองซ้ำ
    where=where_filter,                    # ชั้น 1: metadata filter (ChromaDB native)
    include=["documents", "metadatas"],
)
for doc_id, doc, meta in zip(...):
    if any(tech_id in meta["technique_ids"] for tech_id in technique_ids):  # ชั้น 2: Python filter
        retrieved_docs.append(doc)
```

- **ชั้น metadata (ChromaDB native):** กรองด้วย `where={"phase": phase}` ก่อน — เอาเฉพาะ chunk ของ phase ที่กำลังเขียนตอนนี้ (เช่น `containment`)
- **ชั้น technique (Python post-filter):** ดึงมา 30 อันดับแรกจากชั้นแรก แล้วกรองซ้ำว่า chunk นั้นมี technique ตรงกับ threat ที่กำลัง generate ไหม (ChromaDB ไม่รองรับ `$contains` บน array field ตรงๆ เลยต้องกรองฝั่ง Python)

### วนทีละ Section ไม่ใช่ยิง Query รอบเดียว (Per-Section Loop)

```python
for section in TEMPLATE_SECTIONS:      # preparation, detection, containment, eradication, post_incident
    query = f"{threat_key} {phase} incident response procedure {' '.join(technique_ids)}"
    retrieved_chunks = query_rag(collection, query, phase, technique_ids, n_results=5)
    content = generate_section(model, section, threat_key, technique_ids, retrieved_chunks, missing_techs)
```

แต่ละรอบสร้าง query เฉพาะ phase นั้น (เช่น `"WannaCry containment incident response procedure T1486 T1190 T1021.002"`) — กันไม่ให้ chunk ของ phase อื่นมาปนตอนเขียน phase ปัจจุบัน

### Coverage Check — บอกความมั่นใจของระบบตรงๆ

ก่อน generate ระบบกวาดทั้ง KB เช็คว่า technique ไหน**ไม่มี chunk รองรับเลย**:

```python
def check_technique_coverage(collection, technique_ids: list[str]) -> list[str]:
    all_meta = collection.get(include=["metadatas"])["metadatas"]
    covered = {tid for meta in all_meta for tid in technique_ids if tid in meta.get("technique_ids", "")}
    return [tid for tid in technique_ids if tid not in covered]
```

ถ้า `query_rag()` หาไม่เจอ chunk ตรง technique เลยในเฟสนั้น **ระบบคืนค่าว่างตรงๆ ไม่มี fallback ไปดึง chunk ของ threat อื่นมาแทนแบบเงียบๆ** — เพื่อให้ป้าย `⚠️ Knowledge Coverage Warning` / `Zero-Day` ขึ้นตามความจริง แทนที่ LLM จะดูมั่นใจทั้งที่ไม่มีข้อมูลรองรับ

> **บทเรียนสำคัญที่เจอระหว่างทำ:** เดิมโค้ดมี fallback แบบ "ถ้าไม่เจอ chunk ตรง technique ก็ดึง chunk ของ phase เดียวกันมาแทนเฉยๆ" (ไม่สนใจ technique) ผลคือ `retrieved_chunks` ไม่เคยว่างเลย ป้ายเตือนเลยไม่มีวันขึ้น — ทั้งที่จริงไม่มีข้อมูลรองรับ technique นั้นอยู่เลย เป็นตัวอย่างว่า **fallback ที่ออกแบบไม่ดีทำให้ระบบดู "มั่นใจ" ปลอมๆ ได้**

---

## 3. LLM (Google Gemini) — ตัวเรียบเรียง/สังเคราะห์ภาษา

**หน้าที่:** เอา chunk ดิบที่ RAG ดึงมา (bullet points จากหลายเล่ม) มาสังเคราะห์ใหม่เป็นตาราง playbook ภาษาไทยที่อ่านลื่น เฉพาะเจาะจงกับ threat ที่กำลัง generate

**วิธีทำงาน (`generate_section()`):**

```python
prompt = f"""
{section['fill_instruction']}          # คำสั่งประจำ phase เช่น "เขียนส่วน Containment เป็นตาราง 2 คอลัมน์"
**Threat:** {threat_name}
**MITRE ATT&CK Techniques:** {technique_ids}
{missing_note}                          # เตือนถ้ามี technique ที่ไม่มี KB รองรับ
**ข้อมูลอ้างอิงจาก Knowledge Base:**
{context}                               # <-- chunk ที่ RAG ดึงมา ใส่ตรงนี้
...ห้ามเกริ่นนำ ห้ามพูดคุยโต้ตอบ ให้ตอบเฉพาะตารางเท่านั้น
"""
response = model.generate_content(prompt)   # gemini-flash-lite-latest
```

- Prompt ประกอบจาก: คำสั่งของ phase + threat name + technique list + **chunk ที่ retrieve มา (context)** + กติกาการตอบที่เข้มงวด (ห้ามเกริ่น ห้ามสรุป ให้ตอบเป็นตารางเท่านั้น)
- โมเดลถูกสั่งให้ "ใช้ข้อมูลจาก KB เป็นหลัก" → ground คำตอบกับของจริงแทนที่จะดึงจากความจำภายในของโมเดลเอง
- มี retry + exponential backoff จับ error `429 / ResourceExhausted` เพื่อรับมือ Free Tier rate limit

**ข้อจำกัดที่ต้องระวัง:** LLM ไม่ตรวจสอบว่า chunk ที่ได้รับมาถูกต้องหรือเกี่ยวข้องจริงไหม — มันจะเรียบเรียงเนื้อหาที่ได้รับให้ดูดีเสมอ ต่อให้ chunk ที่ RAG ป้อนมาผิด (เช่น ดึงข้าม threat) LLM ก็จะเขียนออกมาดูน่าเชื่อถือเหมือนกัน **ความถูกต้องของผลลัพธ์สุดท้ายจึงขึ้นกับคุณภาพของขั้น Retrieval เกือบทั้งหมด ไม่ใช่ขึ้นกับ LLM**

---

## สิ่งที่ค้นพบจากการทดลอง (เชื่อมโยงทฤษฎี RAG กับพฤติกรรมจริง)

| ที่เจอ | บทเรียนเชิงหลักการ |
|---|---|
| `include=["ids"]` ทำให้ ChromaDB query พังทุกครั้ง → หลุดไป fallback แบบไม่กรอง technique เลย | **Metadata filter สำคัญกว่า semantic similarity อย่างเดียว** — ถ้า filter พัง ระบบจะเงียบๆ กลายเป็น pure semantic search ทันที โดยไม่มีใครรู้ตัว |
| แท็ก technique ระดับ "ทั้งเล่ม" ทำให้ threat ที่ใช้ technique เดียวกัน (Brute Force / RDP Brute Force มี technique set เหมือนกันทุกตัว) ดึง chunk ปนกันหนัก | **ความละเอียดของ metadata (granularity) กระทบคุณภาพการดึงโดยตรง** — ยิ่งแท็กละเอียดระดับ sub-process ยิ่งกันการดึงข้ามบริบทได้ดีขึ้น |
| Threat ชื่อกว้างๆ ("Brute Force") ถูก threat ที่ชื่อเฉพาะเจาะจงกว่า (RDP, Lateral Movement) แย่ง chunk ของตัวเองไปเกือบหมด (ก่อนแก้: 1/5, หลังแก้ mapping+เนื้อหา: 6/5) | **Semantic similarity ขึ้นกับ "anchor keyword" ใน query** — query ที่ไม่มีคำเฉพาะเจาะจงพอ จะแพ้เนื้อหาของเพื่อนบ้านที่ specific กว่า แม้เนื้อหาตัวเองมีอยู่ใน KB |
| Fallback แบบเงียบ (ไม่เจอ chunk ตรง technique ก็ดึง chunk ใกล้เคียงมาแทน) ทำให้ป้ายเตือนไม่ขึ้นทั้งที่ไม่มีข้อมูลรองรับจริง | **Fail loudly ดีกว่า fail silently** ในระบบ RAG — การ "พยายามตอบให้ได้เสมอ" มีราคาคือความน่าเชื่อถือของสัญญาณเตือน |
| Chunk ที่ retrieve ได้บางส่วนมาจาก threat อื่นเสมอ (เช่น T1078 อยู่ใน SQLi, Brute Force, Credential Dumping พร้อมกัน) | **การดึงข้าม threat ไม่ใช่บั๊กเสมอไป** ถ้า technique เดียวกันถูกใช้จริงในหลาย threat นั่นคือพฤติกรรมที่ถูกต้องของ RAG — ต้องแยกให้ออกจากกรณี "ดึงข้ามเพราะ query ไม่ specific พอ" |

---

## ไฟล์ที่เกี่ยวข้อง

| ไฟล์ | บทบาท |
|------|--------|
| [poc/01_ingest.py](poc/01_ingest.py) | Chunking + tagging + embedding + เก็บลง ChromaDB |
| [poc/02_generate.py](poc/02_generate.py) | Retrieval (`query_rag`, `check_technique_coverage`) + Generation (`generate_section`) + Assembly |
| [poc/03_test_retrieval.py](poc/03_test_retrieval.py) | ทดสอบว่า metadata filter ทำงานถูกต้องก่อนเชื่อ generation |
| [poc/technique_mapping.json](poc/technique_mapping.json) | ตาราง threat → MITRE ATT&CK technique_ids (15 threats) |
| [poc/playbooks/](poc/playbooks/) | Knowledge Base ต้นฉบับ 15 เล่ม → 200 chunks |
| [poc/AUTHORING_GUIDE.md](poc/AUTHORING_GUIDE.md) | กติกาการเขียน/แท็ก playbook ด้วยมือให้เข้ากับ pipeline นี้ |

ดูภาพรวมระบบแบบเต็ม (รวมส่วนที่ยังไม่ implement เช่น n8n, Playbook Store, Dedup) ได้ที่ [architecture.md](architecture.md)
