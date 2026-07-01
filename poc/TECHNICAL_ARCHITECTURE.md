# ⚙️ สถาปัตยกรรมระบบ (Technical Architecture): Omnissiah RAG PoC

เอกสารนี้อธิบายเจาะลึกถึงสถาปัตยกรรมทางเทคนิคของระบบสร้าง Incident Response (IR) Playbook อัตโนมัติ (Omnissiah) ถูกเขียนขึ้นสำหรับ Engineer, SOC Analyst และ AI Agent เพื่อใช้ในการทำความเข้าใจ บำรุงรักษา หรือต่อยอด Proof of Concept (PoC) นี้

---

## 🏗️ ภาพรวมสถาปัตยกรรม (System Architecture)

ระบบนี้ใช้ไปป์ไลน์ **Retrieval-Augmented Generation (RAG)** ที่ออกแบบมาเพื่องานด้านเอกสาร Incident Response โดยเฉพาะ เป็นการเชื่อมต่อระหว่างคู่มือ IR มาตรฐาน (Knowledge Base) กับ Generative LLM เพื่อสร้าง Playbook แบบเจาะจงภัยคุกคามโดยอัตโนมัติ

### องค์ประกอบหลัก (Core Components)
1. **Knowledge Base (Markdown)**: ไฟล์ Playbook ต้นฉบับ 15 เล่มที่ทำหน้าที่เป็นแหล่งข้อมูลที่ถูกต้อง (Ground Truth)
2. **Vector Database (ChromaDB)**: ฐานข้อมูลสำหรับเก็บ Document Embeddings และ Metadata เพื่อการค้นหาด้วยความหมาย (Semantic Search) และการกรองที่แม่นยำ (Exact-match)
3. **Generative Model (Google Gemini)**: ประมวลผลบริบทที่ค้นพบร่วมกับ Prompt ที่ถูกจัดโครงสร้างมาอย่างดี เพื่อสร้างตาราง Markdown (ใช้โมเดล `gemini-flash-lite-latest` เพื่อความรวดเร็วและรองรับข้อจำกัดของ Free Tier)

---

## 🔄 การไหลของข้อมูล (Data Pipeline & Workflow)

### 1. การนำเข้าข้อมูล `01_ingest.py` (Data Ingestion)
- **Input**: ไฟล์ดิบ `.md` ในโฟลเดอร์ `playbooks/`
- **การแยกวิเคราะห์ (Parsing)**: สคริปต์ใช้ Regular Expressions (`re`) เพื่อดึงข้อมูล YAML Frontmatter (ได้แก่ `threat_name`, `technique_ids`, `severity`)
- **การตัดแบ่ง (Chunking)**: เอกสารจะถูกตัดแบ่งตามหัวข้อ Markdown (`## Phase: ...` และ `### Sub: ...`) แต่ละ Chunk จะแทน Phase หรือกระบวนการย่อยๆ (เช่น `preparation`, `detection`)
- **การทำ Embedding**: ใช้ `DefaultEmbeddingFunction` ของ ChromaDB (all-MiniLM-L6-v2) ในการแปลงข้อความ Chunk เป็น Vector Embeddings
- **การจัดเก็บ (Storage)**: Chunks จะถูกเก็บใน Collection ชื่อ `omnissiah_procedures` ที่สำคัญคือจะมีการแนบ Metadata (`phase` และ `technique_ids` แบบ String) เข้าไปในแต่ละ Chunk ด้วย

### 2. การดึงข้อมูลและเตรียมบริบท `02_generate.py` (Retrieval & Context Injection)
- **Input**: ผู้ใช้งานรันคำสั่งโดยระบุภัยคุกคามเป้าหมาย เช่น `python 02_generate.py --threat "WannaCry"`
- **การทำ Mapping**: สคริปต์จะค้นหาใน `technique_mapping.json` เพื่อหา MITRE ATT&CK Technique IDs ที่ตรงกับภัยคุกคามนั้น (เช่น WannaCry -> T1486, T1190, T1021.002)
- **กลยุทธ์การค้นหาแบบลูกผสม (Hybrid Retrieval Strategy)**: 
  - *Vector Search + Metadata Pre-filtering*: ค้นหาใน ChromaDB ด้วยข้อความ (เช่น "WannaCry preparation incident response procedure") และบังคับกรอง Metadata ขั้นแรก: `{"phase": {"$eq": "preparation"}}`
  - *Python-side Post-filtering*: เนื่องจากข้อจำกัดของฟังก์ชัน `$contains` ในอาเรย์ของ ChromaDB สคริปต์จึงดึงข้อมูลเบื้องต้นมา 30 รายการ แล้วนำมากรองซ้ำในระดับ Python โดยเช็คว่า `any(tech_id in metadata['technique_ids'] for tech_id in target_technique_ids)`
  - *ระบบสำรอง (Fallback)*: หากไม่มี technique ID ตรงกันเลย ระบบจะเปลี่ยนไปค้นหาโดยอิงจากความหมาย (Semantic) ของ `phase` เพียงอย่างเดียว

### 3. การสร้างและจัดรูปแบบผลลัพธ์ `02_generate.py` (Generation & Formatting)
- **Prompt Engineering**: สคริปต์จะวนลูปตามเทมเพลต 5 ขั้นตอน (`TEMPLATE_SECTIONS`) และแทรกข้อมูล Context ที่ค้นพบเข้าไปใน Prompt ที่กำหนดไว้อย่างตายตัว
- **การจำกัดรูปแบบผลลัพธ์ (Output Constraints)**: Prompt จะสั่ง LLM อย่างเด็ดขาดว่า:
  > *"ห้ามเกริ่นนำ ห้ามมีคำทักทาย ห้ามมีสรุปปิดท้าย ห้ามพูดคุยโต้ตอบ... ให้ตอบเฉพาะตารางและข้อมูลในรูปแบบเอกสารทางการเท่านั้น"* 
  ซึ่งบังคับให้ LLM ออกแบบผลลัพธ์เป็นตาราง Markdown 2 คอลัมน์ (`| ขั้นตอน | กระบวนการ |`) 
- **การจัดการ Rate Limit**: เพื่อแก้ปัญหาโควต้าเต็ม (Error 429) จาก Google Free Tier ระบบมีกลไกดังนี้:
  - **Pacing**: มีการหยุดรอ `time.sleep(5)` ก่อนเรียก API ทุกครั้ง เพื่อให้ความเร็วในการ Request ไม่เกินขีดจำกัด (ประมาณ 12 RPM)
  - **Exponential Backoff**: ใช้ `try-except` จับ Error `ResourceExhausted` แล้วสั่งให้ระบบหยุดรอ (Sleep) 60 วินาทีก่อนลองใหม่ (สูงสุด 5 ครั้ง)

---

## 💻 บันทึกสำหรับนักพัฒนา (Developer Notes & Extensibility)

### การอัปเกรดโมเดล AI
ปัจจุบันระบบใช้โมเดล `gemini-flash-lite-latest` ใน `02_generate.py` เพื่อหลีกเลี่ยงการติด Limit ของ Free Tier หากนำระบบนี้ไปใช้จริงในระดับ Production (และมีบัญชี Google Cloud แบบเสียเงิน) ควรเปลี่ยนไปใช้ `gemini-1.5-pro` หรือ `gemini-2.5-pro` เพื่อเพิ่มความสามารถในการวิเคราะห์เหตุผลและรองรับ Context ที่ยาวขึ้น

```python
# ในไฟล์ 02_generate.py
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-flash-lite-latest") # เปลี่ยนตรงนี้สำหรับ Production
```

### การปรับแต่งเทมเพลต Prompt
หากต้องการเปลี่ยนรูปแบบผลลัพธ์ (เช่น เปลี่ยนจากตาราง Markdown เป็นคำสั่ง CLI เพียวๆ หรือ JSON) ให้แก้ไขตัวแปร `TEMPLATE_SECTIONS` ในไฟล์ `02_generate.py` ตรงส่วน `fill_instruction`

### ระบบแจ้งเตือน Zero-Day (Zero-Day Handling)
หากขั้นตอน Retrieval ค้นหาไม่พบข้อมูลที่เกี่ยวข้องเลย (0 Chunks) ระบบจะแทรกคำเตือนอัตโนมัติ (`⚠️ คำเตือน: เนื้อหาส่วนนี้สร้างจากความรู้ทั่วไปของ AI โดยตรง...`) เข้าไปในหัวข้อนั้น เพื่อให้ผู้ใช้ทราบว่า AI กำลังใช้ข้อมูลจาก Pre-training ภายนอก ไม่ได้ใช้จาก Knowledge Base ขององค์กร
