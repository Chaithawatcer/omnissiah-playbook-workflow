# 🛡️ Omnissiah — Architecture รายละเอียดอย่างละเอียด

> ระบบเวิร์คโฟลว์อัตโนมัติสำหรับสร้าง Incident Response Playbook  
> โดยใช้ **RAG + LLM + Vector Database + n8n Workflow Automation**

> [!IMPORTANT]
> ระบบนี้เป็นแบบ **Fully Automated**
> ผู้ใช้เพียงแค่ป้อน IOC หรือชื่อภัยคุกคาม ระบบจะค้นหา สร้าง และจัดเก็บ Playbook โดยอัตโนมัติ
> โดย Pre-built Playbook Store จะเติบโตขึ้นเรื่อยๆ ทุกครั้งที่มีการโจมตีแบบใหม่เข้ามา

---

## ภาพรวมของระบบ (High-Level Overview)

```mermaid
graph TD
    user["Analyst (Human)"] -- "ป้อน IOC หรือ Threat Name" --> input["Input Form (n8n Webhook)"]
    input --> mapper["MITRE ATT&CK Mapping Engine"]
    mapper --> dedup{"Deduplication Check\n(มี Playbook แล้วหรือยัง?)"}
    dedup -- "มีแล้ว (HIT)" --> prebuilt["Pre-built Playbook Store"]
    dedup -- "ยังไม่มี (MISS)" --> parse["Parse Mastertemplate\nเป็น Section Slots"]
    parse --> loop["Per-Section Generation Loop\n(วน query → retrieve → generate\nทีละ section ตาม template)"]
    mastertemplate["Mastertemplate\n(Static File — ไม่เข้า Vector DB)"] --> parse
    vdb["Vector DB\n(Phase Procedure Docs)"] --> loop
    loop --> assemble["ประกอบทุก Section\nกลับเป็น Playbook สมบูรณ์"]
    assemble --> save["Auto-save to Pre-built Store\n(Index by Technique ID)"]
    save --> output["Playbook Output (Markdown / PDF)"]
    prebuilt --> output
```

---

## สถาปัตยกรรมแบบละเอียด (Detailed Architecture)

### Layer 1 — Input Layer (ชั้นรับข้อมูล)

ผู้ใช้ป้อนข้อมูลเพียง **2 ส่วน**:

```mermaid
graph TD
    subgraph InputLayer ["Input Layer"]
        ioc["IOC Feed\n(IP, File Hash, Domain, Alert, Log)"]
        threat["Threat Name\n(Attack Technique, Malware, CVE, Campaign)"]
    end
    ioc --> val["Input Validator & Classifier"]
    threat --> val
```

> [!WARNING]
> **ข้อควรระวังเรื่อง IOC Input:**
> อาการดิบๆ เช่น "CPU สูง" มัน ambiguous มาก อาจเป็น cryptomining (T1496), process injection (T1055)
> หรือ process ปกติก็ได้ — เป็นความสัมพันธ์ **many-to-many** ไม่ใช่ 1:1
> ทางที่ดี IOC ที่เข้าระบบควรเป็น detection ที่ผ่าน triage / มี ATT&CK tag มาแล้ว (จาก EDR/SIEM)
> ไม่ใช่ symptom ดิบที่ให้ระบบเดาเอง

---

### Layer 2 — Mapping Engine (ชั้นจับคู่ MITRE ATT&CK)

ระบบแปลง Input ให้เป็น **Technique ID** ของ MITRE ATT&CK Framework โดยอัตโนมัติ:

```mermaid
graph TD
    subgraph MappingLayer ["MITRE ATT&CK Mapping Layer"]
        kb["MITRE ATT&CK Knowledge Base\n(14 Tactics, 500+ Techniques)"]
        mapperA["IOC Mapper\n(IOC → Technique IDs)\nRule-based + ATT&CK Tag"]
        mapperB["Threat Mapper\n(Threat Name → Multiple Technique IDs)\nSemantic Search / ATT&CK API"]
    end
    kb --> mapperA
    kb --> mapperB
    mapperA --> result["Technique ID(s) List"]
    mapperB --> result
```

> [!NOTE]
> **ทั้งสองฝั่ง Map ได้หลาย Technique เหมือนกัน**
> IOC เดียวกันอาจเกี่ยวข้องกับหลาย Technique ได้ เช่น Phishing email อาจ map ได้ทั้ง T1566 และ T1204
> Threat เดียวกันยิ่ง map ได้หลาย Technique เช่น React2Shell → T1190, T1059, T1078, T1053, T1547
> Mapping ต้อง ground ด้วยแหล่งข้อมูลจริง (ATT&CK, CTI Feed) **ไม่ใช่ให้ LLM เดา**

---

### Layer 3 — Decision & Playbook Engine (ชั้นตัดสินใจและสร้าง Playbook)

หัวใจสำคัญของระบบ — ใช้ **Per-Section Generation Loop** ไม่ใช่ Generate ทั้ง Playbook ในรอบเดียว:

```mermaid
graph TD
    tid["Technique ID(s) จาก Layer 2"]

    tid --> dedup{"Deduplication Check\nค้นหาใน Pre-built Store\nด้วย Technique ID"}

    dedup -- "HIT: มี Playbook อยู่แล้ว" --> fetch["ดึง Playbook จาก Store\n(ไม่เรียก LLM ประหยัด Token)"]
    fetch --> out["Output"]

    dedup -- "MISS: ยังไม่มี Playbook" --> parse["Parse Mastertemplate\nแตกเป็น Section Slots\n(Preparation, Detection, Containment,\nEradication, Recovery, Post-Incident)"]

    parse --> loop["Per-Section Generation Loop"]

    subgraph loop_detail ["Generation Loop (วนทีละ Section)"]
        q["1. สร้าง Query เฉพาะ Section\n(ใช้ [[fill]] instruction + Technique ID)"]
        r["2. RAG Retrieve\n(Filter: phase + technique_id)"]
        g["3. LLM Generate เฉพาะ Section นั้น\n(Context + Slot Instruction + System Prompt)"]
        q --> r --> g
    end

    loop --> loop_detail
    g --> assemble["ประกอบทุก Section\nกลับเข้า Template Structure"]
    assemble --> save["Auto-save to Pre-built Store\nIndexed by Technique ID"]
    save --> out
```

> [!IMPORTANT]
> **ทำไมต้อง Generate ทีละ Section (Per-Section Loop)?**
>
> Naive RAG (retrieve รอบเดียว → generate ทั้ง Playbook รวด) มีปัญหา 3 จุด:
> 1. **Template โดนสับเป็นเศษ** — ถ้ายัด template เข้า vector DB มันจะถูก chunking จนเสียโครงสร้าง
> 2. **Top-k รอบเดียวครอบไม่ทั่ว** — chunk ของ phase ที่ relevant สูงจะเบียด phase อื่นจนหาย
> 3. **คุม output ตามรูป template ไม่ได้** — LLM จะเขียนตามใจตัวเอง ไม่ตรงตามโครงสร้างที่ต้องการ
>
> พอแยกเป็น **loop ต่อ section + filter ด้วย metadata** ทั้งสามปัญหานี้หายหมด

**กฎการ Deduplication:**
- ระบบ Match ด้วย **Technique ID** เป็นหลัก
- หากมี Playbook ที่ใช้ Technique ID เดียวกันอยู่แล้ว → ถือว่าซ้ำ → ส่งอันเก่าออกทันที
- หากไม่ซ้ำ → Generate ใหม่ → บันทึกลง Store

---

### Layer 3.5 — Mastertemplate Slot Architecture (โครงสร้าง Slot ของ Template)

Mastertemplate ไม่ใช่เอกสารให้คนอ่าน — มันคือ **spec ที่เครื่อง generator จะ parse**
แต่ละ section ประกอบด้วย 3 ส่วน:

```mermaid
graph LR
    subgraph slot ["1 Section = 1 Slot"]
        static["Static Content\n(Boilerplate ที่ไม่เปลี่ยน)"]
        dynamic["Dynamic Slot\n{{placeholder}}\n(ช่องว่างรอเติมจาก RAG)"]
        fill["Fill Instruction\n[[fill: ...]]\n(คำสั่ง per-section prompt)"]
        source["Source Filter\n[[source: phase=X, technique={ids}]]\n(metadata filter สำหรับ RAG)"]
        repeat["Repeat Marker\n[[repeat: slot_name[]]]\n(ระบุว่าแถวซ้ำได้)"]
    end
```

**Convention ที่ใช้ใน Mastertemplate:**

| Marker | ความหมาย | ตัวอย่าง |
|--------|----------|----------|
| `{{placeholder}}` | ช่องว่าง dynamic ที่ generator จะเติม | `{{threat_name}}`, `{{containment_steps}}` |
| `[[fill: ...]]` | คำสั่ง prompt สำหรับ generate section นั้น | `[[fill: เขียน containment steps เป็น numbered list]]` |
| `[[source: ...]]` | metadata filter สำหรับ RAG retrieval | `[[source: phase=containment, technique={technique_ids}]]` |
| `[[repeat: ...]]` | ระบุว่า slot นี้ทำซ้ำได้หลายแถว | `[[repeat: mitre_techniques[]]]` |

**Slot Schema ทั้งหมดที่ Generator ต้อง Parse:**

```
Header:
  threat_name              : text
  detection_sla            : text
  mitre_techniques[]       : repeating (technique_id, tactic, technique_name)

Phase 1 — Preparation:
  prep_tools[]             : repeating rows (prep_tool, prep_check_command)
  [[fill: ใส่ tool ที่ต้องใช้ + คำสั่งเช็คความพร้อม]]
  [[source: phase=preparation, technique={technique_ids}]]

Phase 2 — Detection & Analysis:
  detection[]              : repeating rows (detection_item, detection_command)
  [[fill: list สิ่งที่ต้องตรวจ + คำสั่ง/query ต่อแถว]]
  [[source: phase=detection, technique={technique_ids}]]

Phase 3 — Containment:
  containment[]            : repeating rows (containment_target, containment_steps)
  [[fill: เขียน containment steps ที่ตรงกับ technique เป็น numbered list]]
  [[source: phase=containment, technique={technique_ids}]]

Phase 4 — Eradication & Recovery:
  eradication[]            : repeating rows (eradication_action, eradication_steps)
  [[fill: เขียนขั้นตอนกำจัด root cause + กู้คืนระบบ]]
  [[source: phase=eradication, technique={technique_ids}]]

Phase 5 — Post-Incident:
  post_incident_summary    : text
  [[fill: สรุป lessons learned + improvement actions]]
```

> [!CAUTION]
> **กฎเหล็กของ Mastertemplate:**
> - Template ต้องเป็น **threat-agnostic** — ห้ามมีชื่อ threat ใดๆ hardcode อยู่ในเนื้อหา
> - ใช้ `{{threat_name}}` แทน ไม่ใช่เขียนว่า "Phishing" ตรงๆ
> - ห้ามเอาเนื้อหา procedure จริงมายัดใน template — template มีแค่โครง + placeholder + instruction
> - ชื่อ placeholder ต้องเป็น **snake_case ตัวเล็กล้วน** ไม่มีเว้นวรรค

---

### Layer 4 — n8n Workflow Orchestration (ชั้นควบคุม Workflow)

```mermaid
graph TD
    A["Webhook Node\n(รับ Input จาก User)"]
    B["MITRE Mapping Node\n(Python Script)"]
    C{"Deduplication Check Node\n(Query Pre-built Store)"}
    D["Template Parser Node\n(แตก Mastertemplate เป็น Slots)"]
    E["Per-Section Loop Node\n(วน RAG + LLM ทีละ Section)"]
    F["Assembly Node\n(ประกอบ Sections กลับเป็น Playbook)"]
    G["Auto-save Node\n(Write to Pre-built Store)"]
    H["Format Output Node\n(Markdown / PDF)"]
    I["Response Node\n(ส่ง Playbook กลับให้ User)"]

    A --> B --> C
    C -- "HIT" --> H
    C -- "MISS" --> D --> E --> F --> G --> H --> I
```

---

### Layer 5 — Data & Storage Layer (ชั้นจัดเก็บข้อมูล)

```mermaid
graph TD
    subgraph Storage ["Data & Storage Layer"]
        subgraph vdb ["Vector Database (ChromaDB / Qdrant)"]
            p1["📘 Preparation Phase Doc\nLabels: Technique IDs"]
            p2["📘 Identification & Analysis Phase Doc\nLabels: Technique IDs"]
            p3["📘 Containment Phase Doc\nLabels: Technique IDs"]
            p4["📘 Eradication Phase Doc\nLabels: Technique IDs"]
            p5["📘 Recovery Phase Doc\nLabels: Technique IDs"]
        end
        subgraph static ["Static Files (ไม่เข้า Vector DB)"]
            master["📄 Mastertemplate\n(โครงร่างมาตรฐานของ Playbook)\nส่งตรงเข้า LLM Prompt"]
        end
        subgraph store ["Pre-built Playbook Store"]
            pb["Validated Playbooks\n(Index: Technique ID → Playbook File)\nFormat: Markdown / JSON / PDF\nStorage: Local / Google Drive / DB"]
        end
    end
    vdb -- "RAG Retrieval\n(Filter by phase + technique)" --> engine["Playbook Engine (Layer 3)"]
    static -- "Direct Injection\n(ส่งตรงเป็นส่วนของ Prompt)" --> engine
    engine -- "Auto-save (Non-duplicate)" --> store
```

**กลยุทธ์การจัดเก็บเอกสาร (Document Strategy — 6 Docs Total):**

| เอกสาร | จำนวน | ที่จัดเก็บ | เหตุผล |
|--------|--------|-----------|--------|
| **Mastertemplate** | 1 ไฟล์ | Static File (ส่งตรงใน LLM Prompt) | ป้องกัน Template "ระเบิด" จาก Chunking |
| **Phase Procedure Docs** | 5 ไฟล์ | Vector Database (with Technique Labels) | ค้นหาด้วย Semantic Search + Filter by Technique ID |

> [!IMPORTANT]
> **ทำไม Mastertemplate ต้องไม่เข้า Vector DB?**
> เพราะ Vector DB จะทำ Chunking (ตัดเอกสารเป็นท่อนเล็กๆ) ซึ่งจะทำลายโครงสร้าง Template
> ทำให้ Playbook ที่ Generate ออกมามีโครงสร้างไม่สมบูรณ์ (Template "ระเบิด")
> จึงต้องส่ง Mastertemplate เข้า LLM แบบตรงๆ ผ่าน System Prompt เพื่อรักษาโครงสร้างเอกสาร

**Chunking Strategy สำหรับ Phase Procedure Docs:**

| หัวข้อ | รายละเอียด |
|--------|-----------|
| **วิธี Chunk** | ตัดตาม heading/section ของเอกสาร (ไม่ใช่ fixed token) เก็บ list ขั้นตอนให้อยู่ก้อนเดียวกัน |
| **Metadata ต่อ Chunk** | `phase` (prep/detect/contain/erad/recovery), `technique_id`, `source_doc`, `heading` |
| **การ Filter** | ใช้ **metadata filter** (phase + technique) ร่วมกับ vector similarity — ไม่ใช่ similarity อย่างเดียว |
| **ทำไมต้อง Filter** | กันไม่ให้ chunk ของ Containment โผล่ตอนกำลังเขียน Preparation แค่เพราะใกล้กันเชิงความหมาย |

**Technique Labels (Metadata) บน Phase Docs:**
- แต่ละ Phase Document จะมี Metadata ระบุ Technique IDs ที่เกี่ยวข้อง
- เมื่อ RAG Engine ค้นหา จะใช้ Technique ID จาก Layer 2 เป็นตัว Filter
- ตัวอย่าง: ถ้าได้ `T1566` (Phishing) → ดึงเฉพาะ Phase Docs ที่ Label ว่ารองรับ `T1566`
- ช่วยลด Noise ได้มาก เพราะไม่ดึง Phase Docs ที่ไม่เกี่ยวข้องกับ Technique นั้นมาใส่ Context

---

## Per-Section Generation Loop (กลไกการ Generate ทีละ Section)

นี่คือหัวใจของระบบ — ทำงานเป็น loop วนทีละ slot ตามโครงของ Mastertemplate:

```mermaid
sequenceDiagram
    autonumber
    participant Template as Mastertemplate Parser
    participant Loop as Generation Loop
    participant VDB as Vector DB
    participant LLM as LLM API

    Template->>Loop: แตก Template เป็น N Sections (Slots)

    loop สำหรับแต่ละ Section (Phase)
        Loop->>Loop: 1. สร้าง Query เฉพาะ Section<br/>(ใช้ [[fill]] + Technique ID)
        Loop->>VDB: 2. RAG Retrieve<br/>(Filter: phase=section_name, technique=ids)
        VDB-->>Loop: Return Chunks ที่ตรง Phase + Technique
        Loop->>LLM: 3. Generate Section<br/>(Slot Instruction + Retrieved Chunks + Context)
        LLM-->>Loop: Return Generated Section Content
        Loop->>Loop: 4. เก็บผลลัพธ์ของ Section นี้
    end

    Loop->>Template: 5. ประกอบทุก Section กลับเข้า Template Structure
    Template-->>Loop: Playbook สมบูรณ์
```

**ตัวอย่าง 1 รอบของ Loop (Section: Containment):**

```
Query = "containment steps for T1190 / React2Shell"
      ↓
RAG Filter = { phase: "containment", technique_id: "T1190" }
      ↓
Retrieved Chunks:
  - "Isolate affected server from network immediately..."
  - "Block exploit traffic at WAF/reverse proxy..."
      ↓
LLM Prompt = [[fill]] instruction + Retrieved Chunks + Incident Context
      ↓
Generated Output = Containment section ที่เฉพาะกับ T1190
```

---

## Playbook Document Structure (โครงสร้างเอกสารที่ Generate)

โครงสร้างมาตรฐานของเอกสาร Playbook ที่สร้างขึ้นจาก Mastertemplate:

- **📋 Header Information**
  - Playbook ID (PB-XXXX)
  - `{{threat_name}}` / Technique ID(s)
  - MITRE ATT&CK Mapping `[[repeat: mitre_techniques[]]]`
  - Severity Level (ระดับความรุนแรง)
  - Generated At / Last Updated
- **1️⃣ Preparation Phase** `[[source: phase=preparation]]`
  - Prerequisites / Required Tools `[[repeat: prep_tools[]]]`
  - Team Roles & Responsibilities
  - Initial Checklist
- **2️⃣ Identification & Analysis Phase** `[[source: phase=detection]]`
  - Detection Indicators / IOC `[[repeat: detection[]]]`
  - Log Sources to Check
  - Analysis Steps (ทีละขั้น)
  - Severity Assessment Criteria
- **3️⃣ Containment Phase** `[[source: phase=containment]]`
  - Short-term Containment (ฉุกเฉิน) `[[repeat: containment[]]]`
  - Long-term Containment
  - Evidence Preservation Steps
- **4️⃣ Eradication & Recovery Phase** `[[source: phase=eradication]]`
  - Root Cause Removal Steps `[[repeat: eradication[]]]`
  - System Hardening Actions
  - Vulnerability Patching
  - System Restoration & Verification
- **5️⃣ Post-Incident Review**
  - Lessons Learned `{{post_incident_summary}}`
  - Improvement Actions

---

## Tech Stack ที่เลือกใช้

| Component               | Technology                        | หน้าที่                                                |
|-------------------------|-----------------------------------|-------------------------------------------------------|
| **Workflow Engine**     | n8n (Self-hosted)                 | ควบคุม Flow ทั้งหมด + Per-Section Loop               |
| **LLM**                | Gemini API / OpenAI               | Generate Playbook content ทีละ Section                |
| **Vector Database**     | ChromaDB / Qdrant                 | เก็บ Embeddings ของ Procedures + Metadata Filter      |
| **Embedding Model**     | text-embedding-004 / nomic-embed  | แปลงเอกสารเป็น Vector สำหรับ Similarity Search       |
| **MITRE ATT&CK Data**  | STIX/TAXII API / Local JSON       | แหล่งข้อมูล Tactics & Techniques                      |
| **Mapping Script**      | Python                            | Rule-based + Semantic Mapping Logic                   |
| **Deduplication Logic** | Python / n8n Function Node        | ตรวจสอบ Technique ID ก่อน Generate                   |
| **Template Parser**     | Python / n8n Function Node        | Parse Mastertemplate เป็น Slots + ประกอบกลับ           |
| **Document Format**     | Markdown → PDF                   | รูปแบบ Output ของ Playbook                            |
| **Playbook Store**      | SQLite / JSON Files / Google Drive| เก็บ Pre-built Playbook ที่ Auto-saved แล้ว           |
| **Frontend**            | Simple HTML Form / n8n Form Node  | UI สำหรับ Analyst ป้อน Input                         |

---

## Data Flow แบบ Step-by-Step (Fully Automated)

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant n8n as n8n Workflow
    participant MITRE as MITRE ATT&CK Mapper
    participant Store as Pre-built Playbook Store
    participant Parser as Template Parser
    participant VDB as Vector Database (RAG)
    participant LLM as LLM API

    Analyst->>n8n: Submit Input (IOC or Threat Name)
    n8n->>MITRE: Map Input to Technique ID(s)
    MITRE-->>n8n: Return Technique ID List [T1190, T1059, ...]
    n8n->>Store: Deduplication Check (Query by Technique ID)

    alt HIT: Playbook already exists
        Store-->>n8n: Return existing Playbook
        n8n-->>Analyst: Deliver Playbook instantly
    else MISS: No existing Playbook found
        n8n->>Parser: Parse Mastertemplate into Section Slots
        Parser-->>n8n: Return Slot List with [[fill]] + [[source]]

        loop For each Section Slot
            n8n->>VDB: RAG Query (Filter: phase + technique_ids)
            VDB-->>n8n: Return Relevant Chunks
            n8n->>LLM: Generate Section (Chunks + [[fill]] instruction)
            LLM-->>n8n: Return Generated Section
        end

        n8n->>n8n: Assemble all Sections into Playbook
        n8n->>Store: Auto-save Playbook (Index by Technique ID)
        n8n-->>Analyst: Deliver Generated Playbook
    end
```

---

## กระบวนการ Self-Growing Store (การเติบโตของ Pre-built Store)

```mermaid
graph LR
    A["Threat 1 เข้ามา\n(MISS → Loop Generate → Auto-save)"] --> store["Pre-built Playbook Store\n(เริ่มต้นว่างเปล่า)"]
    B["Threat 2 เข้ามา (แบบใหม่)\n(MISS → Loop Generate → Auto-save)"] --> store
    C["Threat 1 เข้ามาซ้ำ\n(HIT → ดึงทันที ไม่เรียก LLM)"] -- "ดึงจาก Store" --> store
    D["Threat 3 เข้ามา (แบบใหม่)\n(MISS → Loop Generate → Auto-save)"] --> store
    store -- "โตขึ้นเรื่อยๆ อัตโนมัติ" --> bigstore["Pre-built Store\nครบถ้วนมากขึ้นเรื่อยๆ"]
```

> [!TIP]
> **คุม Reproducibility ด้วย:**
> - ตั้ง LLM temperature ต่ำ (0.1–0.3)
> - ใช้ template เข้มๆ กำหนดโครงสร้าง output
> - Cache ผลที่ผ่าน review แล้ว + Version Control
> - SOC ต้องการผลซ้ำได้และ trace ได้ — LLM ธรรมชาติให้ output ไม่เหมือนเดิมทุกครั้ง ต้องตั้งใจคุม

---

## ข้อควรระวังเชิงสถาปัตยกรรม (Architecture Considerations)

> [!WARNING]
> **Playbook ที่ Generate ออกมาอาจ "Generic" เกินไป**
> ถ้าเอกสาร Phase เป็นเนื้อหากลางๆ (preparation ทั่วไป) playbook ที่ได้ก็จะกลางๆ ตาม
> ของที่ทำให้ playbook มีค่าจริงคือ **detection + mitigation ที่เฉพาะกับ technique**
> ซึ่ง ATT&CK แต่ละ technique มี Detection + Mitigation ให้อยู่แล้ว ลองดึงมายัดตอน generate ด้วย

> [!WARNING]
> **Threat ใหม่ที่ยังไม่มีใคร Map**
> ATT&CK/CTI ของ CVE สดๆ อาจยังไม่มี mapping เป็นอาทิตย์
> ถ้าฝั่ง generate ไปพึ่ง LLM ล้วนๆ มันจะมั่ว
> Generate flow จะเชื่อถือได้เฉพาะ threat ที่ documented ดีแล้ว

---

## ขอบเขตที่อยู่ในระบบ / นอกระบบ

| ขอบเขต                                                          | ✅ ในระบบ | ❌ นอกระบบ |
|-----------------------------------------------------------------|----------|----------|
| รับ Input แบบ Text (IOC / Threat Name)                          | ✅       |          |
| Map กับ MITRE ATT&CK อัตโนมัติ                                  | ✅       |          |
| RAG ดึง Context จาก Vector DB อัตโนมัติ (Filter by metadata)    | ✅       |          |
| Deduplication Check ก่อน Generate                              | ✅       |          |
| Per-Section Generation Loop (วน generate ทีละ section)         | ✅       |          |
| Auto-save Playbook ที่ไม่ซ้ำลง Pre-built Store                  | ✅       |          |
| Pre-built Store โตขึ้นเองทุกครั้งที่พบ Threat ใหม่              | ✅       |          |
| Output เป็น Markdown / PDF                                      | ✅       |          |
| เชื่อมต่อกับ SIEM โดยตรง (Real-time Alert Feed)                |          | ❌       |
| Execute / Automate การแก้ไขระบบ (Remediation)                  |          | ❌       |
| Human Validation ก่อน Auto-save (ถ้าต้องการ Quality Control)   |          | ❌ (Optional) |

---

## Development Roadmap (ลำดับการพัฒนา)

| Step | งาน | เสร็จเมื่อ | หมายเหตุ |
|------|------|-----------|----------|
| **1** | ล็อค Mastertemplate + แตกเป็น Slot Structure | มี template ที่ threat-agnostic พร้อม slot markers | ✅ เสร็จแล้ว |
| **2** | เตรียม Test Case + เกณฑ์วัด | มี gold-standard playbook ไว้เทียบ | ใช้ React2Shell เป็นเคสแรก |
| **3** | Manual Fill Run (ไม่ใช้ Vector DB) | รู้ว่า prompt/template เวิร์คหรือต้องแก้ | ตอบคำถามแพงที่สุดของโปรเจกต์ |
| **4** | สร้าง Retrieval Layer | retrieve ตรงกับที่คัดมือ | chunk + metadata + embed + filter eval |
| **5** | ประกอบ Generation Loop เต็ม | ใส่ threat name แล้ว generate ได้ครบทั้งเล่ม | per-section loop + assembly |
| **6** | Mapping Layer | ใส่ชื่อ threat แล้วได้ technique list | เริ่มจาก manual table ก่อน |
| **7** | Human Review Gate + Save เข้า Library | มี playbook ผ่าน review ตัวแรกเข้า library | library เริ่มมีของให้ retrieve |
| **8** | Scale | เพิ่ม threat / template / mapping | ค่อยขยายทีหลัง |

> [!TIP]
> **วินัยที่ต้องถือตลอดทาง:**
> - ทำ **1 template / 1 threat / manual ก่อน** เสมอ
> - ทำ **generate flow ก่อน retrieve flow** (เพราะ library ยังว่าง จะ retrieve อะไรไม่ได้)
> - Mapping ต้อง **ground ด้วย table** ก่อนค่อยพึ่ง LLM
> - คุม reproducibility ด้วย **temperature ต่ำ + cache ผลที่ผ่าน review**

---

*จัดทำโดย: Omnissiah Project Team*  
*อัปเดตล่าสุด: มิถุนายน 2569*
