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
    dedup -- "ยังไม่มี (MISS)" --> rag["RAG Engine\n(Vector DB Search)\nFilter by Technique Labels"]
    rag --> llm["LLM (Gemini / OpenAI)\nGenerate Playbook"]
    mastertemplate["Mastertemplate\n(Static File — ไม่เข้า Vector DB)"] --> llm
    llm --> save["Auto-save to Pre-built Store\n(Index by Technique ID)"]
    save --> output["Playbook Output (Markdown / PDF)"]
    prebuilt --> output
```

---

## สถาปัตยกรรมแบบละเอียด (Detailed Architecture)

### Layer 1 — Input Layer (ชั้นรับข้อมูล)

ผู้ใช้ป้อนข้อมูลเพียง **2 ส่วน** (ลดจากเดิม 3 ส่วน เพราะไม่ต้องหา Context เอง):

```mermaid
graph TD
    subgraph InputLayer ["Input Layer"]
        ioc["IOC Feed\n(IP, File Hash, Domain, Alert, Log)"]
        threat["Threat Name\n(Attack Technique, Malware, CVE, Campaign)"]
    end
    ioc --> val["Input Validator & Classifier"]
    threat --> val
```

---

### Layer 2 — Mapping Engine (ชั้นจับคู่ MITRE ATT&CK)

ระบบแปลง Input ให้เป็น **Technique ID** ของ MITRE ATT&CK Framework โดยอัตโนมัติ:

```mermaid
graph TD
    subgraph MappingLayer ["MITRE ATT&CK Mapping Layer"]
        kb["MITRE ATT&CK Knowledge Base\n(14 Tactics, 500+ Techniques)"]
        mapperA["IOC Mapper\n(IOC → 1 Technique ID)\nRule-based Matching"]
        mapperB["Threat Mapper\n(Threat Name → Multiple Technique IDs)\nSemantic Search / ATT&CK API"]
    end
    kb --> mapperA
    kb --> mapperB
    mapperA --> result["Technique ID(s) List"]
    mapperB --> result
```

---

### Layer 3 — Decision & Playbook Engine (ชั้นตัดสินใจและสร้าง Playbook)

หัวใจสำคัญของระบบ ทำการตรวจสอบ สร้าง และจัดเก็บ Playbook:

```mermaid
graph TD
    tid["Technique ID(s) จาก Layer 2"]

    tid --> dedup{"Deduplication Check\nค้นหาใน Pre-built Store\nด้วย Technique ID"}

    dedup -- "HIT: มี Playbook อยู่แล้ว" --> fetch["ดึง Playbook จาก Store\n(ไม่เรียก LLM ประหยัด Token)"]
    fetch --> out["Output"]

    dedup -- "MISS: ยังไม่มี Playbook" --> rag["RAG Engine\nค้นหา Phase Procedures ที่เกี่ยวข้อง\nจาก Vector DB (Filter by Technique Labels)"]
    rag --> ctx["Context ที่ได้:\n- Phase Procedures ที่ตรงกับ Technique\n  (Filtered by Technique Labels)"]
    ctx --> llm["LLM Node\nนำ Context + Mastertemplate (Static File)\n+ System Prompt → Generate Playbook"]
    llm --> save["Auto-save to Pre-built Store\nIndexed by Technique ID"]
    save --> out
```

**กฎการ Deduplication:**
- ระบบ Match ด้วย **Technique ID** เป็นหลัก
- หากมี Playbook ที่ใช้ Technique ID เดียวกันอยู่แล้ว → ถือว่าซ้ำ → ส่งอันเก่าออกทันที
- หากไม่ซ้ำ → Generate ใหม่ → บันทึกลง Store

---

### Layer 4 — n8n Workflow Orchestration (ชั้นควบคุม Workflow)

```mermaid
graph TD
    A["Webhook Node\n(รับ Input จาก User)"]
    B["MITRE Mapping Node\n(Python Script)"]
    C{"Deduplication Check Node\n(Query Pre-built Store)"}
    D["RAG Node\n(Vector DB Similarity Search)"]
    E["LLM Node\n(Gemini / OpenAI API)"]
    F["Auto-save Node\n(Write to Pre-built Store)"]
    G["Format Output Node\n(Markdown / PDF)"]
    H["Response Node\n(ส่ง Playbook กลับให้ User)"]

    A --> B --> C
    C -- "HIT" --> G
    C -- "MISS" --> D --> E --> F --> G --> H
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
    vdb -- "RAG Retrieval\n(Filter by Technique Labels)" --> engine["Playbook Engine (Layer 3)"]
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

**Technique Labels (Metadata) บน Phase Docs:**
- แต่ละ Phase Document จะมี Metadata ระบุ Technique IDs ที่เกี่ยวข้อง
- เมื่อ RAG Engine ค้นหา จะใช้ Technique ID จาก Layer 2 เป็นตัว Filter
- ตัวอย่าง: ถ้าได้ `T1566` (Phishing) → ดึงเฉพาะ Phase Docs ที่ Label ว่ารองรับ `T1566`
- ช่วยลด Noise ได้มาก เพราะไม่ดึง Phase Docs ที่ไม่เกี่ยวข้องกับ Technique นั้นมาใส่ Context

---

## Playbook Document Structure (โครงสร้างเอกสารที่ Generate)

โครงสร้างมาตรฐานของเอกสาร Playbook ที่สร้างขึ้นจาก Mastertemplate:

- **📋 Header Information**
  - Playbook ID (PB-XXXX)
  - Threat Name / Technique ID
  - MITRE ATT&CK Mapping
  - Severity Level (ระดับความรุนแรง)
  - Generated At / Last Updated
- **1️⃣ Preparation Phase**
  - Prerequisites / Required Tools
  - Team Roles & Responsibilities
  - Initial Checklist
- **2️⃣ Identification & Analysis Phase**
  - Detection Indicators / IOC
  - Log Sources to Check
  - Analysis Steps (ทีละขั้น)
  - Severity Assessment Criteria
- **3️⃣ Containment Phase**
  - Short-term Containment (ฉุกเฉิน)
  - Long-term Containment
  - Evidence Preservation Steps
- **4️⃣ Eradication Phase**
  - Root Cause Removal Steps
  - System Hardening Actions
  - Vulnerability Patching
- **5️⃣ Recovery Phase**
  - System Restoration Steps
  - Verification & Testing
  - Return to Normal Operations
- **6️⃣ Post-Incident Review**
  - Lessons Learned
  - Improvement Actions

---

## Tech Stack ที่เลือกใช้

| Component               | Technology                        | หน้าที่                                                |
|-------------------------|-----------------------------------|-------------------------------------------------------|
| **Workflow Engine**     | n8n (Self-hosted)                 | ควบคุม Flow ทั้งหมดแบบอัตโนมัติ                       |
| **LLM**                | Gemini API / OpenAI               | Generate Playbook content                             |
| **Vector Database**     | ChromaDB / Qdrant                 | เก็บ Embeddings ของ Procedures สำหรับ RAG              |
| **Embedding Model**     | text-embedding-004 / nomic-embed  | แปลงเอกสารเป็น Vector สำหรับ Similarity Search       |
| **MITRE ATT&CK Data**  | STIX/TAXII API / Local JSON       | แหล่งข้อมูล Tactics & Techniques                      |
| **Mapping Script**      | Python                            | Rule-based + Semantic Mapping Logic                   |
| **Deduplication Logic** | Python / n8n Function Node        | ตรวจสอบ Technique ID ก่อน Generate                   |
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
    participant VDB as Vector Database (RAG)
    participant LLM as LLM API

    Analyst->>n8n: Submit Input (IOC or Threat Name)
    n8n->>MITRE: Map Input to Technique ID(s)
    MITRE-->>n8n: Return Technique ID List [T1566, T1059, ...]
    n8n->>Store: Deduplication Check (Query by Technique ID)

    alt HIT: Playbook already exists
        Store-->>n8n: Return existing Playbook
        n8n-->>Analyst: Deliver Playbook instantly
    else MISS: No existing Playbook found
        n8n->>VDB: RAG Query (Filter by Technique Labels)
        VDB-->>n8n: Return Phase Procedures (Filtered by Labels)
        n8n->>LLM: Send Context + Mastertemplate (Static File) + System Prompt
        LLM-->>n8n: Return Generated Playbook
        n8n->>Store: Auto-save Playbook (Index by Technique ID)
        n8n-->>Analyst: Deliver Generated Playbook
    end
```

---

## กระบวนการ Self-Growing Store (การเติบโตของ Pre-built Store)

```mermaid
graph LR
    A["Threat 1 เข้ามา\n(MISS → Generate → Auto-save)"] --> store["Pre-built Playbook Store\n(เริ่มต้นว่างเปล่า)"]
    B["Threat 2 เข้ามา (แบบใหม่)\n(MISS → Generate → Auto-save)"] --> store
    C["Threat 1 เข้ามาซ้ำ\n(HIT → ดึงทันที ไม่เรียก LLM)"] -- "ดึงจาก Store" --> store
    D["Threat 3 เข้ามา (แบบใหม่)\n(MISS → Generate → Auto-save)"] --> store
    store -- "โตขึ้นเรื่อยๆ อัตโนมัติ" --> bigstore["Pre-built Store\nครบถ้วนมากขึ้นเรื่อยๆ"]
```

---

## ขอบเขตที่อยู่ในระบบ / นอกระบบ

| ขอบเขต                                                          | ✅ ในระบบ | ❌ นอกระบบ |
|-----------------------------------------------------------------|----------|----------|
| รับ Input แบบ Text (IOC / Threat Name)                          | ✅       |          |
| Map กับ MITRE ATT&CK อัตโนมัติ                                  | ✅       |          |
| RAG ดึง Context จาก Vector DB อัตโนมัติ                         | ✅       |          |
| Deduplication Check ก่อน Generate                              | ✅       |          |
| Generate Playbook ด้วย LLM อัตโนมัติ                           | ✅       |          |
| Auto-save Playbook ที่ไม่ซ้ำลง Pre-built Store                  | ✅       |          |
| Pre-built Store โตขึ้นเองทุกครั้งที่พบ Threat ใหม่              | ✅       |          |
| Output เป็น Markdown / PDF                                      | ✅       |          |
| เชื่อมต่อกับ SIEM โดยตรง (Real-time Alert Feed)                |          | ❌       |
| Execute / Automate การแก้ไขระบบ (Remediation)                  |          | ❌       |
| Human Validation ก่อน Auto-save (ถ้าต้องการ Quality Control)   |          | ❌ (Optional) |

---

*จัดทำโดย: Omnissiah Project Team*  
*อัปเดตล่าสุด: มิถุนายน 2569*
