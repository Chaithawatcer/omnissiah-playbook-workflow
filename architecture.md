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
    user["Analyst (Human)"] -- "1. ป้อน IOC/Threat Name + เลือก Flow" --> input["Input Form (n8n Webhook)"]
    input --> mapper["MITRE ATT&CK Mapping Engine"]
    mapper --> flow_select{"เลือก Flow การทำงาน"}
    
    %% Urgent Flow (Fast Path)
    flow_select -- "A. Urgent Flow (ด่วน)" --> dedup_urg{"Deduplication Check\n(หา Verified หรือ Draft)"}
    dedup_urg -- "HIT (พบ Playbook)" --> store_fetch_urg["ดึงจาก Playbook Store"]
    store_fetch_urg --> output_urg["ส่งมอบทันที\n(แปะป้าย Draft หรือ Verified)"]
    
    dedup_urg -- "MISS (ไม่มีเลย)" --> parse_urg["Parse Mastertemplate\n(Static File)"]
    parse_urg --> loop_urg["Per-Section Generation Loop\n(RAG จาก Vector DB + LLM)"]
    loop_urg --> assemble_urg["Assemble Playbook"]
    assemble_urg --> save_draft["บันทึกเข้า Store เป็น Draft"]
    save_draft --> output_urg
    save_draft --> queue_rev["ส่งงานเข้าคิวรอยืนยัน\n(Pending Review Queue)"]

    %% Standard Flow (Verified Path)
    flow_select -- "B. Standard Flow (ปกติ)" --> dedup_std{"Deduplication Check\n(หาเฉพาะ Verified)"}
    dedup_std -- "HIT (พบ Verified)" --> store_fetch_std["ดึงจาก Playbook Store"]
    store_fetch_std --> output_std["ส่งมอบ Verified Playbook"]
    
    dedup_std -- "MISS (ไม่มี/มีแค่ Draft)" --> parse_std["Parse Mastertemplate\n(Static File)"]
    parse_std --> loop_std["Per-Section Generation Loop\n(RAG จาก Vector DB + LLM)"]
    loop_std --> assemble_std["Assemble Playbook (Draft)"]
    assemble_std --> review_gate{"Human Review & Test Gate\n(n8n Form / Human Approve)"}
    
    queue_rev --> review_gate
    
    review_gate -- "แก้ไข / อนุมัติ" --> save_verified["บันทึกเข้า Store เป็น Verified"]
    save_verified --> output_std
    
    vdb["Vector DB\n(Phase Procedure Docs)"] --> loop_urg
    vdb --> loop_std
    mastertemplate["Mastertemplate\n(Static File)"] --> parse_urg
    mastertemplate --> parse_std
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

หัวใจสำคัญของระบบ — ควบคุมลำดับการค้นหา การตรวจสอบความซ้ำซ้อนด้วยสถานะ และการใช้ **Per-Section Generation Loop**:

```mermaid
graph TD
    tid["Technique ID(s) จาก Layer 2"] --> flow_select{"เช็คประเภท Flow"}
    
    %% Urgent Flow Loop
    flow_select -- "Urgent Flow" --> query_store_urg["ค้นหาใน Playbook Store"]
    query_store_urg --> check_urg{"พบ Playbook\n(Verified/Draft)?"}
    check_urg -- "Yes (HIT)" --> deliver_urg["ดึงไปใช้ทันที\n(ถ้าเป็น Draft จะแปะป้ายเตือน)"]
    check_urg -- "No (MISS)" --> parse_urg["Parse Mastertemplate\n& Run Loop"]
    parse_urg --> assemble_urg["Assemble Playbook (Draft)"]
    assemble_urg --> save_store_urg["บันทึกลง Store เป็น Draft"]
    save_store_urg --> deliver_urg
    save_store_urg --> enqueue_review["เข้าคิวรอคนตรวจ (Async)"]

    %% Standard Flow Loop
    flow_select -- "Standard Flow" --> query_store_std["ค้นหาใน Playbook Store"]
    query_store_std --> check_std{"พบ Verified Playbook?"}
    check_std -- "Yes (HIT)" --> deliver_std["ดึง Verified ไปใช้ทันที"]
    check_std -- "No (MISS/Draft Only)" --> parse_std["Parse Mastertemplate\n& Run Loop"]
    parse_std --> assemble_std["Assemble Playbook (Draft)"]
    assemble_std --> review_gate{"Human Review Gate\n(n8n Form / Edit & Approved)"}
    review_gate --> save_store_std["บันทึกลง Store เป็น Verified"]
    save_store_std --> deliver_std
```

**กฎการตัดสินใจของ Deduplication Engine:**

- **Urgent Flow (เน้นความเร็วสูงสุด):**
  1. ค้นหา `Verified Playbook` ด้วย Technique ID ใน Store -> หากเจอให้ส่งมอบทันที
  2. หากไม่เจอ `Verified` แต่เจอ `Draft Playbook` -> ดึง `Draft` มาส่งมอบทันที โดยเพิ่มแบนเนอร์แจ้งเตือนเด่นชัด: `⚠️ [DRAFT - UNVERIFIED PLAYBOOK]` เพื่อแจ้งผู้ใช้ยอมรับความเสี่ยง
  3. หากไม่พบเลย -> สร้างใหม่เป็น `Draft` -> ส่งมอบ -> บันทึกเข้าระบบเป็น `Draft` -> ส่งงานเข้าคิวรอยืนยัน (Queue) เพื่อตรวจภายหลัง
- **Standard Flow (เน้นความปลอดภัยและถูกต้อง):**
  1. ค้นหา `Verified Playbook` ด้วย Technique ID ใน Store -> หากเจอให้ส่งมอบทันที
  2. หากไม่พบ หรือพบแค่ `Draft` -> เข้าสู่ขั้นตอน Generate ใหม่ -> ส่งมอบให้คนตรวจสอบแก้ไขผ่าน Portal (n8n Form) -> บันทึกผลลัพธ์เป็น `Verified` เสมอ

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

n8n จะเป็นตัวแยกการทำงาน (Switch Node) และเก็บสถานะงานรอรีวิวด้วย Waiting Node:

```mermaid
graph TD
    A["Webhook Node\n(รับ Input + ระบุโหมด Urgent/Standard)"]
    B["MITRE Mapping Node\n(Python Script)"]
    C{"Check Flow Mode"}
    
    %% Urgent Path in n8n
    C -- "Urgent" --> D_urg["Deduplication Node\n(Query Verified & Draft)"]
    D_urg -- "HIT" --> H_urg["Deliver Node (ส่งเมล์/Slack)"]
    D_urg -- "MISS" --> E_urg["Template Parser Node"]
    E_urg --> F_urg["Per-Section Loop Node\n(LLM & RAG)"]
    F_urg --> G_urg["Assembly Node"]
    G_urg --> S_urg["Save Store Node\n(สถานะ = Draft)"]
    S_urg --> H_urg
    S_urg --> Q_urg["Enqueue Review Node\n(ส่งลิงก์ Form รอตรวจ)"]

    %% Standard Path in n8n
    C -- "Standard" --> D_std["Deduplication Node\n(Query Verified เท่านั้น)"]
    D_std -- "HIT" --> H_std["Deliver Node"]
    D_std -- "MISS" --> E_std["Template Parser Node"]
    E_std --> F_std["Per-Section Loop Node\n(LLM & RAG)"]
    F_std --> G_std["Assembly Node (Draft)"]
    G_std --> W_std["n8n Form Node / Wait Link\n(หยุดรอนักวิเคราะห์เข้ามารีวิว/แก้ไข)"]
    W_std --> S_std["Save Store Node\n(สถานะ = Verified)"]
    S_std --> H_std
    
    Q_urg --> W_std
    A --> B --> C
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
        subgraph store ["Pre-built Playbook Store (SQL / File DB)"]
            verified["✅ Verified Playbooks\n(reviewed_by: Human,\nstatus: 'Verified')"]
            drafts["📝 Draft Playbooks\n(reviewed_by: None,\nstatus: 'Draft')"]
        end
    end
    vdb -- "RAG Retrieval\n(Filter by phase + technique)" --> engine["Playbook Engine (Layer 3)"]
    static -- "Direct Injection\n(ส่งตรงเป็นส่วนของ Prompt)" --> engine
    engine -- "Save as Draft / Verified" --> store
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

**การเก็บสถานะใน Pre-built Playbook Store:**
- Playbook ทุกไฟล์ที่ถูกเก็บจะมี Metadata ประกอบด้วย:
  - `playbook_id`: รหัสเอกสาร (เช่น PB-1002)
  - `technique_id`: MITRE Technique ID
  - `status`: `Draft` หรือ `Verified` หรือ `Deprecated`
  - `created_at`: วันที่สร้าง
  - `verified_at`: วันที่ผ่านการตรวจสอบโดยคน (เว้นว่างหากสถานะเป็น Draft)
  - `verified_by`: ชื่อของนักวิเคราะห์ผู้รีวิว

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
- ช่วยลด Noise ได้มาก เพราะไม่ดึง Phase Docs ที่ไม่เกี่ยวข้องกับ Technique นั้นมาใส่ Context

---

## 🔄 Playbook Development Lifecycle (PDLC)

เพื่อแก้ไขปัญหา "สร้างเสร็จแล้วปล่อยลืม" (Generate & Forget) และรักษาความน่าเชื่อถือของเนื้อหาที่เป็นขั้นตอนปฏิบัติจริง ระบบจึงนำหลักการวงจรชีวิตของ Playbook มาบังคับใช้ โดยมีกระบวนการและสถานะการเปลี่ยนผ่านดังนี้:

```mermaid
stateDiagram-v2
    [*] --> Draft : AI Generated (MISS)
    Draft --> Verified : Human Verification & Test Gate (Approved)
    Draft --> Deprecated : Cancelled / Unused
    Verified --> Deprecated : Tactic Outdated / Overwritten
    Deprecated --> [*]
```

### 1. สถานะเอกสาร (Playbook States)
- **Draft (ฉบับร่าง):** Playbook ที่พึ่งถูกสร้างขึ้นจาก AI ยังไม่ผ่านการตรวจสอบ/ทดสอบจริงโดยคน มีความเสี่ยงที่เนื้อหาบางอย่างอาจไม่ตรงกับระบบภายในขององค์กร หรืออาจมีหลอน (Hallucination) เล็กน้อย
- **Verified (ฉบับผ่านการตรวจสอบ):** Playbook ที่ได้รับการทดสอบและรับรองความถูกต้องโดยมนุษย์ (Security Analyst) เรียบร้อยแล้ว ถือว่าเป็นเอกสารที่น่าเชื่อถือ ใช้งานในระบบผลิตจริงได้อย่างปลอดภัย
- **Deprecated (ฉบับยกเลิกใช้งาน):** Playbook ที่หมดอายุหรือถูกแทนที่ด้วยวิธีรับมือที่ดีกว่า เพื่อไม่ให้คนหยิบไปใช้ซ้ำ

### 2. วงจรการพัฒนาระหว่าง 2 Flows
- **Urgent Flow (Fast Path):**
  - เน้นบริการผู้ใช้ทันทีเมื่อมีเคสระดับวิกฤตเกิดขึ้น
  - ผลลัพธ์ที่ส่งมอบให้ผู้ใช้จะถูกทำเครื่องหมายตัวใหญ่ชัดเจนว่าเป็น **Draft (Unverified)**
  - ในเบื้องหลัง ระบบจะส่งคำขอตรวจสอบเข้าคิว **Pending Review Queue** โดยอัตโนมัติเพื่อให้คนมารีวิวภายหลัง
- **Standard Flow (Verified Path):**
  - เป็นวงจรมาตรฐานในการสร้าง Playbook ต้นแบบเก็บสะสมไว้ใน Store
  - AI จะรัน RAG และ LLM เป็นด่านแรกเพื่อสร้างโครงร่าง
  - จากนั้นจะหยุดรอ (Wait) ที่ **Human Verification Gate** (ส่ง Form ไปให้นักวิเคราะห์แก้ไขและรีวิวผ่านเว็บฟอร์ม)
  - หลังจากคนคลิกตรวจสอบและกดยืนยัน (Approve) เท่านั้น เอกสารจึงจะได้รับการบันทึกเป็นสถานะ `Verified`

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

## Data Flow แบบ Step-by-Step (Urgent vs Standard Mode)

### A. Urgent Flow (Fast Path)

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant n8n as n8n Workflow
    participant MITRE as MITRE ATT&CK Mapper
    participant Store as Playbook Store
    participant VDB as Vector Database (RAG)
    participant LLM as LLM API

    Analyst->>n8n: Submit Input (Urgent Flow requested)
    n8n->>MITRE: Map Input to Technique ID(s)
    MITRE-->>n8n: Return Technique ID List [T1190, T1059]
    n8n->>Store: Check Deduplication (Query Verified or Draft)
    
    alt HIT: Playbook already exists
        Store-->>n8n: Return Playbook (Verified or Draft)
        n8n-->>Analyst: Deliver Playbook immediately (with status flag)
    else MISS: No Playbook found
        n8n->>n8n: Parse Mastertemplate & Start Loop
        loop For each Section
            n8n->>VDB: Query (Filter: phase + technique)
            VDB-->>n8n: Return Chunks
            n8n->>LLM: Generate Section (Chunks + instruction)
            LLM-->>n8n: Return Section Content
        end
        n8n->>n8n: Assemble all Sections into Playbook
        n8n->>Store: Auto-save Playbook as 'Draft'
        n8n-->>Analyst: Deliver Playbook immediately (Labeled: DRAFT)
        n8n->>n8n: Send to Pending Review Queue (for future verification)
    end
```

### B. Standard Flow (Human-Verified Path)

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    actor Reviewer as SOC Team (Human Reviewer)
    participant n8n as n8n Workflow
    participant Store as Playbook Store
    participant VDB as Vector Database (RAG)
    participant LLM as LLM API

    Analyst->>n8n: Submit Input (Standard Flow requested)
    n8n->>Store: Check Deduplication (Query Verified only)
    
    alt HIT: Verified Playbook exists
        Store-->>n8n: Return Verified Playbook
        n8n-->>Analyst: Deliver Verified Playbook immediately
    else MISS: No Verified Playbook exists (or only Draft exists)
        n8n->>n8n: Parse Mastertemplate & Start Loop
        loop For each Section
            n8n->>VDB: Query (Filter: phase + technique)
            VDB-->>n8n: Return Chunks
            n8n->>LLM: Generate Section (Chunks + instruction)
            LLM-->>n8n: Return Section Content
        end
        n8n->>n8n: Assemble all Sections into Draft Playbook
        n8n->>Reviewer: Send Review Notification (with Web Form link)
        Note over Reviewer, n8n: n8n Workflow enters WAITING state
        Reviewer->>n8n: Review, edit content, and click 'Approve' via Form
        n8n->>Store: Save Playbook as 'Verified'
        n8n-->>Analyst: Deliver Verified Playbook
    end
```

---

## กระบวนการ Self-Growing Store (การเติบโตของ Playbook Store)

```mermaid
graph TD
    A["Threat A เข้ามา (ด่วน / Urgent)"] --> MISS_urg{"ตรวจ Store (MISS)"}
    MISS_urg --> Gen_urg["AI Gen + Delivery"]
    Gen_urg --> Save_Draft["บันทึกเข้า Store เป็น Draft"]
    
    Save_Draft --> StoreDB["Playbook Store DB"]
    
    B["Threat B เข้ามา (ปกติ / Standard)"] --> MISS_std{"ตรวจ Store (MISS)"}
    MISS_std --> Gen_std["AI Gen + Review Wait"]
    Gen_std --> Review_Gate["Human Review (n8n Form)"]
    Review_Gate --> Save_Ver["บันทึกเข้า Store เป็น Verified"]
    Save_Ver --> StoreDB
    
    %% Transition of Draft to Verified
    StoreDB -- "หยิบฉบับ Draft ใน Store ไปสกรีนทีหลัง" --> Review_Gate
    
    C["Threat เข้ามาซ้ำ (มีใน Store แล้ว)"] --> HIT{"ตรวจ Store (HIT)"}
    HIT -- "เจอ Verified" --> Deliver_Ver["ส่งมอบ Verified ทันที\n(ความปลอดภัยสูงสุด)"]
    HIT -- "เจอแต่ Draft (โหมด Urgent)" --> Deliver_Drf["ส่งมอบ Draft ทันที\n(แปะป้ายระวัง)"]
```

> [!TIP]
> **คุม Reproducibility และคุณภาพด้วย:**
> - ตั้ง LLM temperature ต่ำ (0.1–0.3) เพื่อความเสถียรของเนื้อหา
> - ใช้ Mastertemplate กำหนดกรอบของผลลัพธ์ไม่ให้หลุดขอบเขต
> - การนำระบบตรวจสอบคุณภาพโดยคนมาประยุกต์ใช้ (Human Review) จะทำให้ความถูกต้องของคลังความรู้สูงขึ้นอย่างเป็นระบบ

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
