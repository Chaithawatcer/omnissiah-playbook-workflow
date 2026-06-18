# 🛡️ Omnissiah — Architecture รายละเอียดอย่างละเอียด

> ระบบเวิร์คโฟลว์กึ่งอัตโนมัติสำหรับสร้าง Incident Response Playbook  
> โดยใช้ LLM + Google NotebookLM (Knowledge Base) + n8n Workflow Automation

> [!IMPORTANT]
> ระบบนี้เป็นแบบ **Semi-Automated (Human-in-the-Loop)**  
> Analyst จะเป็นผู้ค้นหา Context จาก **Google NotebookLM** แล้วป้อนเข้าสู่ n8n เอง  
> เนื่องจาก NotebookLM ไม่มี Public API สำหรับเรียกใช้อัตโนมัติ

---

## ภาพรวมของระบบ (High-Level Overview)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Google NotebookLM                                   │
│        (เก็บ Template + Procedure Docs ทุก Phase)                       │
└────────────────────────────┬────────────────────────────────────────────┘
                             │  Analyst ค้นหา Context ด้วยตัวเอง
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Analyst (Human)                                 │
│   รับ Context จาก NotebookLM → Copy ใส่ใน Input Form ของระบบ           │
└────────────────────────────┬────────────────────────────────────────────┘
                             │  Input (3 ส่วน)
               ┌─────────────┼─────────────┐
               ▼             ▼             ▼
     [IOC / Alert Feed]  [Threat Name]  [Context จาก NotebookLM]
      เช่น CPU สูง        เช่น           (Procedure / Template
      Network ผิดปกติ     react2shell     ที่ Analyst คัดมา)
               │             │
               ▼             ▼
     ┌──────────────────────────────┐
     │   MITRE ATT&CK Mapping Engine│
     │   (1:1 หรือ 1:Many)          │
     └──────────────┬───────────────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
  [Pre-built Playbook]   [LLM Generate]
  (ดึงมาแสดงทันที)       (Context + Template
                          → Generate ใหม่)
          │                   │
          └─────────┬─────────┘
                    ▼
         ┌────────────────────┐
         │   Playbook Output   │
         │ (Markdown / PDF)    │
         └────────────────────┘
```

---

## สถาปัตยกรรมแบบละเอียด (Detailed Architecture)

### Layer 1 — Input Layer (ชั้นรับข้อมูล)

```
┌──────────────────────────────────────────────────────────┐
│                     INPUT LAYER                          │
│                                                          │
│  ┌─────────────────────────┐  ┌──────────────────────┐  │
│  │     Mode A: IOC Feed    │  │  Mode B: Threat Name │  │
│  │  ─────────────────────  │  │  ──────────────────  │  │
│  │  • IP Address           │  │  • ชื่อ Attack        │  │
│  │  • File Hash (MD5/SHA)  │  │    Technique         │  │
│  │  • Domain Name          │  │  • ชื่อ Malware       │  │
│  │  • Alert Description    │  │  • Campaign Name     │  │
│  │  • SIEM Alert Text      │  │  • CVE Number        │  │
│  │  • Log Snippet          │  │                      │  │
│  └─────────────────────────┘  └──────────────────────┘  │
│                    │                      │              │
│                    ▼                      ▼              │
│           ┌──────────────────────────────────┐           │
│           │    Input Validator & Classifier  │           │
│           │  (ตรวจสอบ format + จำแนก Mode)  │           │
│           └──────────────────────────────────┘           │
└──────────────────────────────────────────────────────────┘
```

---

### Layer 2 — Mapping Engine (ชั้นจับคู่ MITRE ATT&CK)

```
┌──────────────────────────────────────────────────────────┐
│                  MITRE ATT&CK MAPPING LAYER              │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              MITRE ATT&CK Knowledge Base            │ │
│  │  ┌────────────────────┐  ┌────────────────────────┐ │ │
│  │  │  Tactics (14)      │  │  Techniques (500+)     │ │ │
│  │  │  ─────────────     │  │  ──────────────────    │ │ │
│  │  │  • Reconnaissance  │  │  • T1566 (Phishing)    │ │ │
│  │  │  • Initial Access  │  │  • T1059 (Cmd Script)  │ │ │
│  │  │  • Execution       │  │  • T1078 (Valid Acct)  │ │ │
│  │  │  • Persistence     │  │  • T1003 (OS Cred)     │ │ │
│  │  │  • ...             │  │  • ...                 │ │ │
│  │  └────────────────────┘  └────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌──────────────────────┐  ┌──────────────────────────┐  │
│  │  Mode A Mapper       │  │  Mode B Mapper           │  │
│  │  ──────────────────  │  │  ──────────────────────  │  │
│  │  IOC → 1 Technique   │  │  Threat → [T1, T2, T3…]  │  │
│  │  (Rule-based Match)  │  │  (Semantic Search + API) │  │
│  └──────────┬───────────┘  └─────────────┬────────────┘  │
│             │                            │               │
│             ▼                            ▼               │
│    [Technique ID Found]       [Technique ID List Found]  │
└──────────────────────────────────────────────────────────┘
```

---

### Layer 3 — Playbook Retrieval & Generation Engine

```
┌──────────────────────────────────────────────────────────────────────┐
│              PLAYBOOK ENGINE LAYER                                   │
│                                                                      │
│    ┌─────────────────────────────────────────────────────────────┐   │
│    │             👤 HUMAN-IN-THE-LOOP STEP                       │   │
│    │                                                             │   │
│    │   Analyst เปิด Google NotebookLM แยกต่างหาก               │   │
│    │   → ถามหา Procedure ของ Technique ที่ Map ได้               │   │
│    │   → NotebookLM ตอบด้วย Context จากเอกสารที่อัปโหลดไว้      │   │
│    │   → Analyst คัดลอก Context ที่เกี่ยวข้องมา                 │   │
│    └──────────────────────────┬──────────────────────────────────┘   │
│                               │  Context (Text) จาก Analyst          │
│         Mode A Path           ▼            Mode B Path               │
│  ┌─────────────────┐  ┌───────────────┐  ┌─────────────────────────┐ │
│  │ Pre-built        │  │  Context Input│  │  LLM Generation Engine  │ │
│  │ Playbook Store  │  │  (จาก NB LM)  │  │  ─────────────────────  │ │
│  │ ───────────────  │  └──────┬────────┘  │  รับ:                   │ │
│  │ • เก็บแบบ File  │         │           │  • Context จาก NotebookLM│ │
│  │   หรือ DB ง่ายๆ │         └───────────▶  • Mastertemplate        │ │
│  │ • Index ด้วย    │                     │  • System Prompt         │ │
│  │   Technique ID  │                     │  → Generate Playbook     │ │
│  │ • ดึง Playbook  │                     └─────────────┬───────────┘ │
│  │   มาแสดงทันที  │                                   │              │
│  └────────┬─────── ┘                                  │              │
│           └──────────────────────────┬─────────────────┘              │
│                                      ▼                                │
│                        ┌─────────────────────────┐                    │
│                        │   Playbook Output Layer  │                    │
│                        └─────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────────┘
```

---

### Layer 4 — n8n Workflow Orchestration (ชั้นควบคุม Workflow)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    n8n WORKFLOW ORCHESTRATION                       │
│                                                                     │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────────────┐  │
│  │  Webhook │──▶│ Classify │──▶│  Route   │──▶│  Sub-Workflow  │  │
│  │  Node    │   │  Node    │   │  (IF)    │   │  Mode A / B    │  │
│  │ (รับInput)│  │(จำแนก   │   │  Node    │   │                │  │
│  │          │   │  Mode)   │   │          │   │                │  │
│  └──────────┘   └──────────┘   └──────────┘   └────────────────┘  │
│                                                         │           │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │           │
│  │  Format  │◀──│  LLM     │◀──│  RAG     │◀───────────┘           │
│  │  Output  │   │  Node    │   │  Node    │                        │
│  │  Node    │   │(Gemini / │   │(Vector   │                        │
│  │          │   │ OpenAI)  │   │ Search)  │                        │
│  └────┬─────┘   └──────────┘   └──────────┘                        │
│       │                                                             │
│       ▼                                                             │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │   Output Node: ส่งผลลัพธ์กลับ (JSON / Markdown / PDF)        │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Layer 5 — Data & Storage Layer (ชั้นจัดเก็บข้อมูล)

```
┌──────────────────────────────────────────────────────────────────────┐
│                    DATA & STORAGE LAYER                              │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  ☁️  Google NotebookLM  (Knowledge Base หลัก)               │    │
│  │  ────────────────────────────────────────────────────────    │    │
│  │  • Mastertemplate (โครงสร้าง Playbook)                      │    │
│  │  • Preparation Phase Docs (แยกตาม Attack Type)              │    │
│  │  • Identify & Analysis Phase Docs                           │    │
│  │  • Containment Phase Docs                                   │    │
│  │  • Eradication Phase Docs                                   │    │
│  │  • MITRE ATT&CK Reference Docs                              │    │
│  │  • Analyst ค้นหาผ่าน UI ของ NotebookLM เอง                 │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  📁 Pre-built Playbook Repository (Local / Cloud Storage)   │    │
│  │  ────────────────────────────────────────────────────────    │    │
│  │  • Playbook สำเร็จรูปที่ผ่านการ validate แล้ว (Mode A)      │    │
│  │  • Index ด้วย Technique ID (T1566, T1059, …)                │    │
│  │  • Format: Markdown / JSON / PDF                            │    │
│  │  • เก็บใน Google Drive / Local Folder / Simple DB           │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Playbook Document Structure (โครงสร้างเอกสารที่ Generate)

```
┌─────────────────────────────────────────────────────┐
│            PLAYBOOK OUTPUT STRUCTURE                │
│         (จาก Mastertemplate + Phase Docs)           │
├─────────────────────────────────────────────────────┤
│  📋 Header                                          │
│  ├─ Playbook ID (PB-XXXX)                           │
│  ├─ Threat Name / Technique ID                      │
│  ├─ MITRE ATT&CK Mapping                            │
│  ├─ Severity Level                                  │
│  └─ Last Updated                                    │
├─────────────────────────────────────────────────────┤
│  1️⃣  Preparation Phase                              │
│  ├─ Prerequisites / Required Tools                  │
│  ├─ Team Roles & Responsibilities                   │
│  └─ Initial Checklist                               │
├─────────────────────────────────────────────────────┤
│  2️⃣  Identification & Analysis Phase                │
│  ├─ Detection Indicators (IOC)                      │
│  ├─ Log Sources to Check                            │
│  ├─ Analysis Steps (ทีละขั้น)                       │
│  └─ Severity Assessment Criteria                    │
├─────────────────────────────────────────────────────┤
│  3️⃣  Containment Phase                              │
│  ├─ Short-term Containment (ฉุกเฉิน)                │
│  ├─ Long-term Containment                           │
│  └─ Evidence Preservation Steps                     │
├─────────────────────────────────────────────────────┤
│  4️⃣  Eradication Phase                              │
│  ├─ Root Cause Removal Steps                        │
│  ├─ System Hardening Actions                        │
│  └─ Vulnerability Patching                          │
├─────────────────────────────────────────────────────┤
│  5️⃣  Recovery Phase                                 │
│  ├─ System Restoration Steps                        │
│  ├─ Verification & Testing                          │
│  └─ Return to Normal Operations                     │
├─────────────────────────────────────────────────────┤
│  6️⃣  Post-Incident Review                           │
│  ├─ Lessons Learned                                 │
│  └─ Improvement Actions                             │
└─────────────────────────────────────────────────────┘
```

---

## Tech Stack ที่เลือกใช้

| Component               | Technology                        | หน้าที่                                          |
|-------------------------|-----------------------------------|--------------------------------------------------|
| **Workflow Engine**     | n8n (Self-hosted)                 | ควบคุม Flow ทั้งหมด                              |
| **LLM**                | Gemini API / OpenAI               | Generate Playbook content                        |
| **Knowledge Base**      | Google NotebookLM ☁️              | เก็บและค้นหา Procedure/Template Docs            |
| **MITRE ATT&CK Data**  | STIX/TAXII API / Local JSON       | แหล่งข้อมูล Techniques                           |
| **Backend Script**      | Python                            | Mapping Logic, API Calls                         |
| **Document Format**     | Markdown → PDF                   | รูปแบบ Output ของ Playbook                       |
| **Frontend (Optional)** | Simple HTML Form / n8n Form Node | UI สำหรับ Analyst ป้อน Input + Context          |
| **Playbook Store**      | Google Drive / Local Folder       | เก็บ Pre-built Playbook ที่ validate แล้ว        |

---

## Data Flow แบบ Step-by-Step (Semi-Automated)

```
╔══════════════════════════════════════════════════════════════════╗
║              🔵 PHASE 1: Analyst Prep (ทำก่อน)                 ║
╚══════════════════════════════════════════════════════════════════╝

STEP 1: Analyst เปิด Google NotebookLM
        → ถามหา Procedure ที่ตรงกับ Threat / Technique
        → อ่านและคัดลอก Context ที่เกี่ยวข้อง (Preparation / Identify / Containment / Eradication)
        │
        ▼
STEP 2: Analyst ได้ Context เป็น Text กลับมา

╔══════════════════════════════════════════════════════════════════╗
║              🟢 PHASE 2: n8n Automated Pipeline                ║
╚══════════════════════════════════════════════════════════════════╝

STEP 3: Analyst กรอก Input Form (บน n8n หรือ Simple Web UI)
        ├─ ช่อง 1: IOC / Alert หรือ Threat Name
        ├─ ช่อง 2: Context ที่คัดมาจาก NotebookLM
        └─ ช่อง 3: เลือก Mode (A = Pre-built / B = Generate)
        │
        ▼
STEP 4: Input Validator Node (n8n)
        ตรวจสอบ Format + จำแนก Mode
        │
        ▼ (Mode A)                          ▼ (Mode B)
STEP 5A: MITRE Mapping (1:1)           STEP 5B: MITRE Mapping (1:Many)
         IOC → Technique ID                     Threat → [T1, T2, T3…]
         │                               │
         ▼                               ▼
STEP 6A: ค้นหา Pre-built Playbook      STEP 6B: LLM Node (n8n)
         จาก Playbook Store                     รับ Input:
         ด้วย Technique ID                      - Context จาก Analyst (NotebookLM)
         → ดึง Playbook ทันที                   - Mastertemplate
                                                - System Prompt
                                                → Generate Playbook
        │                               │
        └──────────────┬────────────────┘
                       ▼
STEP 7: Format Output Node (n8n)
        แปลงเป็น Markdown / PDF
        │
        ▼
STEP 8: ส่งกลับให้ Analyst ตรวจสอบ

╔══════════════════════════════════════════════════════════════════╗
║           🟡 PHASE 3: Human Review & Feedback Loop             ║
╚══════════════════════════════════════════════════════════════════╝

STEP 9: Analyst ตรวจสอบ Playbook ที่ได้
        → ถูกต้อง: บันทึกเป็น Pre-built Playbook สำหรับ Mode A ในอนาคต
        → ไม่ถูกต้อง: แก้ไข Context / Prompt → วนซ้ำที่ STEP 3
```

---

## ขอบเขตที่อยู่ในระบบ / นอกระบบ

| ขอบเขต                                                       | ✅ ในระบบ | ❌ นอกระบบ |
|--------------------------------------------------------------|----------|----------|
| รับ Input แบบ Text (IOC / Threat Name)                       | ✅       |          |
| Map กับ MITRE ATT&CK                                         | ✅       |          |
| ค้นหา Context ผ่าน Google NotebookLM (โดย Analyst)           | ✅       |          |
| Generate Playbook ด้วย LLM + Context จาก Analyst            | ✅       |          |
| ดึง Pre-built Playbook ที่ผ่านการ validate                   | ✅       |          |
| Output เป็น Markdown / PDF                                   | ✅       |          |
| Feedback Loop → ปรับปรุง Playbook Store                      | ✅       |          |
| RAG อัตโนมัติโดยไม่มี Human (ผ่าน Vector DB)                |          | ❌       |
| เชื่อมต่อกับ NotebookLM API โดยตรง                          |          | ❌       |
| เชื่อมต่อกับ SIEM โดยตรง (Real-time)                        |          | ❌       |
| Execute / Automate การแก้ไขระบบ (Remediation)               |          | ❌       |

---

*จัดทำโดย: Omnissiah Project Team*  
*อัปเดตล่าสุด: มิถุนายน 2569*
