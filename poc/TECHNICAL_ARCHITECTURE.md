# ⚙️ Technical Architecture: Omnissiah RAG PoC

This document provides a deep-dive technical overview of the Omnissiah Incident Response (IR) Playbook Generator. It is designed for engineers, SOC analysts, and AI agents who need to understand, maintain, or extend this Proof of Concept (PoC).

---

## 🏗️ System Architecture

The system implements a **Retrieval-Augmented Generation (RAG)** pipeline specifically tailored for Incident Response documentation. It bridges static, pre-approved IR procedures (Knowledge Base) with a Generative LLM to dynamically construct threat-specific playbooks.

### Core Components
1. **Knowledge Base (Markdown)**: 15 modularized IR playbooks acting as ground truth.
2. **Vector Database (ChromaDB)**: Stores document embeddings and metadata for semantic and exact-match retrieval.
3. **Generative Model (Google Gemini)**: Processes retrieved context and structured prompts to generate Markdown tables (`gemini-flash-lite-latest` is used to optimize for speed and Free Tier rate limits).

---

## 🔄 Data Pipeline & Workflow

### 1. Data Ingestion (`01_ingest.py`)
- **Input**: Raw `.md` files in `playbooks/`.
- **Parsing**: The script uses Regular Expressions (`re`) to extract YAML frontmatter (`threat_name`, `technique_ids`, `severity`).
- **Chunking**: The document is split by Markdown headers (`## Phase: ...` and `### Sub: ...`). Each chunk represents a specific phase (e.g., `preparation`, `detection`) and sub-process.
- **Embedding**: Uses ChromaDB's `DefaultEmbeddingFunction` (all-MiniLM-L6-v2) to convert text chunks into vector embeddings.
- **Storage**: Chunks are stored in the `omnissiah_procedures` collection. Crucially, metadata (`phase` and `technique_ids` as a stringized list) is attached to each chunk.

### 2. Retrieval & Context Injection (`02_generate.py`)
- **Input**: User executes the script with a target threat, e.g., `python 02_generate.py --threat "WannaCry"`.
- **Mapping**: The script looks up `technique_mapping.json` to find the exact MITRE ATT&CK Technique IDs associated with the threat (e.g., WannaCry -> T1486, T1190, T1021.002).
- **Hybrid Retrieval Strategy**: 
  - *Vector Search + Metadata Pre-filtering*: Queries ChromaDB with a semantic string (e.g., "WannaCry preparation incident response procedure") while enforcing a strict metadata filter: `{"phase": {"$eq": "preparation"}}`.
  - *Python-side Post-filtering*: Because ChromaDB's native `$contains` on arrays can be complex, the script fetches up to 30 candidates and iterates through them in Python. It strictly filters for chunks where `any(tech_id in metadata['technique_ids'] for tech_id in target_technique_ids)`.
  - *Fallback Mechanism*: If no technique ID matches exactly, it falls back to semantic similarity based solely on the `phase`.

### 3. Generation & Formatting (`02_generate.py`)
- **Prompt Engineering**: The script loops through 5 predefined templates (`TEMPLATE_SECTIONS`). It injects the retrieved context into a rigid prompt.
- **Output Constraints**: The prompt explicitly instructs the LLM:
  > *"ห้ามเกริ่นนำ ห้ามมีคำทักทาย ห้ามมีสรุปปิดท้าย ห้ามพูดคุยโต้ตอบ... ให้ตอบเฉพาะตารางและข้อมูลในรูปแบบเอกสารทางการเท่านั้น"* 
  This forces the LLM to output a strict 2-column Markdown table (`| ขั้นตอน | กระบวนการ |`) suitable for executive and L1 analyst consumption.
- **Rate Limit Handling**: To bypass Google's strict Free Tier limits for Gemini APIs (Error 429), the generator implements:
  - **Pacing**: `time.sleep(5)` before every API call to maintain a request rate below 15 RPM.
  - **Exponential Backoff**: A `try-except` block catches `ResourceExhausted` exceptions and triggers a 60-second sleep before retrying (max 5 retries).

---

## 💻 Developer Notes & Extensibility

### Updating the Model
The system currently uses `gemini-flash-lite-latest` in `02_generate.py` to maximize the daily quota. For production environments with a paid Google Cloud billing account, this should be upgraded to `gemini-1.5-pro` or `gemini-2.5-pro` for deeper reasoning and longer context windows.

```python
# In 02_generate.py
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-flash-lite-latest") # Change this for production
```

### Modifying the Prompt Template
To change the output format (e.g., switching from a Markdown Table back to raw CLI commands or JSON), locate the `TEMPLATE_SECTIONS` array in `02_generate.py` and modify the `fill_instruction` strings.

### Zero-Day Handling
If the Retrieval phase returns `0` chunks, the system automatically injects a Zero-Day warning (`⚠️ คำเตือน: เนื้อหาส่วนนี้สร้างจากความรู้ทั่วไปของ AI โดยตรง...`) into the final Markdown. This ensures users know when the LLM is hallucinating or relying on pre-training data rather than the organization's Knowledge Base.
