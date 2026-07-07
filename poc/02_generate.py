"""
02_generate.py — Omnissiah Per-Section Generation Loop
รับ input: ชื่อ threat → map MITRE Technique IDs → Per-Section Loop (RAG + LLM) → Playbook

Usage:
  python 02_generate.py --threat "WannaCry"
  python 02_generate.py --threat "Phishing" --severity High
  python 02_generate.py --list   (แสดงรายชื่อ threat ที่รองรับทั้งหมด)

ต้องตั้งค่า environment variable:
  set GEMINI_API_KEY=your_api_key_here   (Windows)
  export GEMINI_API_KEY=your_api_key_here (Linux/Mac)
"""

import os
import sys
import json
import time
import argparse
import datetime
import chromadb
import google.generativeai as genai
from chromadb.utils import embedding_functions
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# --- Config ---
CHROMA_DIR = str(Path(__file__).parent / "chroma_db")
COLLECTION_NAME = "omnissiah_procedures"
TECHNIQUE_MAPPING_FILE = Path(__file__).parent / "technique_mapping.json"
OUTPUT_DIR = Path(__file__).parent / "output"
EMBEDDING_FN = embedding_functions.DefaultEmbeddingFunction()

# โครงสร้าง 5 Phase ของ Mastertemplate
TEMPLATE_SECTIONS = [
    {
        "phase": "preparation",
        "heading": "## 1️⃣ Phase 1: Preparation",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Preparation สำหรับ playbook นี้ในภาษาไทย โดยไม่ต้องใส่คำสั่ง Command ลึกๆ "
            "แต่ให้อธิบายเป็นขั้นตอนที่เข้าใจง่าย จัดรูปแบบผลลัพธ์เป็นตาราง Markdown (Table) ที่มี 2 คอลัมน์คือ:\n"
            "| ขั้นตอน | กระบวนการ |\n"
            "โดยคอลัมน์ 'ขั้นตอน' คือชื่อหัวข้อย่อย และ 'กระบวนการ' คือคำอธิบายสิ่งที่ต้องทำ"
        ),
    },
    {
        "phase": "detection",
        "heading": "## 2️⃣ Phase 2: Identification & Analysis",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Detection & Analysis สำหรับ playbook นี้ในภาษาไทย โดยไม่ต้องใส่คำสั่ง Command ลึกๆ "
            "แต่ให้อธิบายเป็นขั้นตอนที่เข้าใจง่าย จัดรูปแบบผลลัพธ์เป็นตาราง Markdown (Table) ที่มี 2 คอลัมน์คือ:\n"
            "| ขั้นตอน | กระบวนการ |\n"
            "โดยคอลัมน์ 'ขั้นตอน' คือชื่อหัวข้อย่อย (เช่น Process Creation) และ 'กระบวนการ' คือคำอธิบายสิ่งผิดปกติที่ต้องตรวจสอบ"
        ),
    },
    {
        "phase": "containment",
        "heading": "## 3️⃣ Phase 3: Containment",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Containment สำหรับ playbook นี้ในภาษาไทย โดยไม่ต้องใส่คำสั่ง Command ลึกๆ "
            "แต่ให้อธิบายเป็นขั้นตอนที่เข้าใจง่าย จัดรูปแบบผลลัพธ์เป็นตาราง Markdown (Table) ที่มี 2 คอลัมน์คือ:\n"
            "| ขั้นตอน | กระบวนการ |\n"
            "โดยคอลัมน์ 'ขั้นตอน' คือชื่อหัวข้อย่อย (เช่น การกักกันระยะสั้น) และ 'กระบวนการ' คือคำอธิบายสิ่งที่ต้องทำ"
        ),
    },
    {
        "phase": "eradication",
        "heading": "## 4️⃣ Phase 4: Eradication & Recovery",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Eradication & Recovery สำหรับ playbook นี้ในภาษาไทย โดยไม่ต้องใส่คำสั่ง Command ลึกๆ "
            "แต่ให้อธิบายเป็นขั้นตอนที่เข้าใจง่าย จัดรูปแบบผลลัพธ์เป็นตาราง Markdown (Table) ที่มี 2 คอลัมน์คือ:\n"
            "| ขั้นตอน | กระบวนการ |\n"
            "โดยคอลัมน์ 'ขั้นตอน' คือชื่อหัวข้อย่อย (เช่น การกำจัดมัลแวร์) และ 'กระบวนการ' คือคำอธิบายสิ่งที่ต้องทำ"
        ),
    },
    {
        "phase": "post_incident",
        "heading": "## 5️⃣ Phase 5: Post-Incident Review",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Post-Incident Review สำหรับ playbook นี้ในภาษาไทย โดยไม่ต้องใส่คำสั่ง Command ลึกๆ "
            "แต่ให้อธิบายเป็นขั้นตอนที่เข้าใจง่าย จัดรูปแบบผลลัพธ์เป็นตาราง Markdown (Table) ที่มี 2 คอลัมน์คือ:\n"
            "| ขั้นตอน | กระบวนการ |\n"
            "โดยคอลัมน์ 'ขั้นตอน' คือชื่อหัวข้อย่อย (เช่น บทเรียนที่ได้รับ) และ 'กระบวนการ' คือคำอธิบายสิ่งที่ต้องทำ"
        ),
    },
]


def load_technique_mapping() -> dict:
    """โหลด technique_mapping.json"""
    with open(TECHNIQUE_MAPPING_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def query_rag(collection, query: str, phase: str, technique_ids: list[str],
              n_results: int = 5, threat_name: str = None) -> list[dict]:
    """
    Tiered + labeled retrieval — จัดลำดับความน่าเชื่อถือของแหล่งเพื่อลด contamination:
      - primary   : chunk ที่ตรงเทคนิค และ "สะอาด" = มาจาก playbook ของ threat นี้เอง
                    หรือถูกแท็กระดับ Sub (technique_source == "sub") → ยึดเป็นแกน
      - secondary : chunk ที่ตรงเทคนิค แต่มาจากเล่มอื่นแบบ broad (แท็กระดับเล่ม) → ใช้เสริม nuance
      - fallback  : ดึง phase อย่างเดียว เฉพาะเมื่อ "ไม่มี" chunk ตรงเทคนิคเลย → ติดธงว่าไม่ยืนยันเทคนิค
    คืน list ของ dict: {doc, threat_name, technique_ids, matched, tier}
    """
    def matched_techs(meta):
        tstr = meta.get("technique_ids", "") or ""
        return [t for t in technique_ids if t in tstr]

    primary, secondary = [], []
    seen_ids = set()

    try:
        results = collection.query(
            query_texts=[query],
            n_results=30,  # ดึงมาเผื่อกรอง
            where={"phase": {"$eq": phase}},
            include=["documents", "metadatas"],  # ChromaDB คืน ids ให้เสมออยู่แล้ว ห้ามใส่ "ids" ใน include (จะ error)
        )
        if results and results["documents"] and results["documents"][0]:
            for doc_id, doc, meta in zip(results["ids"][0], results["documents"][0], results["metadatas"][0]):
                if doc_id in seen_ids:
                    continue
                m = matched_techs(meta)
                if not m:
                    continue  # ไม่ตรงเทคนิคเป้าหมาย → ตัดทิ้ง (กันเนื้อหาเล่มอื่นที่ไม่เกี่ยว)
                seen_ids.add(doc_id)
                item = {
                    "doc": doc,
                    "threat_name": meta.get("threat_name", "") or "",
                    "technique_ids": meta.get("technique_ids", "") or "",
                    "matched": m,
                }
                is_own = bool(threat_name) and item["threat_name"] == threat_name
                is_precise = meta.get("technique_source") == "sub"
                if is_own or is_precise:
                    item["tier"] = "primary"
                    primary.append(item)
                else:
                    item["tier"] = "secondary"
                    secondary.append(item)
    except Exception:
        pass

    # เลือก primary ให้เต็มก่อน แล้วค่อยเติม secondary จนครบโควตา
    chosen = primary[:n_results]
    if len(chosen) < n_results:
        chosen += secondary[: n_results - len(chosen)]

    # fallback เฉพาะเมื่อไม่มี chunk ตรงเทคนิคเลย (ครองเทคนิคไม่ได้จริงๆ)
    if not chosen:
        try:
            results = collection.query(
                query_texts=[query],
                n_results=min(3, n_results),
                where={"phase": {"$eq": phase}},
                include=["documents", "metadatas"],
            )
            if results and results["documents"] and results["documents"][0]:
                for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
                    chosen.append({
                        "doc": doc,
                        "threat_name": (meta or {}).get("threat_name", "") or "",
                        "technique_ids": (meta or {}).get("technique_ids", "") or "",
                        "matched": [],
                        "tier": "fallback",
                    })
        except Exception:
            pass

    return chosen[:n_results]


def check_technique_coverage(collection, technique_ids: list[str]) -> list[str]:
    """
    ตรวจว่า technique_id ตัวไหน "ไม่มี chunk ใดๆ ใน KB รองรับเลย"
    - ดึง metadata ทุก chunk ออกมา (KB เล็ก จึงกวาดทั้งหมดได้)
    - ใช้ substring match ให้ตรงกับตรรกะจริงใน query_rag() เพื่อไม่ให้ผลไม่ตรงกัน
      (เช่น target 'T1071' จะถือว่า cover ถ้ามี chunk ที่ metadata เป็น 'T1071.004')
    คืน: list ของ technique_id ที่ "ขาด" การรองรับใน KB (เรียงตามลำดับเดิม)
    """
    try:
        all_meta = collection.get(include=["metadatas"]).get("metadatas", []) or []
    except Exception:
        # เช็คไม่ได้ → ไม่ฟันธงว่าขาด เพื่อไม่ให้ทั้งงานล้ม
        return []

    covered = set()
    for meta in all_meta:
        tech_str = (meta or {}).get("technique_ids", "") or ""
        for tid in technique_ids:
            if tid in tech_str:
                covered.add(tid)

    return [tid for tid in technique_ids if tid not in covered]


def generate_section(model, section: dict, threat_name: str, technique_ids: list[str],
                     retrieved_chunks: list[str], missing_techs: list[str] = None) -> str:
    """
    สร้างเนื้อหา 1 Phase ด้วย LLM
    Input: fill instruction + retrieved chunks จาก RAG
    Output: Markdown content ของ Phase นั้น
    """
    def _fmt(item):
        # ติดป้ายที่มา + เทคนิคของแต่ละ chunk เพื่อให้ LLM เห็น provenance และกรองเองได้
        return f"(threat={item.get('threat_name','')} | technique={item.get('technique_ids','')})\n{item.get('doc','')}"

    primary_c = [c for c in retrieved_chunks if isinstance(c, dict) and c.get("tier") == "primary"]
    secondary_c = [c for c in retrieved_chunks if isinstance(c, dict) and c.get("tier") == "secondary"]
    fallback_c = [c for c in retrieved_chunks if isinstance(c, dict) and c.get("tier") == "fallback"]

    parts = []
    if primary_c:
        parts.append("[ขั้นตอนหลัก — ยึดเป็นแกนของ playbook ต้องครอบคลุมให้ครบ]\n"
                     + "\n\n---\n".join(_fmt(c) for c in primary_c))
    if secondary_c:
        parts.append("[บริบทเสริม — ใช้เพื่อปรับให้เข้ากับ threat เท่านั้น ห้ามยกเป็นขั้นตอนหลัก"
                     " ถ้าเนื้อหาไม่เกี่ยวกับเทคนิคเป้าหมาย]\n"
                     + "\n\n---\n".join(_fmt(c) for c in secondary_c))
    if fallback_c:
        parts.append("[บริบทกว้าง (ยังไม่ยืนยันว่าตรงเทคนิค) — ใช้ด้วยความระมัดระวัง]\n"
                     + "\n\n---\n".join(_fmt(c) for c in fallback_c))
    context = "\n\n".join(parts) if parts else "ไม่พบข้อมูลที่เกี่ยวข้องใน Knowledge Base"

    missing_note = ""
    if missing_techs:
        missing_note = (
            f"\n**⚠️ หมายเหตุความครอบคลุม:** เทคนิคต่อไปนี้ไม่มีข้อมูลอ้างอิงใน Knowledge Base เลย: "
            f"{', '.join(missing_techs)}\n"
            f"สำหรับส่วนที่เกี่ยวข้องกับเทคนิคเหล่านี้ ห้ามแต่งชื่อเครื่องมือ/Event ID/คำสั่งที่เจาะจงขึ้นมาเอง "
            f"ให้เขียนเป็นแนวทางทั่วไปที่ระมัดระวัง และกำกับในตารางว่า '(ยังไม่ได้ตรวจสอบกับ KB)'\n"
        )

    prompt = f"""
{section['fill_instruction']}

**Threat:** {threat_name}
**MITRE ATT&CK Techniques:** {', '.join(technique_ids)}
{missing_note}
**ข้อมูลอ้างอิงจาก Knowledge Base (IR Playbook จริง):**
{context}

**คำแนะนำ:**
- ยึด "ขั้นตอนหลัก" เป็นโครงของ playbook เสมอ และต้องครอบคลุมให้ครบ
- ใช้ "บริบทเสริม"/"บริบทกว้าง" เฉพาะเพื่อปรับถ้อยคำและเพิ่มรายละเอียดให้เข้ากับ threat "{threat_name}" เท่านั้น
- แต่ละ chunk มีป้าย (threat=... | technique=...) กำกับ — **ถ้าเนื้อหา chunk เป็นของเทคนิคที่ไม่อยู่ใน [{', '.join(technique_ids)}] ห้ามนำขั้นตอนนั้นมาใส่ playbook เด็ดขาด** (เช่นขั้นตอนขโมย/รีเซ็ต credential ที่ไม่เกี่ยวกับเทคนิคเป้าหมาย)
- ปรับ nuance ให้เข้ากับลักษณะเฉพาะของ threat "{threat_name}" (เช่น worm ที่แพร่อัตโนมัติ ต้องเน้น containment ก่อน remediate)
- อย่าเขียนทั่วไปเกินไป ให้เฉพาะเจาะจงกับ technique และ threat นี้
- ถ้า Knowledge Base มีคำสั่ง CLI ให้ใส่ด้วย
- เขียนเป็นภาษาไทย
- **สำคัญมาก:** ห้ามเกริ่นนำ ห้ามมีคำทักทาย ห้ามมีสรุปปิดท้าย ห้ามพูดคุยโต้ตอบ (เช่น ห้ามใช้คำว่า "ในฐานะ SOC Analyst..." หรือ "นี่คือส่วน...") ให้ตอบเฉพาะตารางและข้อมูลในรูปแบบเอกสารทางการเท่านั้น
"""

    max_retries = 5
    for attempt in range(max_retries):
        try:
            time.sleep(5)  # ถ่วงเวลา 5 วินาทีก่อนเรียก API เพื่อกระจาย Load (แก้ปัญหา Rate Limit ชนเพดาน)
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            if "429" in str(e) or "ResourceExhausted" in str(e) or "quota" in str(e).lower():
                if attempt < max_retries - 1:
                    console.print(f"\n[yellow]⚠️  API Rate Limit (Free Tier). รอ 60 วินาทีเพื่อลองใหม่ (ครั้งที่ {attempt+1}/{max_retries})...[/yellow]")
                    time.sleep(60)
                else:
                    raise e
            else:
                raise e
    return ""


def assemble_playbook(threat_name: str, severity: str, technique_ids: list[str],
                      sections: dict[str, str], missing_techs: list[str] = None) -> str:
    """ประกอบ Playbook สมบูรณ์จาก sections ที่ generate แล้ว"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    missing_techs = missing_techs or []

    techniques_table = "\n".join([f"| {tid} |" for tid in technique_ids])

    # ติดธง ⚠️ ต่อท้ายเทคนิคที่ไม่มี KB รองรับ ในแถว MITRE ATT&CK
    mitre_cell = ', '.join(
        f"{tid} ⚠️" if tid in missing_techs else tid for tid in technique_ids
    )

    # Banner เตือนความครอบคลุม (โผล่เฉพาะเมื่อมีเทคนิคที่ขาด KB)
    coverage_banner = ""
    if missing_techs:
        coverage_banner = (
            "> ## ⚠️ Knowledge Coverage Warning\n"
            f"> เทคนิคต่อไปนี้ **ไม่มีข้อมูลอ้างอิงใน Knowledge Base เลย:** {', '.join(missing_techs)}\n"
            "> เนื้อหาส่วนที่เกี่ยวข้องกับเทคนิคเหล่านี้ถูกสร้างจากความรู้ทั่วไปของ AI (ไม่ได้อิง IR Playbook จริง)\n"
            "> จึงมีความเสี่ยงที่ playbook จะ **ประกาศครอบคลุมเทคนิคที่ไม่มีขั้นตอนรับมือจริงรองรับ**\n"
            "> **ต้องให้ผู้เชี่ยวชาญตรวจสอบเทคนิคที่ติดธง ⚠️ เป็นพิเศษก่อนใช้งาน**\n\n---\n\n"
        )

    header = f"""# 🛡️ Incident Response Playbook: {threat_name}

> **Status:** 📝 DRAFT — Pending Human Verification
> **Generated by:** Omnissiah IR Engine (RAG + LLM)
> **Generated At:** {now}

---

{coverage_banner}## 📋 Header Information

| Field | Value |
|-------|-------|
| **Threat Name** | {threat_name} |
| **Severity** | {severity} |
| **Status** | DRAFT |
| **MITRE ATT&CK** | {mitre_cell} |

---

"""
    body_parts = [header]
    for section in TEMPLATE_SECTIONS:
        phase = section["phase"]
        content = sections.get(phase, f"*ไม่สามารถ generate ส่วนนี้ได้*")
        body_parts.append(f"{section['heading']}\n\n{content}\n\n---\n\n")

    body_parts.append("*Generated by Omnissiah IR Engine — Verify content before operational use*\n")
    return "".join(body_parts)


def main():
    parser = argparse.ArgumentParser(description="Omnissiah Playbook Generator")
    parser.add_argument("--threat", type=str, help="ชื่อ threat เช่น 'WannaCry', 'Phishing'")
    parser.add_argument("--list", action="store_true", help="แสดงรายชื่อ threat ที่รองรับ")
    parser.add_argument("--n-chunks", type=int, default=5, help="จำนวน chunks ที่ดึงต่อ phase (default: 5)")
    args = parser.parse_args()

    # โหลด mapping
    mapping = load_technique_mapping()

    if args.list:
        console.print("\n[bold]📋 Threats ที่รองรับ:[/bold]")
        for threat, info in mapping.items():
            console.print(f"  • [cyan]{threat}[/cyan] — {', '.join(info['technique_ids'])} ({info['severity']})")
        return

    if not args.threat:
        console.print("[red]❌ กรุณาระบุ --threat หรือใช้ --list เพื่อดูรายชื่อ[/red]")
        parser.print_help()
        sys.exit(1)

    # ค้นหา threat (case-insensitive)
    threat_key = None
    for key in mapping:
        if key.lower() == args.threat.lower():
            threat_key = key
            break

    if not threat_key:
        console.print(f"[red]❌ ไม่พบ threat '{args.threat}' — ใช้ --list เพื่อดูรายชื่อ[/red]")
        sys.exit(1)

    threat_info = mapping[threat_key]
    technique_ids = threat_info["technique_ids"]
    severity = threat_info["severity"]

    console.print(f"\n[bold cyan]🚀 Omnissiah Playbook Generator[/bold cyan]")
    console.print(f"🎯 Threat: [bold]{threat_key}[/bold]")
    console.print(f"📊 Severity: [bold]{severity}[/bold]")
    console.print(f"🏷️  MITRE Techniques: [cyan]{', '.join(technique_ids)}[/cyan]\n")

    # ตรวจสอบ Gemini API Key
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        console.print("[red]❌ ไม่พบ GEMINI_API_KEY — กรุณาตั้งค่า environment variable:[/red]")
        console.print("[yellow]  Windows: set GEMINI_API_KEY=your_key_here[/yellow]")
        console.print("[yellow]  Linux:   export GEMINI_API_KEY=your_key_here[/yellow]")
        sys.exit(1)

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-flash-lite-latest")

    # เชื่อมต่อ ChromaDB
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    try:
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=EMBEDDING_FN
        )
        console.print(f"[green]✅ ChromaDB: {collection.count()} chunks[/green]\n")
    except Exception:
        console.print("[red]❌ ไม่พบ ChromaDB collection — กรุณารัน 01_ingest.py ก่อน[/red]")
        sys.exit(1)

    # ตรวจความครอบคลุม: technique_id ไหนไม่มี chunk รองรับใน KB เลย
    missing_techs = check_technique_coverage(collection, technique_ids)
    if missing_techs:
        console.print(
            f"[bold yellow]⚠️  Coverage Warning:[/bold yellow] ไม่พบข้อมูลใน KB สำหรับเทคนิค: "
            f"[red]{', '.join(missing_techs)}[/red]"
        )
        console.print(
            "[yellow]   เนื้อหาส่วนที่เกี่ยวข้องจะอิงความรู้ทั่วไปของ AI และจะถูกแปะป้ายเตือนในเอกสาร[/yellow]\n"
        )
    else:
        console.print("[green]✅ Coverage: ทุกเทคนิคมีข้อมูลอ้างอิงใน KB[/green]\n")

    # Per-Section Generation Loop
    sections = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for section in TEMPLATE_SECTIONS:
            phase = section["phase"]
            task = progress.add_task(f"[cyan]Phase: {phase}...", total=None)

            # Step 1: RAG Retrieval
            query = f"{threat_key} {phase} incident response procedure {' '.join(technique_ids)}"
            retrieved_chunks = query_rag(
                collection,
                query=query,
                phase=phase,
                technique_ids=technique_ids,
                n_results=args.n_chunks,
                threat_name=threat_key,
            )
            progress.update(task, description=f"[cyan]Phase {phase}: retrieved {len(retrieved_chunks)} chunks...")

            # Step 2: LLM Generate
            content = generate_section(model, section, threat_key, technique_ids, retrieved_chunks, missing_techs)

            # แปะป้ายเตือนถ้าไม่มีข้อมูลเลย หรือได้มาเฉพาะ fallback (ครองเทคนิคไม่ได้)
            only_fallback = bool(retrieved_chunks) and all(
                isinstance(c, dict) and c.get("tier") == "fallback" for c in retrieved_chunks
            )
            if len(retrieved_chunks) == 0 or only_fallback:
                content = "> ⚠️ **คำเตือน:** เนื้อหาส่วนนี้สร้างจากความรู้ทั่วไปของ AI โดยตรง (Zero-Day) เนื่องจากไม่พบข้อมูลในองค์ความรู้ (RAG)\n\n" + content
                
            sections[phase] = content
            progress.update(task, description=f"[green]✅ Phase {phase}: done[/green]")
            progress.stop_task(task)

    # Assemble Playbook
    playbook_md = assemble_playbook(threat_key, severity, technique_ids, sections, missing_techs)

    # บันทึกไฟล์
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"playbook_{threat_key.lower().replace(' ', '_')}_{timestamp}.md"
    output_path = OUTPUT_DIR / filename
    output_path.write_text(playbook_md, encoding="utf-8")

    console.print(Panel(
        f"[bold green]✅ Playbook สร้างเสร็จแล้ว![/bold green]\n"
        f"📄 ไฟล์: [cyan]{output_path}[/cyan]\n"
        f"📊 Phases: {len(sections)}/5\n"
        f"🔍 ขนาด: {len(playbook_md):,} characters\n\n"
        f"[yellow]⚠️  Status: DRAFT — ต้องให้ผู้เชี่ยวชาญตรวจสอบก่อนใช้งานจริง[/yellow]",
        title="🛡️ Omnissiah Output",
        border_style="green"
    ))

    # Preview 10 บรรทัดแรก
    preview_lines = playbook_md.split("\n")[:20]
    console.print("\n[bold]📖 Preview (20 บรรทัดแรก):[/bold]")
    for line in preview_lines:
        console.print(f"  {line}")


if __name__ == "__main__":
    main()