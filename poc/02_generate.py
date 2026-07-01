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
            "จากข้อมูลด้านล่าง เขียนส่วน Preparation สำหรับ playbook นี้ในภาษาไทย:\n"
            "1. รายการเครื่องมือที่ต้องเตรียม (tool name, คำสั่งเช็ค, หน้าที่)\n"
            "2. บทบาทของทีม IR\n"
            "3. แผนการสื่อสารฉุกเฉิน\n"
            "เขียนเป็น Markdown พร้อม bullet points และ code blocks สำหรับคำสั่ง"
        ),
    },
    {
        "phase": "detection",
        "heading": "## 2️⃣ Phase 2: Identification & Analysis",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Detection & Analysis สำหรับ playbook นี้ในภาษาไทย:\n"
            "1. Log sources ที่ต้องตรวจสอบ (เฉพาะ technique นี้ ไม่ใช่ทั่วไป)\n"
            "2. Detection queries / SIEM rules (ใส่คำสั่ง query จริง)\n"
            "3. IOC ที่ต้องค้นหา\n"
            "4. วิธีประเมินขอบเขตการโจมตี\n"
            "เขียนเป็น Markdown พร้อม code blocks สำหรับ query"
        ),
    },
    {
        "phase": "containment",
        "heading": "## 3️⃣ Phase 3: Containment",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Containment สำหรับ playbook นี้ในภาษาไทย:\n"
            "1. Short-term containment (ขั้นตอนฉุกเฉิน numbered steps)\n"
            "2. Long-term containment\n"
            "3. การเก็บรักษาหลักฐาน (Evidence Preservation)\n"
            "เขียนเป็น Markdown พร้อม code blocks สำหรับคำสั่ง"
        ),
    },
    {
        "phase": "eradication",
        "heading": "## 4️⃣ Phase 4: Eradication & Recovery",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Eradication & Recovery สำหรับ playbook นี้ในภาษาไทย:\n"
            "1. ขั้นตอนกำจัด process/service ของมัลแวร์\n"
            "2. ลบ persistence mechanism\n"
            "3. Patch ช่องโหว่ต้นเหตุ\n"
            "4. กู้คืนระบบและยืนยันความสะอาด\n"
            "เขียนเป็น Markdown พร้อม code blocks"
        ),
    },
    {
        "phase": "post_incident",
        "heading": "## 5️⃣ Phase 5: Post-Incident Review",
        "fill_instruction": (
            "คุณคือ SOC Analyst ผู้เชี่ยวชาญด้าน Incident Response "
            "จากข้อมูลด้านล่าง เขียนส่วน Post-Incident Review สำหรับ playbook นี้ในภาษาไทย:\n"
            "1. Lessons Learned (สิ่งที่ค้นพบจากเหตุการณ์)\n"
            "2. Gap Analysis (อะไรที่ขาดหายหรือล้มเหลว)\n"
            "3. Improvement Actions (สิ่งที่ต้องปรับปรุง)\n"
            "4. การอัปเดต Detection Rules\n"
            "เขียนเป็น Markdown"
        ),
    },
]


def load_technique_mapping() -> dict:
    """โหลด technique_mapping.json"""
    with open(TECHNIQUE_MAPPING_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def query_rag(collection, query: str, phase: str, technique_ids: list[str], n_results: int = 5) -> list[str]:
    """
    ดึง chunks จาก ChromaDB ด้วย metadata filter (phase) + semantic similarity
    แล้วนำมากรอง technique_id ด้วย Python 
    """
    retrieved_docs = []
    seen_ids = set()
    
    where_filter = {"phase": {"$eq": phase}}
    
    try:
        results = collection.query(
            query_texts=[query],
            n_results=30, # ดึงมาเผื่อกรอง
            where=where_filter,
            include=["documents", "metadatas", "ids"],
        )
        if results and results["documents"] and results["documents"][0]:
            for doc_id, doc, meta in zip(results["ids"][0], results["documents"][0], results["metadatas"][0]):
                tech_ids_str = meta.get("technique_ids", "")
                
                # Check if any of the target technique_ids is in this chunk's technique_ids
                if any(tech_id in tech_ids_str for tech_id in technique_ids):
                    if doc_id not in seen_ids:
                        seen_ids.add(doc_id)
                        retrieved_docs.append(doc)
                        if len(retrieved_docs) >= n_results:
                            break
    except Exception:
        pass

    # ถ้าดึงไม่ได้เลย fallback ดึงด้วย phase อย่างเดียว
    if not retrieved_docs:
        try:
            results = collection.query(
                query_texts=[query],
                n_results=min(3, n_results),
                where={"phase": {"$eq": phase}},
                include=["documents"],
            )
            if results and results["documents"] and results["documents"][0]:
                retrieved_docs = results["documents"][0]
        except Exception:
            pass

    return retrieved_docs[:n_results]


def generate_section(model, section: dict, threat_name: str, technique_ids: list[str],
                     retrieved_chunks: list[str]) -> str:
    """
    สร้างเนื้อหา 1 Phase ด้วย LLM
    Input: fill instruction + retrieved chunks จาก RAG
    Output: Markdown content ของ Phase นั้น
    """
    context = "\n\n---\n".join(retrieved_chunks) if retrieved_chunks else "ไม่พบข้อมูลที่เกี่ยวข้องใน Knowledge Base"

    prompt = f"""
{section['fill_instruction']}

**Threat:** {threat_name}
**MITRE ATT&CK Techniques:** {', '.join(technique_ids)}

**ข้อมูลอ้างอิงจาก Knowledge Base (IR Playbook จริง):**
{context}

**คำแนะนำ:**
- ใช้ข้อมูลจาก Knowledge Base ด้านบนเป็นหลัก
- ปรับแต่งให้เหมาะสมกับ threat "{threat_name}" โดยเฉพาะ
- อย่าเขียนทั่วไปเกินไป ให้เฉพาะเจาะจงกับ technique และ threat นี้
- ถ้า Knowledge Base มีคำสั่ง CLI ให้ใส่ด้วย
- เขียนเป็นภาษาไทย
"""

    response = model.generate_content(prompt)
    return response.text


def assemble_playbook(threat_name: str, severity: str, technique_ids: list[str],
                      sections: dict[str, str]) -> str:
    """ประกอบ Playbook สมบูรณ์จาก sections ที่ generate แล้ว"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    techniques_table = "\n".join([f"| {tid} |" for tid in technique_ids])

    header = f"""# 🛡️ Incident Response Playbook: {threat_name}

> **Status:** 📝 DRAFT — Pending Human Verification
> **Generated by:** Omnissiah IR Engine (RAG + LLM)
> **Generated At:** {now}

---

## 📋 Header Information

| Field | Value |
|-------|-------|
| **Threat Name** | {threat_name} |
| **Severity** | {severity} |
| **Status** | DRAFT |
| **MITRE ATT&CK** | {', '.join(technique_ids)} |

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
    model = genai.GenerativeModel("gemini-2.0-flash")

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
            )
            progress.update(task, description=f"[cyan]Phase {phase}: retrieved {len(retrieved_chunks)} chunks...")

            # Step 2: LLM Generate
            content = generate_section(model, section, threat_key, technique_ids, retrieved_chunks)
            
            # ถ้าไม่ได้ข้อมูลจาก RAG เลย ให้แปะป้ายแจ้งเตือนไว้ต้นเนื้อหาของ Phase นั้น
            if len(retrieved_chunks) == 0:
                content = "> ⚠️ **คำเตือน:** เนื้อหาส่วนนี้สร้างจากความรู้ทั่วไปของ AI โดยตรง (Zero-Day) เนื่องจากไม่พบข้อมูลในองค์ความรู้ (RAG)\n\n" + content
                
            sections[phase] = content
            progress.update(task, description=f"[green]✅ Phase {phase}: done[/green]")
            progress.stop_task(task)

    # Assemble Playbook
    playbook_md = assemble_playbook(threat_key, severity, technique_ids, sections)

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
