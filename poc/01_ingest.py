"""
01_ingest.py — Omnissiah RAG Ingestion Pipeline
อ่าน playbook .md ทุกไฟล์ใน playbooks/ → chunk ตาม Phase + Sub
→ embed → บันทึกลง ChromaDB พร้อม metadata
"""

import os
import json
import re
import chromadb
from chromadb.utils import embedding_functions
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

# --- Config ---
PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"
CHROMA_DIR = str(Path(__file__).parent / "chroma_db")
COLLECTION_NAME = "omnissiah_procedures"

# ใช้ sentence-transformers รัน local ไม่ต้องใช้ API key
EMBEDDING_FN = embedding_functions.DefaultEmbeddingFunction()


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """แยก YAML frontmatter และ body ออกจากไฟล์ markdown"""
    if not text.startswith("---"):
        return {}, text
    end = text.find("---", 3)
    if end == -1:
        return {}, text
    fm_text = text[3:end].strip()
    body = text[end + 3:].strip()
    meta = {}
    for line in fm_text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            val = val.strip().strip('"')
            # parse list values like ["T1486", "T1190"]
            if val.startswith("["):
                val = json.loads(val)
            meta[key.strip()] = val
    return meta, body


def chunk_playbook(filepath: Path) -> list[dict]:
    """
    ตัด playbook เป็น chunks โดย:
    - แยก frontmatter → technique_ids, threat_name, severity, source_doc
    - split ตาม ## Phase: และ ### Sub:
    - แต่ละ Sub = 1 chunk
    """
    text = filepath.read_text(encoding="utf-8")
    meta, body = parse_frontmatter(text)

    if not meta:
        console.print(f"[yellow]⚠ ข้าม {filepath.name}: ไม่มี frontmatter[/yellow]")
        return []

    threat_name = meta.get("threat_name", "Unknown")
    technique_ids = meta.get("technique_ids", [])
    severity = meta.get("severity", "Medium")
    source_doc = meta.get("source_doc", filepath.stem)

    # Normalize technique_ids เป็น list เสมอ
    if isinstance(technique_ids, str):
        technique_ids = [tid.strip() for tid in technique_ids.split(",")]

    chunks = []
    current_phase = None
    current_sub = None
    buffer = []

    def flush_chunk():
        """บันทึก chunk ปัจจุบันลงใน chunks list"""
        if current_phase and current_sub and buffer:
            content = "\n".join(buffer).strip()
            if content:
                chunk_id = f"{filepath.stem}_{current_phase}_{current_sub}"
                chunk_id = re.sub(r"[^a-zA-Z0-9_-]", "_", chunk_id)
                chunks.append({
                    "id": chunk_id,
                    "content": content,
                    "metadata": {
                        "phase": current_phase,
                        "sub_process": current_sub,
                        "threat_name": threat_name,
                        "technique_ids": ",".join(technique_ids),  # ChromaDB ต้องเป็น string
                        "severity": severity,
                        "source_doc": source_doc,
                        "chunk_type": f"{current_phase}_{current_sub}",
                    }
                })

    for line in body.splitlines():
        # ตรวจหัวข้อ Phase
        phase_match = re.match(r"^## Phase:\s*(.+)", line.strip())
        if phase_match:
            flush_chunk()
            current_phase = phase_match.group(1).strip().lower().replace(" ", "_")
            current_sub = None
            buffer = []
            continue

        # ตรวจหัวข้อ Sub-process
        sub_match = re.match(r"^### Sub:\s*(.+)", line.strip())
        if sub_match:
            flush_chunk()
            current_sub = sub_match.group(1).strip().lower().replace(" ", "_")
            buffer = []
            continue

        # เก็บเนื้อหาใส่ buffer
        if current_phase and current_sub:
            buffer.append(line)

    # flush chunk สุดท้าย
    flush_chunk()
    return chunks


def main():
    console.print("\n[bold cyan]🚀 Omnissiah RAG Ingestion Pipeline[/bold cyan]")
    console.print(f"📁 Playbooks directory: {PLAYBOOKS_DIR}")
    console.print(f"🗄️  ChromaDB path: {CHROMA_DIR}\n")

    # เชื่อมต่อ ChromaDB
    client = chromadb.PersistentClient(path=CHROMA_DIR)

    # ลบ collection เก่าแล้วสร้างใหม่ (fresh start)
    try:
        client.delete_collection(COLLECTION_NAME)
        console.print(f"[yellow]🗑️  ลบ collection เก่า '{COLLECTION_NAME}' แล้ว[/yellow]")
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=EMBEDDING_FN,
        metadata={"hnsw:space": "cosine"}
    )
    console.print(f"[green]✅ สร้าง collection '{COLLECTION_NAME}' ใหม่[/green]\n")

    # อ่านและ chunk ทุก playbook
    all_playbook_files = sorted(PLAYBOOKS_DIR.glob("*.md"))
    if not all_playbook_files:
        console.print("[red]❌ ไม่พบไฟล์ .md ใน playbooks/[/red]")
        return

    all_chunks = []
    for filepath in all_playbook_files:
        chunks = chunk_playbook(filepath)
        all_chunks.extend(chunks)
        console.print(f"[green]✓[/green] {filepath.name}: {len(chunks)} chunks")

    console.print(f"\n[bold]📦 รวม: {len(all_chunks)} chunks จาก {len(all_playbook_files)} playbooks[/bold]\n")

    # ตรวจ duplicate IDs แก้ไขให้ unique
    id_counts = {}
    for chunk in all_chunks:
        base_id = chunk["id"]
        if base_id in id_counts:
            id_counts[base_id] += 1
            chunk["id"] = f"{base_id}_{id_counts[base_id]}"
        else:
            id_counts[base_id] = 0

    # บันทึกลง ChromaDB ทีละ batch
    BATCH_SIZE = 50
    for i in track(range(0, len(all_chunks), BATCH_SIZE), description="Embedding & storing..."):
        batch = all_chunks[i:i + BATCH_SIZE]
        collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["content"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )

    console.print(f"\n[bold green]✅ Ingestion สำเร็จ! {len(all_chunks)} chunks พร้อมใช้งานใน ChromaDB[/bold green]")

    # แสดงสรุปตาราง
    table = Table(title="📊 Chunk Summary by Phase", show_header=True)
    table.add_column("Phase", style="cyan")
    table.add_column("Count", justify="right", style="green")

    phase_counts = {}
    for chunk in all_chunks:
        phase = chunk["metadata"]["phase"]
        phase_counts[phase] = phase_counts.get(phase, 0) + 1

    for phase, count in sorted(phase_counts.items()):
        table.add_row(phase, str(count))

    console.print(table)


if __name__ == "__main__":
    main()
