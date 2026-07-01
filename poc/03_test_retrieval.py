"""
03_test_retrieval.py — ทดสอบว่า RAG ดึง chunks ถูกต้องตาม phase + technique_id
รันก่อน 02_generate.py เสมอเพื่อยืนยันว่า metadata filter ทำงานถูกต้อง
"""

import sys
import json
import chromadb
from chromadb.utils import embedding_functions
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

CHROMA_DIR = str(Path(__file__).parent / "chroma_db")
COLLECTION_NAME = "omnissiah_procedures"
EMBEDDING_FN = embedding_functions.DefaultEmbeddingFunction()

# Test cases: แต่ละ test จะยืนยันว่า RAG ดึงถูก technique
TEST_CASES = [
    {
        "name": "🔴 WannaCry: Detection phase",
        "query": "detect ransomware process activity shadow copy deletion",
        "phase": "detection",
        "technique_id": "T1486",
        "expect_threat": "WannaCry",
        "expect_NOT_contain": "outlook.exe",  # ต้องไม่ดึงของ Phishing มา
    },
    {
        "name": "📧 Phishing: Detection phase (same log source as WannaCry!)",
        "query": "detect malicious process execution email attachment",
        "phase": "detection",
        "technique_id": "T1566.001",
        "expect_threat": "Phishing",
        "expect_NOT_contain": "vssadmin",  # ต้องไม่ดึงของ WannaCry มา
    },
    {
        "name": "🌐 Web Shell: Detection phase",
        "query": "detect web shell activity web server process",
        "phase": "detection",
        "technique_id": "T1505.003",
        "expect_threat": "Web Shell",
        "expect_NOT_contain": "T1486",
    },
    {
        "name": "🔐 Credential Dumping: Containment",
        "query": "contain credential theft lsass memory dump",
        "phase": "containment",
        "technique_id": "T1003.001",
        "expect_threat": "Credential Dumping",
        "expect_NOT_contain": "vssadmin",
    },
    {
        "name": "⛏️ Cryptomining: Eradication",
        "query": "remove cryptominer xmrig process cleanup",
        "phase": "eradication",
        "technique_id": "T1496",
        "expect_threat": "Cryptomining",
        "expect_NOT_contain": "T1486",
    },
    {
        "name": "🖥️ RDP Brute Force: Preparation",
        "query": "tools needed for rdp brute force incident response",
        "phase": "preparation",
        "technique_id": "T1110.001",
        "expect_threat": "RDP Brute Force",
        "expect_NOT_contain": "phishing",
    },
]


def query_rag(collection, query: str, phase: str, technique_id: str, n_results: int = 3):
    """ค้นหาใน ChromaDB ด้วย metadata filter (phase) แล้วมากรอง technique_id ใน Python"""
    where_filter = {"phase": {"$eq": phase}}
    try:
        results = collection.query(
            query_texts=[query],
            n_results=20, # ดึงมาเผื่อกรอง
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )
        if not results or not results["documents"] or not results["documents"][0]:
            return None
            
        # Filter in python
        filtered_docs = []
        filtered_metas = []
        filtered_dists = []
        
        for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
            tech_ids_str = meta.get("technique_ids", "")
            if technique_id in tech_ids_str:
                filtered_docs.append(doc)
                filtered_metas.append(meta)
                filtered_dists.append(dist)
                if len(filtered_docs) == n_results:
                    break
                    
        if not filtered_docs:
            return None
            
        return {
            "documents": [filtered_docs],
            "metadatas": [filtered_metas],
            "distances": [filtered_dists]
        }
    except Exception as e:
        console.print(f"[red]Query error: {e}[/red]")
        return None


def main():
    console.print("\n[bold cyan]🧪 Omnissiah RAG Retrieval Test[/bold cyan]")
    console.print("ทดสอบว่า metadata filter ทำงานถูกต้อง — ถ้า test ผ่านหมด generation จะแม่นยำ\n")

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    try:
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=EMBEDDING_FN
        )
    except Exception:
        console.print("[red]❌ ไม่พบ ChromaDB collection — กรุณารัน 01_ingest.py ก่อน[/red]")
        sys.exit(1)

    total_count = collection.count()
    console.print(f"[green]✅ เชื่อมต่อ ChromaDB สำเร็จ: {total_count} chunks[/green]\n")

    pass_count = 0
    fail_count = 0

    for test in TEST_CASES:
        console.print(f"[bold]{test['name']}[/bold]")
        console.print(f"  Query: [italic]\"{test['query']}\"[/italic]")
        console.print(f"  Filter: phase=[cyan]{test['phase']}[/cyan], technique=[cyan]{test['technique_id']}[/cyan]")

        results = query_rag(
            collection,
            query=test["query"],
            phase=test["phase"],
            technique_id=test["technique_id"],
        )

        if not results or not results["documents"] or not results["documents"][0]:
            console.print(f"  [red]❌ FAIL: ไม่พบ chunk ที่ตรงกัน[/red]\n")
            fail_count += 1
            continue

        docs = results["documents"][0]
        metas = results["metadatas"][0]
        distances = results["distances"][0]

        # ตรวจผล
        top_doc = docs[0]
        top_meta = metas[0]
        top_distance = distances[0]
        top_similarity = 1 - top_distance  # cosine: distance → similarity

        found_threat = top_meta.get("threat_name", "Unknown")
        not_expected = test.get("expect_NOT_contain", "").lower()
        contains_wrong = not_expected and not_expected in top_doc.lower()

        if contains_wrong:
            status = f"[red]❌ FAIL[/red] — พบข้อความที่ไม่ควรอยู่ใน chunk: '{not_expected}'"
            fail_count += 1
        else:
            status = f"[green]✅ PASS[/green] — Threat: {found_threat} | Similarity: {top_similarity:.3f}"
            pass_count += 1

        console.print(f"  Result: {status}")
        console.print(f"  Top chunk preview: [dim]{top_doc[:120].strip()}...[/dim]\n")

    # สรุป
    total = pass_count + fail_count
    console.print(Panel(
        f"[bold]Test Results: {pass_count}/{total} passed[/bold]\n"
        + ("[green]✅ RAG filter ทำงานถูกต้อง พร้อมรัน 02_generate.py[/green]"
           if fail_count == 0
           else f"[red]⚠ มี {fail_count} test ที่ไม่ผ่าน — ตรวจสอบ metadata ของ playbook ก่อน[/red]"),
        title="🏁 Summary",
        border_style="green" if fail_count == 0 else "red"
    ))

    # แสดง sample chunks ทั้งหมดใน collection
    console.print("\n[bold]📊 Sample chunks ใน ChromaDB (แสดง 10 รายการแรก):[/bold]")
    sample = collection.get(limit=10, include=["metadatas"])
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Threat", style="cyan", width=20)
    table.add_column("Phase", style="green", width=12)
    table.add_column("Sub-process", style="yellow", width=18)
    table.add_column("Techniques", style="white", width=20)

    for m in sample["metadatas"]:
        table.add_row(
            m.get("threat_name", ""),
            m.get("phase", ""),
            m.get("sub_process", ""),
            m.get("technique_ids", "")[:20],
        )
    console.print(table)


if __name__ == "__main__":
    main()
