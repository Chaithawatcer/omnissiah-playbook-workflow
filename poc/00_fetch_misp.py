"""
00_fetch_misp.py — Omnissiah CTI Ingestion (MISP → threat_context)

ดึง threat จาก MISP (live API) → สร้าง MITRE ATT&CK mapping จาก 2 แหล่ง:
  1) MISP Galaxy / Tag (mitre-attack-pattern)  → baseline ที่ analyst แท็กไว้
  2) AI mapper (Gemini)                        → เสนอ/ยืนยันเทคนิคเพิ่มจากบริบท event
แล้วเขียนเป็น "review file" (threat_context_*.json) สถานะ pending
เพื่อให้ human-in-the-loop ยืนยัน mapping ก่อนนำไป generate playbook

โหมดทำงาน (แบบ B = review file เป็นหลัก + interactive เสริม):
  # ดึง event แล้วเขียนไฟล์ pending ให้เปิดแก้เอง
  python 00_fetch_misp.py --event-id 1337

  # ดึง + review/approve ในเทอร์มินัลเลย (interactive)
  python 00_fetch_misp.py --event-id 1337 --interactive

  # ทดสอบ offline ด้วย event จำลอง (ไม่ต้องต่อ MISP)
  python 00_fetch_misp.py --mock sample_misp_event.json --interactive

จากนั้น generate:
  python 02_generate.py --context output/threat_context_1337.json

Environment variables:
  MISP_URL         URL ของ MISP instance เช่น https://misp.local
  MISP_KEY         API key ของ MISP
  MISP_VERIFYCERT  "0" เพื่อปิดการ verify TLS (self-signed lab) — default เปิด
  GEMINI_API_KEY   สำหรับ AI mapper (ถ้าไม่มีจะข้าม AI mapping)
"""

import os
import re
import sys
import json
import argparse
import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

# --- Config ---
OUTPUT_DIR = Path(__file__).parent / "output"
MITRE_TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
CONF_RANK = {"high": 3, "medium": 2, "low": 1}

# MISP threat_level_id → severity ของเรา (MISP ไม่มีระดับ Critical โดยตรง)
THREAT_LEVEL_MAP = {"1": "High", "2": "Medium", "3": "Low", "4": "Medium"}


# ─────────────────────────────────────────────────────────────
# 1) โหลด event (live MISP หรือ mock file)
# ─────────────────────────────────────────────────────────────
def load_event_live(event_id: str = None, search_tag: str = None) -> dict:
    """ดึง MISP event ผ่าน PyMISP. คืน dict ของ Event เดียว"""
    try:
        from pymisp import PyMISP
    except ImportError:
        console.print("[red]❌ ไม่พบ pymisp — ติดตั้งด้วย: pip install pymisp[/red]")
        sys.exit(1)

    url = os.environ.get("MISP_URL", "")
    key = os.environ.get("MISP_KEY", "")
    if not url or not key:
        console.print("[red]❌ ต้องตั้งค่า MISP_URL และ MISP_KEY ก่อน (หรือใช้ --mock เพื่อทดสอบ offline)[/red]")
        sys.exit(1)
    verify = os.environ.get("MISP_VERIFYCERT", "1") != "0"

    misp = PyMISP(url, key, ssl=verify)

    if event_id:
        raw = misp.get_event(event_id, pythonify=False)
        if not raw or "Event" not in raw:
            console.print(f"[red]❌ ไม่พบ event id={event_id} บน MISP[/red]")
            sys.exit(1)
        return raw["Event"]

    if search_tag:
        results = misp.search(controller="events", tags=[search_tag], limit=1, pythonify=False)
        if not results:
            console.print(f"[red]❌ ไม่พบ event ที่ tag='{search_tag}'[/red]")
            sys.exit(1)
        first = results[0]
        return first["Event"] if "Event" in first else first

    console.print("[red]❌ ต้องระบุ --event-id หรือ --tag[/red]")
    sys.exit(1)


def load_event_mock(path: str) -> dict:
    """โหลด event จำลองจากไฟล์ JSON (รูปแบบเดียวกับที่ MISP API คืน)"""
    p = Path(path)
    if not p.is_absolute():
        p = Path(__file__).parent / path
    if not p.exists():
        console.print(f"[red]❌ ไม่พบไฟล์ mock: {p}[/red]")
        sys.exit(1)
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("Event", data)


# ─────────────────────────────────────────────────────────────
# 2) สกัดข้อมูลจาก event
# ─────────────────────────────────────────────────────────────
def _parse_attack_string(s: str) -> tuple[str, str]:
    """แยก 'Data Encrypted for Impact - T1486' → (name, technique_id)"""
    m = MITRE_TECH_RE.search(s or "")
    if not m:
        return "", ""
    tid = m.group(0)
    name = s.split(" - " + tid)[0].strip() if (" - " + tid) in s else ""
    return name, tid


def extract_galaxy_techniques(event: dict) -> dict[str, dict]:
    """
    กวาดหา ATT&CK technique จาก Galaxy + Tag ทั้งระดับ event และ attribute
    คืน dict: {technique_id: {"technique_id","name","source":"galaxy"}}
    """
    found: dict[str, dict] = {}

    def add(name: str, tid: str):
        if not tid:
            return
        if tid not in found:
            found[tid] = {"technique_id": tid, "name": name or "", "source": "galaxy"}
        elif name and not found[tid]["name"]:
            found[tid]["name"] = name

    def scan_tags(tags):
        for tag in tags or []:
            tname = tag.get("name", "") if isinstance(tag, dict) else str(tag)
            if "mitre-attack-pattern" in tname:
                # รูปแบบ: misp-galaxy:mitre-attack-pattern="Name - T1486"
                inner = tname.split("=", 1)[-1].strip().strip('"')
                name, tid = _parse_attack_string(inner)
                add(name, tid)

    def scan_galaxies(galaxies):
        for gx in galaxies or []:
            if gx.get("type") != "mitre-attack-pattern":
                continue
            for cl in gx.get("GalaxyCluster", []) or []:
                meta = cl.get("meta", {}) or {}
                ext = meta.get("external_id")
                tid = ""
                if isinstance(ext, list) and ext:
                    tid = ext[0]
                elif isinstance(ext, str):
                    tid = ext
                name, tid2 = _parse_attack_string(cl.get("value", ""))
                add(name, tid or tid2)

    scan_tags(event.get("Tag"))
    scan_galaxies(event.get("Galaxy"))
    for attr in event.get("Attribute", []) or []:
        scan_tags(attr.get("Tag"))
        scan_galaxies(attr.get("Galaxy"))

    return found


def extract_iocs(event: dict) -> list[dict]:
    """ดึง IOCs จาก attributes"""
    iocs = []
    for attr in event.get("Attribute", []) or []:
        iocs.append({
            "type": attr.get("type", ""),
            "value": attr.get("value", ""),
            "category": attr.get("category", ""),
            "comment": attr.get("comment", ""),
        })
    return iocs


def extract_context_names(event: dict) -> list[str]:
    """ดึงชื่อ malware/actor/ransomware จาก galaxy อื่นๆ (ไม่ใช่ attack-pattern) เพื่อเป็นบริบทให้ AI"""
    names = []
    for gx in event.get("Galaxy", []) or []:
        if gx.get("type") == "mitre-attack-pattern":
            continue
        for cl in gx.get("GalaxyCluster", []) or []:
            v = cl.get("value")
            if v:
                names.append(v)
    for tag in event.get("Tag", []) or []:
        tname = tag.get("name", "")
        if "misp-galaxy:" in tname and "mitre-attack-pattern" not in tname:
            names.append(tname.split("=", 1)[-1].strip().strip('"'))
    return list(dict.fromkeys(names))  # dedupe รักษาลำดับ


def derive_severity(event: dict) -> str:
    """map threat_level_id → severity + ยกระดับเป็น Critical ถ้ามี tag บ่งชี้"""
    for tag in event.get("Tag", []) or []:
        if "critical" in tag.get("name", "").lower():
            return "Critical"
    return THREAT_LEVEL_MAP.get(str(event.get("threat_level_id", "")), "Medium")


# ─────────────────────────────────────────────────────────────
# 3) AI mapper
# ─────────────────────────────────────────────────────────────
def ai_map_techniques(event_summary: str, galaxy_techs: list[str]) -> list[dict]:
    """
    ใช้ Gemini เสนอ ATT&CK technique จากบริบท event
    - ถ้า galaxy มีอยู่แล้ว → AI "เสริม" เทคนิคเพิ่ม + ยืนยันตัวเดิม
    - ถ้า galaxy ว่าง → AI "สร้างชุดเทคนิคให้ครบ" ครอบคลุมทุก phase ของการโจมตี
    คืน list ของ {technique_id, name, source:"ai", confidence, reason}
    ถ้าไม่มี GEMINI_API_KEY → คืน [] (ข้าม AI mapping)
    """
    galaxy_empty = not galaxy_techs
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        console.print("[yellow]⚠ ไม่พบ GEMINI_API_KEY — ข้าม AI mapping (ใช้เฉพาะ Galaxy)[/yellow]")
        return []

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-flash-lite-latest")
    except Exception as e:
        console.print(f"[yellow]⚠ เริ่ม Gemini ไม่สำเร็จ ({e}) — ข้าม AI mapping[/yellow]")
        return []

    if galaxy_empty:
        task_instruction = (
            "**สำคัญ:** MISP ไม่มีการแท็กเทคนิค ATT&CK ไว้เลย — คุณต้องเป็นผู้ระบุเทคนิคที่เกี่ยวข้อง"
            " **ทั้งหมดให้ครบถ้วน** โดยไล่ให้ครอบคลุมทุกขั้นของการโจมตีเท่าที่หลักฐานใน event บ่งชี้"
            " (เช่น Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion,"
            " Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact)"
            " ให้เสนอ 5–12 เทคนิคที่น่าจะเกี่ยวข้องที่สุด"
        )
    else:
        task_instruction = (
            "เสนอเทคนิคที่ \"ควรเพิ่ม\" นอกเหนือจากที่แท็กไว้ และยืนยันตัวที่แท็กไว้ถ้าเห็นด้วย"
        )

    prompt = f"""คุณคือนักวิเคราะห์ Threat Intelligence ผู้เชี่ยวชาญ MITRE ATT&CK (Enterprise)
จากข้อมูล threat ด้านล่าง ให้ระบุ MITRE ATT&CK technique ที่เกี่ยวข้อง

**ข้อมูล Threat จาก MISP:**
{event_summary}

**เทคนิคที่ analyst แท็กไว้แล้ว (MISP Galaxy):** {', '.join(galaxy_techs) if galaxy_techs else 'ไม่มี'}

คำสั่ง:
- {task_instruction}
- ใช้เฉพาะ technique ID ที่มีจริงใน ATT&CK Enterprise (รูปแบบ Txxxx หรือ Txxxx.xxx)
- ห้ามแต่ง ID ที่ไม่มีจริง
- ตอบเป็น JSON array เท่านั้น ห้ามมีข้อความอื่น รูปแบบ:
[
  {{"technique_id": "T1570", "name": "Lateral Tool Transfer", "confidence": "high", "reason": "เหตุผลสั้นๆ ภาษาไทยอิงหลักฐานใน event"}}
]
- confidence เป็นหนึ่งใน: high, medium, low
"""
    try:
        resp = model.generate_content(prompt)
        text = resp.text.strip()
        # ตัด code fence ถ้ามี
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
        # จับเฉพาะ array
        start, end = text.find("["), text.rfind("]")
        if start != -1 and end != -1:
            text = text[start:end + 1]
        data = json.loads(text)
    except Exception as e:
        console.print(f"[yellow]⚠ อ่านผล AI mapping ไม่สำเร็จ ({e}) — ใช้เฉพาะ Galaxy[/yellow]")
        return []

    out = []
    for item in data if isinstance(data, list) else []:
        tid_match = MITRE_TECH_RE.search(str(item.get("technique_id", "")))
        if not tid_match:
            continue
        conf = str(item.get("confidence", "medium")).lower()
        if conf not in CONF_RANK:
            conf = "medium"
        out.append({
            "technique_id": tid_match.group(0),
            "name": str(item.get("name", "")).strip(),
            "source": "ai",
            "confidence": conf,
            "reason": str(item.get("reason", "")).strip(),
        })
    return out


def ai_enrich_description(context: dict) -> str | None:
    """
    ใช้ Gemini เขียน description ของภัยแบบละเอียด อิงเทคนิคที่ "อนุมัติแล้ว" + IOCs
    เพื่อใช้เป็นบริบทตอน generate playbook (แทน description แบบสั้นจาก event.info)
    คืน string ใหม่ หรือ None ถ้าทำไม่ได้ (จะคง description เดิม)
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        console.print("[yellow]⚠ ไม่พบ GEMINI_API_KEY — ข้าม AI enrichment (ใช้ description เดิม)[/yellow]")
        return None
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-flash-lite-latest")
    except Exception as e:
        console.print(f"[yellow]⚠ เริ่ม Gemini ไม่สำเร็จ ({e}) — ข้าม enrichment[/yellow]")
        return None

    approved = [m for m in context["mapping"] if m.get("approved")]
    tech_lines = "\n".join(f"- {m['technique_id']} {m.get('name','')}" for m in approved)
    ioc_types = ", ".join(sorted({i.get("type", "") for i in context.get("iocs", []) if i.get("type")}))

    prompt = f"""คุณคือนักวิเคราะห์ Threat Intelligence
เขียน "คำอธิบายภัยคุกคาม" (threat description) เป็นภาษาไทย กระชับ 3–5 ประโยค สำหรับใช้เป็นบริบทของ IR playbook

ชื่อภัย: {context.get('threat_name','')}
ความรุนแรง: {context.get('severity','')}
เทคนิค MITRE ATT&CK ที่ยืนยันแล้ว:
{tech_lines if tech_lines else '- (ไม่มี)'}
ประเภท IOC ที่พบ: {ioc_types or '(ไม่มี)'}

ให้ครอบคลุม: ลักษณะภัย, วิธีการโจมตีหลัก (อิงเทคนิคข้างบน), เป้าหมาย/ผลกระทบ, และจุดสังเกตสำคัญ
ตอบเฉพาะเนื้อความคำอธิบาย ห้ามมีหัวข้อ ห้ามขึ้นต้นด้วยคำทักทายหรือ 'นี่คือ...' ห้ามใส่ bullet"""
    try:
        resp = model.generate_content(prompt)
        text = (resp.text or "").strip()
        return text or None
    except Exception as e:
        console.print(f"[yellow]⚠ AI enrichment ล้มเหลว ({e}) — ใช้ description เดิม[/yellow]")
        return None


# ─────────────────────────────────────────────────────────────
# 4) merge galaxy + ai → mapping list
# ─────────────────────────────────────────────────────────────
def merge_mappings(galaxy: dict[str, dict], ai: list[dict]) -> list[dict]:
    """
    รวม galaxy (analyst แท็ก) + ai (โมเดลเสนอ) เป็น mapping เดียว
    - galaxy: approved=True โดย default (คนตั้งใจแท็ก) confidence=high
    - ai-only: approved=False (ต้องให้ human ยืนยันก่อน) confidence ตามที่ AI ให้
    - อยู่ทั้งสอง: source="galaxy+ai", approved=True
    """
    merged: dict[str, dict] = {}

    for tid, g in galaxy.items():
        merged[tid] = {
            "technique_id": tid,
            "name": g.get("name", ""),
            "source": "galaxy",
            "confidence": "high",
            "reason": "analyst แท็กไว้ใน MISP Galaxy",
            "approved": True,
        }

    for a in ai:
        tid = a["technique_id"]
        if tid in merged:
            merged[tid]["source"] = "galaxy+ai"
            if a.get("reason"):
                merged[tid]["reason"] += f" | AI: {a['reason']}"
            if not merged[tid]["name"] and a.get("name"):
                merged[tid]["name"] = a["name"]
        else:
            merged[tid] = {
                "technique_id": tid,
                "name": a.get("name", ""),
                "source": "ai",
                "confidence": a.get("confidence", "medium"),
                "reason": a.get("reason", ""),
                "approved": False,  # AI เดา → human ต้องยืนยัน
            }

    # เรียง: approved ก่อน แล้ว confidence สูงก่อน แล้วตาม ID
    return sorted(
        merged.values(),
        key=lambda m: (not m["approved"], -CONF_RANK.get(m["confidence"], 0), m["technique_id"]),
    )


# ─────────────────────────────────────────────────────────────
# 5) build / save / display threat_context
# ─────────────────────────────────────────────────────────────
def build_context(event: dict, mapping: list[dict], iocs: list[dict],
                  severity: str, source_ref: str) -> dict:
    threat_name = (event.get("info") or "Unknown Threat").strip()
    description = threat_name
    ctx_names = extract_context_names(event)
    if ctx_names:
        description += " | เกี่ยวข้อง: " + ", ".join(ctx_names)

    return {
        "status": "pending",  # pending → approved (human-in-the-loop gate)
        "threat_name": threat_name,
        "severity": severity,
        "description": description,
        "description_source": "event",  # จะกลายเป็น "ai" หลัง enrichment
        "source": {
            "type": source_ref,
            "misp_event_info": threat_name,
            "misp_event_id": str(event.get("id", "")),
            "misp_uuid": event.get("uuid", ""),
            "org": (event.get("Org") or {}).get("name", ""),
            "event_date": event.get("date", ""),
            "fetched_at": datetime.datetime.now().isoformat(timespec="seconds"),
        },
        "mapping": mapping,
        "iocs": iocs,
        "review": {"reviewed_by": None, "reviewed_at": None, "notes": ""},
    }


def summarize_event(event: dict, iocs: list[dict], ctx_names: list[str]) -> str:
    """สร้างสรุป event เป็นข้อความให้ AI ใช้ map"""
    lines = [f"ชื่อ event: {event.get('info','')}"]
    if ctx_names:
        lines.append(f"Malware/Actor ที่เกี่ยวข้อง: {', '.join(ctx_names)}")
    if iocs:
        lines.append("ตัวบ่งชี้ (IOCs):")
        for i in iocs[:20]:
            c = f" ({i['comment']})" if i.get("comment") else ""
            lines.append(f"  - {i['type']}: {i['value']}{c}")
    return "\n".join(lines)


def display_mapping(context: dict):
    table = Table(title=f"🎯 ATT&CK Mapping — {context['threat_name']}", show_header=True)
    table.add_column("✔", justify="center")
    table.add_column("Technique", style="cyan")
    table.add_column("ชื่อ")
    table.add_column("ที่มา", style="magenta")
    table.add_column("Conf")
    table.add_column("เหตุผล", overflow="fold", max_width=48)
    for m in context["mapping"]:
        check = "[green]✅[/green]" if m["approved"] else "[red]⬜[/red]"
        conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(m["confidence"], "white")
        table.add_row(
            check, m["technique_id"], m.get("name", ""),
            m["source"], f"[{conf_color}]{m['confidence']}[/{conf_color}]", m.get("reason", ""),
        )
    console.print(table)
    approved = [m["technique_id"] for m in context["mapping"] if m["approved"]]
    console.print(f"\n[bold]เทคนิคที่อนุมัติแล้ว ({len(approved)}):[/bold] "
                  f"[green]{', '.join(approved) if approved else '— ยังไม่มี —'}[/green]")
    console.print(f"[bold]สถานะ:[/bold] {'[green]approved[/green]' if context['status']=='approved' else '[yellow]pending[/yellow]'}")


def save_context(context: dict, out_path: Path):
    OUTPUT_DIR.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8")


def run_generate(context_path: Path):
    """เรียก 02_generate.py ต่อทันทีหลังอนุมัติ (chain ให้จบในคำสั่งเดียว)"""
    import subprocess
    script = Path(__file__).parent / "02_generate.py"
    console.print(Panel(
        f"[bold]▶️  เริ่มสร้าง playbook ต่อ...[/bold]\n"
        f"python 02_generate.py --context {context_path}",
        title="🔗 Auto-generate", border_style="cyan"
    ))
    result = subprocess.run([sys.executable, str(script), "--context", str(context_path)])
    if result.returncode != 0:
        console.print(
            "[red]❌ generate ไม่สำเร็จ[/red] — ตรวจว่าตั้ง GEMINI_API_KEY แล้ว "
            "และรัน 01_ingest.py สร้าง ChromaDB ไว้หรือยัง\n"
            f"[yellow]context ถูกบันทึกไว้แล้วที่ {context_path} — รัน generate ซ้ำเองได้[/yellow]"
        )


# ─────────────────────────────────────────────────────────────
# 6) interactive review loop
# ─────────────────────────────────────────────────────────────
def interactive_review(context: dict):
    console.print(Panel(
        "[bold]โหมด Interactive Review[/bold] — ยืนยัน ATT&CK mapping ก่อน generate\n"
        "คำสั่ง:\n"
        "  [cyan]a Txxxx[/cyan]     สลับสถานะอนุมัติของเทคนิค (toggle)\n"
        "  [cyan]all[/cyan]         ติ๊กอนุมัติทุกเทคนิค\n"
        "  [cyan]none[/cyan]        เอาติ๊กออกทุกเทคนิค\n"
        "  [cyan]add Txxxx[/cyan]   เพิ่มเทคนิคเอง (จะถูกอนุมัติทันที)\n"
        "  [cyan]rm Txxxx[/cyan]    ลบเทคนิคออกจาก mapping\n"
        "  [cyan]ok[/cyan]          ยืนยัน (status=approved) → บันทึก → generate ต่อทันที\n"
        "  [cyan]q[/cyan]           บันทึกเป็น pending แล้วออก (ยังไม่อนุมัติ)",
        border_style="cyan"
    ))

    def find(tid):
        tid = tid.upper()
        for m in context["mapping"]:
            if m["technique_id"] == tid:
                return m
        return None

    while True:
        display_mapping(context)
        cmd = Prompt.ask("\n[bold]> คำสั่ง[/bold]").strip()
        if not cmd:
            continue
        parts = cmd.split()
        verb = parts[0].lower()

        if verb == "q":
            context["status"] = "pending"
            console.print("[yellow]บันทึกเป็น pending (ยังไม่อนุมัติ)[/yellow]")
            return
        if verb == "ok":
            if not any(m["approved"] for m in context["mapping"]):
                console.print("[red]❌ ต้องอนุมัติอย่างน้อย 1 เทคนิคก่อน[/red]")
                continue
            reviewer = Prompt.ask("ชื่อผู้อนุมัติ (reviewed_by)", default=os.environ.get("USERNAME", "analyst"))
            context["status"] = "approved"
            context["review"]["reviewed_by"] = reviewer
            context["review"]["reviewed_at"] = datetime.datetime.now().isoformat(timespec="seconds")
            console.print("[green]✅ อนุมัติแล้ว[/green]")
            return
        if verb == "all":
            for m in context["mapping"]:
                m["approved"] = True
            continue
        if verb == "none":
            for m in context["mapping"]:
                m["approved"] = False
            continue
        if verb == "a" and len(parts) == 2:
            m = find(parts[1])
            if m:
                m["approved"] = not m["approved"]
            else:
                console.print(f"[red]ไม่พบ {parts[1]}[/red]")
            continue
        if verb == "rm" and len(parts) == 2:
            m = find(parts[1])
            if m:
                context["mapping"].remove(m)
            else:
                console.print(f"[red]ไม่พบ {parts[1]}[/red]")
            continue
        if verb == "add" and len(parts) == 2:
            tid_match = MITRE_TECH_RE.fullmatch(parts[1].upper())
            if not tid_match:
                console.print("[red]รูปแบบไม่ถูกต้อง (ต้องเป็น Txxxx หรือ Txxxx.xxx)[/red]")
                continue
            tid = tid_match.group(0)
            if find(tid):
                console.print(f"[yellow]{tid} มีอยู่แล้ว[/yellow]")
                continue
            name = Prompt.ask("ชื่อเทคนิค (กด Enter ข้ามได้)", default="")
            context["mapping"].append({
                "technique_id": tid, "name": name, "source": "manual",
                "confidence": "high", "reason": "เพิ่มโดย analyst", "approved": True,
            })
            continue
        console.print("[red]คำสั่งไม่ถูกต้อง[/red]")


# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Omnissiah MISP → threat_context")
    src = parser.add_argument_group("แหล่งข้อมูล")
    src.add_argument("--event-id", type=str, help="MISP event id (live API)")
    src.add_argument("--tag", type=str, help="ค้นหา event แรกที่มี tag นี้ (live API)")
    src.add_argument("--mock", type=str, help="ไฟล์ JSON event จำลอง (ทดสอบ offline)")
    parser.add_argument("--interactive", action="store_true", help="review/approve ในเทอร์มินัล")
    parser.add_argument("--no-ai", action="store_true", help="ข้าม AI mapping (ใช้เฉพาะ Galaxy)")
    parser.add_argument("--no-enrich", dest="enrich", action="store_false",
                        help="ไม่ต้องให้ AI เขียน description แบบละเอียดหลังอนุมัติ")
    parser.add_argument("--no-generate", dest="generate", action="store_false",
                        help="ไม่ต้องรัน 02_generate ต่ออัตโนมัติหลังอนุมัติ")
    parser.add_argument("--out", type=str, help="path ไฟล์ output (default: output/threat_context_<id>.json)")
    args = parser.parse_args()

    # 1) โหลด event
    if args.mock:
        event = load_event_mock(args.mock)
        source_ref = "mock"
    else:
        event = load_event_live(event_id=args.event_id, search_tag=args.tag)
        source_ref = "misp"

    console.print(f"\n[bold cyan]🛰️  MISP Event:[/bold cyan] {event.get('info','')} "
                  f"[dim](id={event.get('id','?')})[/dim]")

    # 2) สกัด galaxy + iocs + context
    galaxy = extract_galaxy_techniques(event)
    iocs = extract_iocs(event)
    ctx_names = extract_context_names(event)
    severity = derive_severity(event)
    console.print(f"[green]✔ Galaxy techniques:[/green] {', '.join(galaxy.keys()) if galaxy else '— ไม่มี —'}")
    console.print(f"[green]✔ IOCs:[/green] {len(iocs)}  |  [green]Severity:[/green] {severity}")

    # 3) AI mapping
    ai = []
    if not args.no_ai:
        if not galaxy:
            console.print("[yellow]🤖 Galaxy ไม่มีเทคนิค — ให้ AI สร้างชุดเทคนิคให้ครบทั้งหมด...[/yellow]")
        else:
            console.print("[cyan]🤖 AI กำลังวิเคราะห์เทคนิคเพิ่มเติม...[/cyan]")
        summary = summarize_event(event, iocs, ctx_names)
        ai = ai_map_techniques(summary, list(galaxy.keys()))
        console.print(f"[green]✔ AI เสนอ:[/green] {', '.join(a['technique_id'] for a in ai) if ai else '— ไม่มี —'}")
    elif not galaxy:
        console.print("[red]⚠ ปิด AI (--no-ai) และ Galaxy ก็ว่าง → จะไม่มีเทคนิคเลย[/red]")

    # 4) merge + build context
    mapping = merge_mappings(galaxy, ai)
    if not mapping:
        console.print("[red]❌ ไม่พบเทคนิคใดๆ ทั้งจาก Galaxy และ AI — ตรวจสอบ event[/red]")
        sys.exit(1)
    context = build_context(event, mapping, iocs, severity, source_ref)

    # 5) review
    if args.interactive:
        interactive_review(context)
    else:
        display_mapping(context)
        console.print(
            "\n[yellow]📝 นี่คือ review file สถานะ 'pending'[/yellow]\n"
            "   เปิดไฟล์แก้ mapping (ตั้ง \"approved\": true/false ต่อเทคนิค)\n"
            "   แล้วเปลี่ยน \"status\" เป็น \"approved\" ก่อน generate\n"
            "   หรือรันซ้ำด้วย [cyan]--interactive[/cyan] เพื่อยืนยันในเทอร์มินัล"
        )

    # 6) AI enrichment — หลังอนุมัติแล้ว ให้ AI เขียน description ละเอียดอิงเทคนิคที่ยืนยัน
    if context["status"] == "approved" and args.enrich:
        console.print("[cyan]🤖 AI กำลังเขียน description แบบละเอียด...[/cyan]")
        enriched = ai_enrich_description(context)
        if enriched:
            context["description"] = enriched
            context["description_source"] = "ai"
            console.print(Panel(enriched, title="📝 AI Description", border_style="cyan"))

    # 7) save
    eid = event.get("id", "event")
    out_path = Path(args.out) if args.out else OUTPUT_DIR / f"threat_context_{eid}.json"
    save_context(context, out_path)

    console.print(Panel(
        f"📄 บันทึก: [cyan]{out_path}[/cyan]\n"
        f"สถานะ: {'[green]approved ✅ พร้อม generate[/green]' if context['status']=='approved' else '[yellow]pending ⏳ รอยืนยัน[/yellow]'}\n\n"
        f"[bold]ขั้นต่อไป:[/bold]\n"
        f"  python 02_generate.py --context {out_path}",
        title="🛰️ Omnissiah CTI", border_style="green"
    ))

    # 8) auto-generate: ถ้าอนุมัติแล้ว → รัน 02_generate ต่อทันที (เว้นแต่ --no-generate)
    if context["status"] == "approved" and args.generate:
        run_generate(out_path)
    elif context["status"] != "approved":
        console.print("[yellow]ℹ️  ยังไม่อนุมัติ → ยังไม่ generate (อนุมัติก่อนแล้วจะ generate ให้อัตโนมัติ)[/yellow]")


if __name__ == "__main__":
    main()
