# Omnissiah — RAG-based Incident Response Playbook Generator

KMITL Faculty of IT year-4 capstone project (2-person group). Goal: auto-generate Incident Response Playbooks using **RAG + LLM (Gemini) + Vector DB (ChromaDB)**, mapped to MITRE ATT&CK techniques.

- Full target-system design (n8n orchestration, Playbook Store, Draft/Verified/Deprecated lifecycle, SLA review gates — mostly **not yet implemented**): [architecture.md](architecture.md)
- What's actually implemented in code today, explained from real code lines: [poc-architecture.md](poc-architecture.md)

**Do not confuse the two** — `architecture.md` describes the full future vision; `poc-architecture.md` describes the working PoC in `poc/`.

## Session routine (do this EVERY session)

This is a 2-person project — the teammate pushes work between sessions. **At the start of every session:**

1. `git fetch` + `git pull` on the current branch (`test-generate`) — if local generated artifacts (`poc/chroma_db/`) block the merge, stash/discard them; they're regenerable via `01_ingest.py`.
2. **Read [HANDOFF.md](HANDOFF.md)** — it's the running log both teammates (and their Claude sessions) use to hand off work. Summarize new entries to the user before starting new work.
2.5. **Check open GitHub Issues** (`gh issue list`) — the team splits work via Issues on this repo (labels: `system-1`/`system-2`/`kb-curation`/`adapter`/`docs`/`decision-needed`). When finishing work that closes an issue, reference it in the commit (`fix #N`). gh CLI is installed and authenticated as Chaithawatcer.
3. If playbooks or ingest logic changed in the pull, re-run `python poc/01_ingest.py` before trusting any retrieval/generation results — the local ChromaDB is stale otherwise.

**At the end of any session that changed code/docs/design decisions:** append a new entry to `HANDOFF.md` (never edit old entries — add a new section instead), then commit and push so the teammate sees it. Include: what was done, what was designed-but-not-implemented, open questions for the teammate, and next steps.

## PoC structure (`poc/`)

| File | Role |
|---|---|
| [poc/01_ingest.py](poc/01_ingest.py) | Chunk playbooks (by `## Phase:` / `### Sub:`), tag technique_ids per-sub, embed (local `sentence-transformers`, no API), store in ChromaDB |
| [poc/02_generate.py](poc/02_generate.py) | `query_rag()` (2-layer filter: metadata phase + Python technique post-filter), `check_technique_coverage()`, `generate_section()` (Gemini), per-section loop, assembly |
| [poc/03_test_retrieval.py](poc/03_test_retrieval.py) | Sanity-checks metadata filtering before trusting generation output |
| [poc/technique_mapping.json](poc/technique_mapping.json) | threat name → MITRE technique_ids table (15 threats) |
| [poc/playbooks/](poc/playbooks/) | Knowledge base source, 15 `.md` files → ~200 chunks |
| [poc/mastertemplate.md](poc/mastertemplate.md) | Threat-agnostic template (never chunked/embedded — sent whole into the LLM prompt) |
| [poc/AUTHORING_GUIDE.md](poc/AUTHORING_GUIDE.md) | Rules for hand-writing/tagging playbooks to match the pipeline |

## Non-obvious rules / gotchas

- **Mastertemplate never enters the vector DB.** Chunking would destroy its slot structure ("template explosion"). It's injected directly into the LLM prompt instead; only the 5 phase-procedure docs get embedded.
- **Metadata filter before semantic similarity.** RAG retrieval filters by `phase` (ChromaDB `where`) then by `technique_ids` (Python post-filter, since Chroma doesn't support `$contains` on array fields) — pure similarity search alone pulls in irrelevant cross-threat chunks.
- **Fail loudly, not silently.** `check_technique_coverage()` and the zero-chunk case in `query_rag()` must surface a `⚠️ Knowledge Coverage Warning` / Zero-Day banner rather than silently falling back to unrelated chunks. A past bug (`include=["ids"]` breaking the Chroma query, and a phase-only fallback) caused the warning to never fire even when a technique had zero KB support — treat any "fallback that widens retrieval instead of returning empty" as suspect.
- **Sub-technique tagging beats whole-playbook tagging.** Tag MITRE techniques at the `### Sub: name [Txxxx]` level, not just in frontmatter — techniques sharing a log source (e.g. same Sysmon Event ID) across threats otherwise cause heavy cross-threat chunk pollution.
- **Template placeholders are `snake_case`, threat-agnostic** — never hardcode a threat name in the mastertemplate; use `{{threat_name}}` etc.
- **Human review gates containment/eradication** in the full design — never auto-execute remediation.
- Cross-threat retrieval isn't automatically a bug: if a technique (e.g. T1078) is genuinely used by multiple threats, pulling its chunk for more than one threat is correct RAG behavior. Only suspect it when the query lacks a specific anchor keyword.
- **A generic threat name loses the retrieval race to a specific one.** Tested: querying "Brute Force" (broad name, weak semantic anchor) got its own chunks only 1/5 — RDP Brute Force / Lateral Movement / Credential Dumping chunks (sharing `T1078`/`T1021.001`) crowded it out, because those threat names are more specific. Querying "RDP Brute Force" stayed anchored (4/5 own chunks) since "RDP" is a distinctive term. This is a vector-search failure mode independent of metadata tagging — sub-technique tags don't fix it when the *techniques themselves* are identical between two threats.
- **`Brute Force` and `RDP Brute Force` technique sets were deliberately de-collided**, not merged: `technique_mapping.json` gives Brute Force `[T1110.001, T1110.003, T1078]` (RDP's `T1021.001` removed, Password Spraying `T1110.003` added) and RDP Brute Force keeps `[T1110.001, T1021.001, T1078]`. RDP-specific content (e.g. Logon Type 10) was moved out of `04_brute_force.md` into the RDP playbook. Residual overlap on `T1110.001`/`T1078` is intentional — RDP brute force genuinely is a brute force.

## Architecture v3 — two systems sharing one CTI head (the "fire escape")

The project is deliberately **two self-contained systems** that share the CTI ingestion head + central `threat_context.json` schema, so if one breaks before the exam defense the other still demos:
- **System 1 — Playbook Generator**: input → MITRE mapping → RAG → full IR Playbook (this is the original PoC in `poc/`, working end-to-end).
- **System 2 — TI Feed Annotation** (📋 planned, not built): from the same `threat_context.json`, run the LLM twice to emit a **dual-audience advisory** — an executive version (plain language, no jargon) and a technical version (T-numbers, IOCs, links to the full playbook). Reuse the `ai_enrich_description()` pattern in `poc/00_fetch_misp.py`.

**Input = 3 adapters + 1 fallback**, all normalizing into `threat_context.json` (don't look for one algorithm that covers all): (1) User report/symptom → LLM mapper (low confidence), (2) SIEM/EDR alert → parse the ATT&CK tag already on the alert (high confidence), (3) IOC/CTI → MISP Galaxy / VirusTotal / OTX enrichment (medium). Fallback = `--threat "WannaCry"` straight into System 1 via `technique_mapping.json`. Only the CTI/MISP adapter (`poc/00_fetch_misp.py`) is built so far.

**Single Human Review gate at the END (v3, advisor feedback 2026-07-08):** do NOT gate mapping approval before generation. Let the pipeline run automatically to a Draft, then the reviewer checks mapping (with source/confidence labels) AND playbook content together, once. Rationale: generation is cheap, two gates = duplicated human work. Hard rule unchanged: nothing becomes Verified without a human; never auto-execute containment/eradication. **The code (`poc/00_fetch_misp.py`) still implements the old v2 pre-generation gate — see GitHub issue #2 to migrate it.**

**Full design doc:** [architecture.md](architecture.md) is now v3 (CTI/human-in-the-loop, has a changelog at the bottom). [poc-architecture.md](poc-architecture.md) = what's actually in code.

## Current work (branch `test-generate`)

**Now in the proposal phase** — advisor needs to sign the topic proposal. Draft ready at [proposal-draft.md](proposal-draft.md); formatted Word version at `Omnissiah_Proposal.docx` (repo root, git-ignored — personal deliverable, convert to Google Doc via Drive import). Assignment framing (say this to the advisor): the goal is to *study how RAG + Vector DB + LLM mechanically interact*, not to ship a complete product.

**Hybrid KB (teammate implemented in `ed0a700`, was previously the "deferred technique-centric idea"):** the KB now mixes threat-centric playbooks with **technique-centric reference playbooks** (one doc per shared technique, e.g. `technique_T1486_*.md`) to cut duplicate content. `02_generate.py` gained **tiered retrieval** (primary = own-threat/sub-tagged, secondary = other docs same technique, fallback = phase-only + flagged). Re-run `python poc/01_ingest.py` after pulling — KB changed a lot.

**Curation status:** playbook *content* is already high quality (specific tools/Event IDs/commands) — strategy is "keep + reformat", not rewrite. `01_wannacry.md` fully sub-tagged; `04_brute_force.md`/`14_rdp_bruteforce.md` partial; ~10 more still need tagging (issue #5).

**⚠️ Two open decisions before trusting the KB / writing "15 threats" in the proposal (GitHub issues #3, #4):**
- **#3:** `ed0a700` reverted Brute Force in `technique_mapping.json` back to `[T1110.001, T1078, T1021.001]`, which re-collides with RDP Brute Force and contradicts `04_brute_force.md`'s frontmatter `[T1110.001, T1110.003, T1078]`. Confirm with teammate whether intentional.
- **#4:** `ed0a700` deleted `08_data_exfiltration.md` + `11_dns_tunneling.md` with no technique-doc replacement — T1041/T1048/T1071.004/T1568 now have zero KB coverage (KB is effectively 13 threats, not 15).

## Tech stack

n8n (workflow, not yet built) · Gemini API (`gemini-flash-lite-latest`) · ChromaDB (cosine similarity) · `sentence-transformers` `all-MiniLM-L6-v2` (local embedding) · Python
