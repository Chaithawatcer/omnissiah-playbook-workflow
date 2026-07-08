# Omnissiah — RAG-based Incident Response Playbook Generator

KMITL Faculty of IT year-4 capstone project (2-person group). Goal: auto-generate Incident Response Playbooks using **RAG + LLM (Gemini) + Vector DB (ChromaDB)**, mapped to MITRE ATT&CK techniques.

- Full target-system design (n8n orchestration, Playbook Store, Draft/Verified/Deprecated lifecycle, SLA review gates — mostly **not yet implemented**): [architecture.md](architecture.md)
- What's actually implemented in code today, explained from real code lines: [poc-architecture.md](poc-architecture.md)

**Do not confuse the two** — `architecture.md` describes the full future vision; `poc-architecture.md` describes the working PoC in `poc/`.

## Session routine (do this EVERY session)

This is a 2-person project — the teammate pushes work between sessions. **At the start of every session:**

1. `git fetch` + `git pull` on the current branch (`test-generate`) — if local generated artifacts (`poc/chroma_db/`) block the merge, stash/discard them; they're regenerable via `01_ingest.py`.
2. **Read [HANDOFF.md](HANDOFF.md)** — it's the running log both teammates (and their Claude sessions) use to hand off work. Summarize new entries to the user before starting new work.
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

## Current work (branch `test-generate`)

Redesigning chunking/metadata: per-sub MITRE tagging with a `technique_source` flag (`sub` vs `playbook` fallback), coverage-warning banners, and curating the 15 seed playbooks into human-written canonical format (`01_wannacry.md` is the reference example — frontmatter + 5 NIST phases + tagged subs; `detection_queries`/`scope_analysis` subs are deprecated).

**Curation status:** existing playbook *content* is already high quality (specific tools/Event IDs/commands, not AI-generic) per a full 15-file review — the mixed strategy is "keep + reformat", not "rewrite from scratch". Only `01_wannacry.md` (full) and `04_brute_force.md`/`14_rdp.md` (partial, for the collision fix above) have sub-technique tags; the other ~12 playbooks still need tagging + `detection_queries`/`scope_analysis` removal, but that's mechanical reformatting work, not authoring new content. With limited time before deadline, prioritize review/reformat/test over hand-writing all 15 from scratch.

**Framing for the advisor:** the assignment goal is to *study how RAG + Vector DB + LLM mechanically interact*, not to ship a complete product — when scoping remaining work, favor demonstrating/documenting findings (metadata-filter-vs-semantic-only, chunking granularity, weak-anchor retrieval failure, honest coverage warnings) over feature completeness.

**Deferred idea (teammate's proposal, not yet started):** restructure the KB from threat-centric docs to sub-technique-centric chunks, and have RAG assemble a playbook by combining technique-level chunks instead of retrieving from one threat's doc. Upside: eliminates duplicate technique content across threats (the root cause of the BF/RDP collision above). Risk: content per technique varies by threat context (e.g. T1078 containment is "revoke DB app account" for SQLi vs "reset privileged AD account" for Credential Dumping) — a single canonical-per-technique chunk risks becoming too generic. Shelved as a post-deadline direction; a small proof-of-concept (one shared technique across 3 threats) is reasonable to demo the idea without migrating the whole KB.

## Tech stack

n8n (workflow, not yet built) · Gemini API (`gemini-flash-lite-latest`) · ChromaDB (cosine similarity) · `sentence-transformers` `all-MiniLM-L6-v2` (local embedding) · Python
