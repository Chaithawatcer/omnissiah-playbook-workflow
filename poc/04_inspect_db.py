"""
04_inspect_db.py — GUI สำหรับเปิดดู ChromaDB (poc/chroma_db) แบบเห็นภาพ
รัน: streamlit run 04_inspect_db.py
"""

import streamlit as st
import chromadb
from chromadb.utils import embedding_functions
from pathlib import Path

CHROMA_DIR = str(Path(__file__).parent / "chroma_db")
COLLECTION_NAME = "omnissiah_procedures"

st.set_page_config(page_title="Omnissiah Vector DB Inspector", layout="wide")


@st.cache_resource
def get_collection():
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    return client.get_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_functions.DefaultEmbeddingFunction(),
    )


try:
    collection = get_collection()
except Exception as e:
    st.error(f"เปิด ChromaDB ไม่ได้: {e}\n\nรัน `python 01_ingest.py` ก่อนเพื่อสร้าง collection")
    st.stop()

st.title("🗂️ Omnissiah Vector DB Inspector")
st.caption(f"Collection: `{COLLECTION_NAME}` · {collection.count()} chunks")

tab_browse, tab_query = st.tabs(["📚 Browse chunks", "🔍 Test RAG query"])

# ---------- Tab 1: Browse ----------
with tab_browse:
    all_data = collection.get(include=["metadatas", "documents"])
    metas = all_data["metadatas"]
    docs = all_data["documents"]

    threats = sorted({m.get("threat_name", "") for m in metas})
    phases_order = ["preparation", "detection", "containment", "eradication", "post_incident"]

    col1, col2, col3 = st.columns(3)
    with col1:
        sel_threats = st.multiselect("Threat", threats, default=[])
    with col2:
        sel_phases = st.multiselect("Phase", phases_order, default=[])
    with col3:
        sel_source = st.multiselect("Technique source", ["sub", "playbook"], default=[])

    rows = []
    for m, d in zip(metas, docs):
        if sel_threats and m.get("threat_name") not in sel_threats:
            continue
        if sel_phases and m.get("phase") not in sel_phases:
            continue
        if sel_source and m.get("technique_source") not in sel_source:
            continue
        rows.append((m, d))

    st.write(f"**{len(rows)}** chunks ตรงตามตัวกรอง")

    for m, d in rows:
        header = f"[{m.get('threat_name')}] {m.get('phase')} / {m.get('sub_process')} — {m.get('technique_ids')}"
        with st.expander(header):
            st.json(m)
            st.text(d)

# ---------- Tab 2: Query tester ----------
with tab_query:
    st.write("จำลอง `query_rag()` จาก `02_generate.py` — ยิง query ดูว่า retrieval ดึง chunk อะไรมา")

    q_text = st.text_input("Query text", "detect ransomware process activity")
    q_phase = st.selectbox("Phase filter", ["(none)"] + phases_order)
    q_technique = st.text_input("Technique ID filter (เว้นว่าง = ไม่กรอง)", "")
    q_n = st.slider("n_results (ก่อนกรอง technique)", 3, 30, 10)

    if st.button("Run query"):
        where_filter = {"phase": {"$eq": q_phase}} if q_phase != "(none)" else None
        results = collection.query(
            query_texts=[q_text],
            n_results=q_n,
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )

        docs_r = results["documents"][0] if results["documents"] else []
        metas_r = results["metadatas"][0] if results["metadatas"] else []
        dists_r = results["distances"][0] if results["distances"] else []

        shown = 0
        for doc, meta, dist in zip(docs_r, metas_r, dists_r):
            if q_technique and q_technique not in meta.get("technique_ids", ""):
                continue
            shown += 1
            similarity = 1 - dist
            st.markdown(
                f"**{shown}. {meta.get('threat_name')}** — {meta.get('sub_process')} "
                f"(`{meta.get('technique_ids')}`) · similarity `{similarity:.3f}`"
            )
            st.text(doc[:300])
            st.divider()

        if shown == 0:
            st.warning("⚠️ ไม่มี chunk ที่ผ่านตัวกรอง — นี่คือกรณีที่ควรขึ้น Knowledge Coverage Warning ใน 02_generate.py")
