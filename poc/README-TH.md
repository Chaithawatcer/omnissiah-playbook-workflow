# 🛡️ คู่มือการใช้งานระบบ Omnissiah RAG PoC (ภาษาไทย)

นี่คือโปรเจกต์แบบ Proof of Concept (PoC) สำหรับระบบสร้าง Incident Response Playbook อัตโนมัติ (Omnissiah) โดยใช้เทคโนโลยี **RAG (Retrieval-Augmented Generation)** ร่วมกับ **Gemini 2.0 Flash** 

หลักการทำงานคือการนำ Playbook ต้นฉบับทั้ง 15 เล่มมาแยกส่วน (Chunk) แล้วเก็บลง Vector Database (ChromaDB) จากนั้นเมื่อระบบต้องการสร้าง Playbook ใหม่ ระบบจะดึงข้อมูลที่เกี่ยวข้องกับภัยคุกคามนั้นๆ (กรองด้วย Phase และ Technique ID) มาให้ AI สรุปและเขียนออกมาตาม Master Template

---

## 🛠️ ข้อกำหนดเบื้องต้น (Prerequisites)

1. **Python 3.10+** (ทดสอบการทำงานบน Windows PowerShell)
2. **Gemini API Key**: สามารถรับได้ฟรีจาก [Google AI Studio](https://aistudio.google.com/)
3. **Git**: สำหรับ pull/push โค้ด

---

## 🚀 การติดตั้ง (Installation)

1. เข้าไปยังโฟลเดอร์ PoC:
   ```powershell
   cd "d:\project 4\poc"
   ```

2. ติดตั้ง Library ที่จำเป็น:
   ```powershell
   pip install -r requirements.txt
   ```
   *(หมายเหตุ: อาจจะใช้เวลาดาวน์โหลด `chromadb` และ `google-generativeai` เล็กน้อย)*

---

## ⚙️ ขั้นตอนการทดสอบระบบ (How to Run)

ระบบนี้ถูกแบ่งออกเป็น 3 สคริปต์หลักที่ต้องรันตามลำดับ:

### 1. การนำเข้าข้อมูล (Ingestion)
รันสคริปต์นี้เพื่ออ่านไฟล์ Playbook ทั้ง 15 เล่มในโฟลเดอร์ `playbooks/` ตัดเป็นส่วนย่อยๆ แล้วนำไปฝัง (Embed) ลงในฐานข้อมูล ChromaDB

```powershell
python 01_ingest.py
```
**ผลลัพธ์ที่คาดหวัง**: ระบบจะแจ้งว่านำเข้าข้อมูลสำเร็จ 225 chunks ลงใน `chroma_db/`

### 2. การทดสอบความแม่นยำ (Retrieval Test)
ก่อนจะให้ AI เขียนเนื้อหา เราต้องมั่นใจว่าระบบค้นหาข้อมูลได้ถูกต้อง และไม่สับสนระหว่างภัยคุกคามที่มี Log Source เหมือนกัน

```powershell
python 03_test_retrieval.py
```
**ผลลัพธ์ที่คาดหวัง**: ระบบจะรัน 6 Test cases และควรขึ้นสถานะ `✅ PASS` ทั้ง 6 รายการ

### 3. การสร้าง Playbook จริง (Generation)
ขั้นตอนสุดท้ายคือการรวมร่าง RAG เข้ากับ LLM คุณต้องตั้งค่า API Key ของคุณก่อนรัน

**บน Windows PowerShell:**
```powershell
# 1. ใส่ API Key ของคุณ
$env:GEMINI_API_KEY="YOUR_API_KEY_HERE"

# 2. รันคำสั่ง Generate (สามารถเปลี่ยน "WannaCry" เป็นชื่ออื่นตามใน technique_mapping.json)
python 02_generate.py --threat "WannaCry"
```

**บน Mac/Linux Terminal:**
```bash
export GEMINI_API_KEY="YOUR_API_KEY_HERE"
python 02_generate.py --threat "WannaCry"
```

---

## 📁 โครงสร้างโฟลเดอร์และไฟล์ที่สำคัญ

- `playbooks/`: โฟลเดอร์เก็บไฟล์ Markdown ต้นฉบับ 15 เล่ม ที่เราให้ AI เป็นคนเขียนขึ้นเพื่อเป็นองค์ความรู้
- `chroma_db/`: ฐานข้อมูล Vector Database ที่เก็บองค์ความรู้ (ถูกสร้างตอนรัน 01_ingest.py)
- `output/`: โฟลเดอร์ที่ระบบจะเซฟ Playbook เล่มใหม่ที่ AI เพิ่งประกอบและ Generate เสร็จ (ตอนรัน 02_generate.py)
- `technique_mapping.json`: ไฟล์คอนฟิกที่ผูกชื่อ Threat เข้ากับ MITRE Technique ID
- `mastertemplate.md`: โครงสร้างหลักของ Playbook แบบมาตรฐานที่มี Placeholder รอ AI มาเติม
- `task.md` & `walkthrough.md`: สรุปสิ่งที่ Antigravity ทำไปในระหว่างเขียนโค้ดชุดนี้

---

## 💡 คำแนะนำสำหรับการนำเสนออาจารย์
ในตอนที่นำเสนอ คุณสามารถโชว์ให้อาจารย์เห็นได้ว่า:
1. **Log Source เหมือนกันแต่ผลลัพธ์ต่างกัน**: อธิบายอาจารย์ว่า RAG ของเรามีการกรอง `technique_ids` เป็น Metadata ทำให้แม้ WannaCry กับ Phishing จะมีการรัน Process ผิดปกติ (Event ID 1) เหมือนกัน แต่ระบบดึงวิธีรับมือมาเฉพาะของใครของมัน ไม่มั่ว!
2. **โชว์ไฟล์ Output**: เปิดไฟล์ในโฟลเดอร์ `output/` เทียบกับ `mastertemplate.md` เพื่อให้อาจารย์เห็นว่าระบบเติมข้อมูลเฉพาะ Phase เข้าไปอย่างไร
