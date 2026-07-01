---
threat_name: SQL Injection
technique_ids: ["T1190", "T1059.004", "T1078"]
severity: High
source_doc: SQL_Injection_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- ติดตั้ง **sqlmap** (สำหรับ reproduce และทดสอบ payload) บนเครื่อง sandbox เท่านั้น
- เตรียม **ModSecurity WAF log parser** หรือ script แยก access log ของ Apache/Nginx/IIS
- ติดตั้ง **DB audit tool** เช่น MySQL General Query Log หรือ MSSQL SQL Server Audit
- เตรียม **Wireshark / tcpdump** สำหรับ capture traffic ระหว่าง web tier ↔ database tier
- มี **SIEM (Splunk/QRadar/Elastic)** พร้อม index web server logs และ DB logs
- เตรียม **Burp Suite Community** สำหรับ replay request และวิเคราะห์ HTTP payload
- จัดเตรียม **database snapshot** (read-only replica) สำหรับ forensic analysis โดยไม่กระทบ production

### Sub: team_roles
- **Incident Commander**: ประสานงานทีม, ตัดสินใจระดับ containment (เช่น ปิด API endpoint)
- **Web Application Security Analyst**: วิเคราะห์ HTTP request log, หา payload SQLi และ parameter ที่ถูก inject
- **Database Administrator (DBA)**: ตรวจสอบ DB audit log, ประเมินข้อมูลที่อาจถูก exfiltrate
- **SOC Analyst (L2/L3)**: เขียน SIEM correlation rule, hunt หา IP และ session ที่เกี่ยวข้อง
- **Developer/Application Owner**: ระบุ vulnerable code, patch parameter validation และ prepared statement
- **CISO/Legal**: ประเมินผลกระทบต่อข้อมูลส่วนบุคคล (PDPA) และแจ้งหน่วยงานที่เกี่ยวข้อง

### Sub: comm_plan
- แจ้ง **DBA และ Application Owner** ทันทีที่ตรวจพบ SQLi payload ใน log
- ใช้ช่องทาง **Secure Chat (Teams/Slack private channel)** เฉพาะทีม IR เท่านั้น ห้ามใช้ email ทั่วไป
- ส่งรายงาน **P1 Alert** ไปยัง CISO ภายใน 15 นาทีหลังยืนยัน incident
- บันทึก **Timeline** ใน ticketing system (Jira/ServiceNow) พร้อม timestamp ทุก action
- ประเมิน PDPA obligation: หากมีข้อมูลส่วนบุคคลรั่วไหล ต้องแจ้งภายใน 72 ชั่วโมง
- **War Room** เปิดเฉพาะ role ที่ระบุ ไม่อนุญาตบุคคลภายนอก

## Phase: detection
### Sub: log_sources
- **Apache/Nginx Access Log**: `/var/log/apache2/access.log`, `/var/log/nginx/access.log` — ดู HTTP status, URI, request body
- **IIS Log**: `C:\inetpub\logs\LogFiles\W3SVC1\` — fields: `cs-uri-stem`, `cs-uri-query`, `sc-status`
- **WAF Log (ModSecurity)**: ดู rule ID 942xxx (SQL Injection rules) ที่ถูก trigger
- **MySQL General Query Log / Slow Query Log**: เปิดด้วย `SET GLOBAL general_log = 'ON';`
- **MSSQL SQL Server Audit**: ตรวจสอบ `sys.fn_get_audit_file` สำหรับ query ผิดปกติ
- **Application Error Log**: stack trace ที่มี SQL syntax error แสดงว่า application error leak schema
- **Network IDS/IPS (Snort/Suricata)**: alert rule `ET WEB_SERVER SQL Injection` signatures

### Sub: detection_queries
**Splunk — ค้นหา SQL Injection payload ใน URI:**
```spl
index=web_logs sourcetype=access_combined
| rex field=uri "(?i)(?P<sqli_pattern>union\s+select|or\s+1=1|--|;drop\s+table|benchmark\(|sleep\(|waitfor\s+delay)"
| where isnotnull(sqli_pattern)
| stats count by src_ip, uri, sqli_pattern, http_method
| sort -count
```

**Splunk — ตรวจจับ error-based SQLi (HTTP 500 หลัง suspicious query):**
```spl
index=web_logs status=500
| rex field=uri "(?i)(?P<param>[?&][^=]+=.*(?:'|%27|--|%2D%2D))"
| where isnotnull(param)
| stats count by src_ip, uri, _time
```

**Elastic (KQL) — หา sqlmap User-Agent:**
```kql
http.request.headers.user-agent: "*sqlmap*" OR http.request.headers.user-agent: "*Havij*"
```

**CLI — grep Apache log หา pattern:**
```bash
grep -iE "(union\s+select|or\s+1=1|--|benchmark\(|sleep\(|%27|0x[0-9a-f]+)" /var/log/apache2/access.log | awk '{print $1, $7, $9}' | sort | uniq -c | sort -rn | head 30
```

**CLI — ตรวจ MySQL audit log หา INFORMATION_SCHEMA query:**
```bash
grep -i "information_schema\|sys.tables\|sysobjects\|xp_cmdshell" /var/log/mysql/mysql.log | tail -100
```

### Sub: ioc_list
- **SQLi Payload patterns**: `' OR '1'='1`, `' UNION SELECT NULL--`, `'; DROP TABLE--`, `WAITFOR DELAY '0:0:5'--`, `BENCHMARK(10000000,MD5(1))`
- **User-Agent strings**: `sqlmap/1.x`, `Havij`, `pangolin`, `BSQL Hacker`
- **HTTP Status anomaly**: IP เดิม ส่ง request ซ้ำๆ ที่ได้ HTTP 500 หลายครั้งติดกัน
- **Encoded payloads**: `%27` (single quote), `%2D%2D` (--), `%3B` (;), `0x414141` (hex encoding)
- **Time-based blind SQLi**: response time > 5 วินาทีสำหรับ request เดิม
- **Unusual DB functions**: `xp_cmdshell`, `UTL_HTTP`, `LOAD_FILE()`, `INTO OUTFILE`
- **Source IP**: IP ที่มี request rate > 50 req/min ไปยัง endpoint เดียว

### Sub: scope_analysis
- ระบุ **endpoint ที่ถูก attack** จาก URI ใน log (เช่น `/api/user?id=`, `/search?q=`)
- ตรวจสอบ **DB tables ที่ถูก query** ผ่าน audit log: มีการ SELECT จาก tables ที่มีข้อมูลสำคัญหรือไม่
- ประเมินว่ามี **data exfiltration** เกิดขึ้นหรือไม่ โดยดู response size ผิดปกติ (ขนาดใหญ่กว่าปกติมาก)
- ตรวจสอบว่า attacker ได้ **privilege escalation** ใน DB หรือไม่ เช่น รัน `xp_cmdshell` หรือ `INTO OUTFILE`
- หาจำนวน **rows ที่ถูก dump** จาก slow query log หรือ network capture
- ตรวจสอบ **session token** ที่ใช้ร่วมกับ SQLi — อาจมี account takeover ตามมา
- map ว่ามี **application อื่น** ใช้ DB เดียวกันที่อาจได้รับผลกระทบ

## Phase: containment
### Sub: short_term
1. **Block source IP** ที่พบ SQLi payload ทันทีที่ Firewall/WAF: `iptables -I INPUT -s <attacker_ip> -j DROP`
2. **เปิด WAF blocking mode**: เปลี่ยน ModSecurity จาก DetectionOnly → Prevention mode สำหรับ SQL Injection rules (942xxx)
3. **ปิด endpoint ชั่วคราว** หากเป็น API เฉพาะ: ใช้ Nginx `deny all;` หรือ return 503 สำหรับ path ที่ถูก exploit
4. **Revoke session ทั้งหมด** สำหรับ user ที่อาจถูก compromise (flush session table)
5. **ปิด MySQL General Query Log** หลังเก็บหลักฐาน เพื่อป้องกัน performance degradation: `SET GLOBAL general_log = 'OFF';`
6. **Isolate database server** จาก internet-facing tier หากพบว่า attacker มี direct DB access
7. **แจ้ง DBA** lock account DB ที่ web app ใช้ และสร้าง account ใหม่ที่มี least privilege

### Sub: long_term
- ใช้ **Prepared Statements / Parameterized Queries** แทน dynamic SQL ในทุก application layer
- ติดตั้ง **Web Application Firewall (WAF)** ระดับ cloud (AWS WAF, Cloudflare) และ tune rule สำหรับ application
- จำกัด **DB user privilege**: web app account ควรมีเฉพาะ SELECT/INSERT/UPDATE ที่จำเป็น ไม่ให้ DROP/EXECUTE
- เปิดใช้งาน **DB Audit Logging** แบบถาวรและส่งเข้า SIEM
- Implement **Rate Limiting** ที่ API Gateway: จำกัด request จาก IP เดียวไม่เกิน 20 req/min

### Sub: evidence_preservation
- เก็บ **Apache/Nginx/IIS access log** ที่ไม่ได้ถูกแก้ไข พร้อม hash (SHA256): `sha256sum access.log > access.log.sha256`
- Export **MySQL binary log** ช่วง incident: `mysqlbinlog --start-datetime="2026-06-01 00:00:00" /var/lib/mysql/mysql-bin.000001 > binlog_dump.sql`
- เก็บ **WAF alert log** และ raw request ที่ถูก block (พร้อม full HTTP header)
- ทำ **database dump** (read-only snapshot) ณ เวลา incident เพื่อ forensic analysis
- บันทึก **network pcap** ระหว่าง web server ↔ DB server ช่วงเวลา attack
- จัดเก็บใน **write-protected storage** และบันทึก chain of custody

## Phase: eradication
### Sub: process_removal
- หากพบ **web shell ถูก drop ผ่าน SQLi** (`INTO OUTFILE` บน MySQL): ลบไฟล์ที่ถูกสร้างใน web root
  ```bash
  find /var/www/html -newer /var/www/html/index.php -name "*.php" -exec ls -la {} \;
  ```
- ตรวจสอบและลบ **UDF (User Defined Function)** ที่ถูก inject ใน MySQL:
  ```sql
  SELECT * FROM mysql.func; DROP FUNCTION IF EXISTS lib_mysqludf_sys;
  ```
- ลบ **scheduled job / cron** ที่อาจถูกสร้างผ่าน `xp_cmdshell` (MSSQL) หรือ OS shell
- Kill process ที่ spawn จาก DB process ที่ผิดปกติ: `ps aux | grep -E "(nc|bash|sh)" | grep mysql`

### Sub: persistence_removal
- Reset **รหัสผ่าน DB account ทั้งหมด** โดยเฉพาะ sa/root: `ALTER USER 'root'@'%' IDENTIFIED BY '<new_strong_password>';`
- ลบ **DB user account** ที่ถูกสร้างโดย attacker: `SELECT user, host FROM mysql.user;` และ DROP user ที่ไม่รู้จัก
- ตรวจสอบ **stored procedures** และ **triggers** ที่ถูกสร้างใหม่ใน DB:
  ```sql
  SELECT ROUTINE_NAME, ROUTINE_TYPE, CREATED FROM information_schema.ROUTINES WHERE CREATED > '2026-01-01';
  ```
- ตรวจสอบและล้าง **application session store** (Redis/Memcached) เพื่อ invalidate session ที่อาจถูก hijack

### Sub: patching
- **Patch application code**: เปลี่ยน dynamic SQL → Prepared Statement ทุก query ที่รับ user input
- **อัปเดต framework**: อัปเดต ORM (Hibernate, SQLAlchemy, Eloquent) เป็น version ล่าสุด
- **ทดสอบ patch** ด้วย sqlmap บน staging environment: `sqlmap -u "https://staging.example.com/api?id=1" --level=5 --risk=3`
- อัปเดต **WAF rules**: sync rule set ล่าสุดจาก OWASP CRS
- ทำ **Code Review** เฉพาะ module ที่มี DB interaction และรัน SAST tool (SonarQube, Checkmarx)

## Phase: post_incident
### Sub: lessons_learned
- วิเคราะห์ว่า **parameter validation** ขาดที่จุดใด และทำไม developer ไม่ใช้ Prepared Statement
- ประเมินว่า **WAF** ทำงานใน detection-only mode หรือ blocking mode และทำไมไม่ block ตั้งแต่แรก
- ตรวจสอบว่า **DB audit log** เปิดใช้งานก่อน incident หรือไม่ — ถ้าไม่มี ทำให้ forensic ล่าช้า
- ประเมิน **mean time to detect (MTTD)** และ **mean time to respond (MTTR)** เทียบกับ SLA
- ตรวจสอบว่า **SIEM alert** ถูก trigger หรือไม่ ถ้าไม่ trigger ต้องปรับ detection rule
- บันทึกว่า **ข้อมูลอะไรถูก expose** และต้องแจ้ง data subject หรือไม่ (PDPA compliance)

### Sub: improvements
- บังคับใช้ **Secure Coding Standard**: ทุก PR ต้องผ่าน SAST scan ก่อน merge
- เพิ่ม **SQLi detection rule** ใน SIEM ที่ครอบคลุม encoded payload (URL encoding, hex encoding)
- ตั้ง **WAF ใน blocking mode** พร้อม whitelist endpoint ที่ต้องการ
- จัด **developer security training** เรื่อง OWASP Top 10 โดยเฉพาะ A03: Injection
- เพิ่ม **penetration test** สำหรับ web application ก่อน go-live ทุกครั้ง
- ทบทวน **DB user privilege** ทุก 6 เดือน และทำ least-privilege audit
