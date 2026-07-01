---
threat_name: DNS Tunneling
technique_ids: ["T1071.004", "T1041", "T1568"]
severity: High
source_doc: DNS_Tunneling_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- ติดตั้ง **Zeek (Bro)** พร้อม DNS analyzer script สำหรับ log DNS query detail (query length, response size)
- เตรียม **dnscat2** และ **iodine** บน sandbox สำหรับ simulate DNS tunnel และ test detection
- เตรียม **Passive DNS database** (PDNS) หรือ threat intel feed สำหรับ lookup ประวัติ domain
- ติดตั้ง **Splunk/Elastic** พร้อม ingest DNS query log จาก internal DNS server
- เตรียม **Whois / RDAP lookup tool** สำหรับ ตรวจสอบ domain registration age และ registrar
- มี **DNS RPZ (Response Policy Zone)** พร้อม feed จาก threat intel (block malicious domain)
- เตรียม **Wireshark** สำหรับ inspect DNS packet payload ขนาดและ entropy

### Sub: team_roles
- **Incident Commander**: ประเมินว่า DNS tunnel ใช้สำหรับ C2 หรือ data exfiltration
- **Network Security Engineer**: วิเคราะห์ DNS log, ระบุ malicious resolver/domain, implement sinkhole
- **Threat Intelligence Analyst**: ระบุ domain ที่ใช้ tunnel, lookup ประวัติ, attribute ไปยัง threat actor
- **SOC Analyst (L2/L3)**: hunt endpoint ที่ generate DNS tunnel query ผ่าน SIEM
- **DNS/Network Admin**: ตั้งค่า DNS RPZ, block domain ที่ malicious, force redirect ไปยัง sinkhole
- **Malware Analyst**: วิเคราะห์ malware ที่ implement DNS tunnel (decode C2 protocol)

### Sub: comm_plan
- แจ้ง **Network Admin** ทันทีเพื่อ force DNS query ผ่าน internal resolver (block external DNS)
- ส่ง **P2 Alert** ไปยัง CISO — DNS tunnel บ่งบอกว่า attacker มี persistent C2 หรือ exfil channel
- แจ้ง **SOC** เพื่อ hunt endpoint ทุกเครื่องที่ query domain เดียวกัน
- ประสาน **Threat Intelligence** เพื่อ share domain IOC และ check threat actor attribution
- บันทึก **domain list** และ **query pattern** สำหรับ IR report

## Phase: detection
### Sub: log_sources
- **Internal DNS Server Log**: Windows DNS Debug Log (`%SystemRoot%\system32\dns\dns.log`), BIND query log
- **Zeek DNS Log** (`dns.log`): query name, query type, answer, TTL, response size
- **Firewall DNS Log**: ดู DNS query ที่ไปยัง external resolver โดยตรง (bypass internal DNS)
- **Sysmon Event ID 22 (DNS Query)**: process ที่ทำ DNS query และ query result
- **Proxy/NGFW Log**: DNS-over-HTTPS (DoH) ที่ bypass traditional DNS monitoring
- **EDR DNS telemetry**: process → DNS query mapping
- **NetFlow**: volume ของ DNS traffic (port 53 UDP/TCP) ผิดปกติจาก specific endpoint

### Sub: detection_queries
**Splunk — ตรวจ DNS query ที่มี subdomain ยาวผิดปกติ (DNS tunnel indicator):**
```spl
index=dns_logs query_type IN ("A","TXT","CNAME","MX")
| eval subdomain_len = len(query)
| where subdomain_len > 50
| rex field=query "^(?P<subdomain>.+)\.(?P<tld>[^.]+\.[^.]+)$"
| stats count, avg(subdomain_len) as avg_len by tld, src_ip
| where count > 100
| sort -count
```

**Splunk — ตรวจ high-frequency DNS query ไปยัง domain เดียว (beacon pattern):**
```spl
index=dns_logs
| stats count by src_ip, query, _time span=1m
| where count > 30
| sort -count
```

**Splunk — ตรวจ TXT record query (มักใช้สำหรับ DNS tunnel C2):**
```spl
index=dns_logs query_type="TXT"
| stats count by src_ip, query
| where count > 10
| sort -count
```

**Splunk — ตรวจ high entropy domain name (random-looking subdomain):**
```spl
index=dns_logs
| eval entropy = -sum(map(lambda c: (freq(c, query)/len(query))*log((freq(c, query)/len(query)), 2), distinct_values(split(query, ""))))
| where entropy > 3.5 AND len(query) > 40
| table _time, src_ip, query, entropy
```

**CLI — ตรวจ DNS query log บน Windows DNS Server:**
```powershell
Get-Content "C:\Windows\System32\dns\dns.log" | Select-String -Pattern "TXT|CNAME" |
  Where-Object {$_.ToString().Length -gt 200} |
  Select-Object -Last 50
```

**Zeek CLI — ตรวจ suspicious DNS query จาก dns.log:**
```bash
zeek-cut query qtype_name < dns.log | awk '{print length($1), $0}' | sort -rn | head 30
```

**Splunk — ตรวจ endpoint ที่ query external DNS server โดยตรง (bypass internal):**
```spl
index=firewall dest_port=53
| where dest_ip NOT IN ("10.0.0.53","192.168.1.1")
| stats count by src_ip, dest_ip
| where count > 50
| sort -count
```

### Sub: ioc_list
- **Long subdomain length**: query ที่มี subdomain ยาว > 50 characters เช่น `aGVsbG8td29ybGQ.malicious.com`
- **High query frequency**: > 100 queries/นาที ไปยัง domain เดียว จาก IP เดียว
- **TXT record query**: DNS TXT query ที่สูงผิดปกติ (TXT ถูกใช้บ่อยสำหรับ C2 data transfer)
- **Domain entropy**: subdomain ที่มีลักษณะ random/base64 encoded (entropy สูง > 3.5)
- **NXDOMAIN flood**: DNS query จำนวนมากที่ได้รับ NXDOMAIN (attacker probe domain ที่ยังไม่ register)
- **TTL ต่ำมาก**: TTL < 30 วินาที บ่งบอก fast-flux สำหรับ C2 evasion
- **Process**: `iodine`, `dnscat`, `dns2tcp`, `PowerDNS tunnel` process บน endpoint

### Sub: scope_analysis
- ระบุ **endpoint ทั้งหมด** ที่ query malicious domain (อาจมีหลายเครื่องติด malware เดียวกัน)
- ตรวจสอบ **data volume** ที่ถูก exfil ผ่าน DNS: ดูจาก total bytes ใน DNS response
- วิเคราะห์ **C2 domain** — เป็น DGA (Dynamic Generated Algorithm) หรือ hardcoded domain
- ตรวจสอบ **DNS tunnel direction**: เป็น C2 (inbound command) หรือ data exfil (outbound)
- ระบุ **protocol ที่ใช้ใน tunnel**: TXT record, CNAME, A record (แต่ละ technique มี bandwidth ต่างกัน)
- ตรวจสอบว่า attacker bypass internal DNS โดย **query external resolver** (8.8.8.8) โดยตรง

## Phase: containment
### Sub: short_term
1. **Block malicious domain** ที่ internal DNS ทันที: เพิ่ม zone record ที่ redirect ไปยัง sinkhole `127.0.0.1`
2. **Block outbound port 53** จาก endpoint ไปยัง external DNS server (บังคับ ใช้ internal DNS เท่านั้น)
3. **Block DNS-over-HTTPS (DoH)** ที่ known DoH server: `8.8.8.8:443`, `1.1.1.1:443`, `9.9.9.9:443`
4. **Isolate endpoint** ที่ generate DNS tunnel traffic
5. **เปิด DNS RPZ** และเพิ่ม domain IOC เข้า block list
6. **ตรวจสอบ DNS cache** ของ internal server: `dnscmd /clearcache` (หลังเก็บ evidence)
7. **Block TLD ที่น่าสงสัย** ชั่วคราว หากใช้ uncommon TLD เช่น `.xyz`, `.click`, `.tk`

### Sub: long_term
- ใช้ **DNS Firewall / RPZ** ที่ integrate กับ threat intel feed แบบ real-time
- Force ให้ endpoint **ใช้ internal DNS เท่านั้น** ด้วย Firewall rule block outbound 53 ไปยัง external IP
- Deploy **DNS Security (DNSSEC)** เพื่อ validate DNS response integrity
- ใช้ **DNS analytics** (machine learning) เพื่อ detect anomalous query pattern
- Implement **split-horizon DNS**: internal domain ไม่ resolve จาก external

### Sub: evidence_preservation
- Export **DNS debug log** ช่วง incident: `Copy-Item "C:\Windows\System32\dns\dns.log" C:\evidence\dns.log`
- เก็บ **Zeek DNS log**: `cp /var/log/zeek/dns.log /evidence/dns_zeek.log`
- ทำ **pcap capture** ของ DNS traffic: `tcpdump -w /evidence/dns_tunnel.pcap port 53`
- บันทึก **full DNS query list** ที่ unique domain ที่ถูก query จาก malicious endpoint
- เก็บ **Sysmon Event 22** สำหรับ endpoint ที่เกี่ยวข้อง

## Phase: eradication
### Sub: process_removal
- Kill **DNS tunnel process** บน endpoint:
  ```powershell
  Get-Process | Where-Object {$_.Name -match "iodine|dnscat|dns2tcp"} | Stop-Process -Force
  ```
- ตรวจสอบ **parent process** ของ DNS tunnel: `Get-Process <pid> | Select-Object Parent`
- Scan endpoint ด้วย **EDR/AV** เพื่อลบ malware ที่ implement DNS tunnel

### Sub: persistence_removal
- ลบ **scheduled task** ที่ restart DNS tunnel process: `Get-ScheduledTask | Where-Object {$_.Actions.Execute -match "iodine|dnscat"}`
- ตรวจสอบ **registry Run key** และ **startup folder** สำหรับ DNS tunnel binary
- ลบ **malware binary** ที่ disk รวมถึง configuration file (เก็บ hash ก่อน)
- ตรวจสอบ **driver** ที่ malware อาจ install สำหรับ DNS interception

### Sub: patching
- อัปเดต **AV/EDR signature** สำหรับ DNS tunnel tool ที่ตรวจพบ
- ปรับ **Firewall rule** เพื่อ enforce DNS policy (internal DNS only)
- อัปเดต **DNS RPZ feed** ให้รวม domain ใหม่จาก incident
- ทบทวน **DNS monitoring threshold** และ alert rule ใน SIEM

## Phase: post_incident
### Sub: lessons_learned
- วิเคราะห์ว่า **DNS monitoring** มีอยู่ก่อน incident และทำไมไม่ detect ได้เร็วกว่า
- ตรวจสอบว่า **endpoint สามารถ bypass internal DNS** ได้ (query external DNS โดยตรง) หรือไม่
- ประเมิน **ข้อมูลที่อาจถูก exfil** ผ่าน DNS tunnel และ volume
- วิเคราะห์ว่า **DGA detection** สามารถ identify malicious domain ก่อน manual review หรือไม่
- ตรวจสอบว่า **DNS-over-HTTPS (DoH)** ถูกใช้เพื่อ evade detection หรือไม่

### Sub: improvements
- Deploy **DNS analytics platform** ที่มี anomaly detection (entropy, frequency analysis)
- บังคับ **internal DNS only** ด้วย Firewall rule บนทุก endpoint
- เพิ่ม **SIEM rule** สำหรับ long subdomain, high-frequency query, และ TXT record spike
- ทำ **threat intel integration** กับ DNS RPZ แบบ automated
- ทบทวน **DNS logging policy** เพื่อ enable full query logging บน internal DNS server
