---
threat_name: Data Exfiltration
technique_ids: ["T1041", "T1048", "T1083"]
severity: Critical
source_doc: Data_Exfiltration_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- ติดตั้ง **DLP solution** (Microsoft Purview, Symantec DLP, Forcepoint) ครอบคลุม endpoint และ network
- เตรียม **NetFlow / Zeek / Suricata** สำหรับ monitor network traffic volume และ destination
- ติดตั้ง **UEBA (User and Entity Behavior Analytics)** เพื่อ detect anomalous file access pattern
- เตรียม **Wireshark / tcpdump** สำหรับ capture traffic ที่น่าสงสัย
- มี **proxy log (Blue Coat/Zscaler/Squid)** พร้อม บันทึก full URL และ upload size
- เตรียม **Cloud Access Security Broker (CASB)** สำหรับ monitor upload ไปยัง cloud storage
- เตรียม script คำนวณ **baseline outbound traffic** (avg bytes/day ต่อ user/IP)

### Sub: team_roles
- **Incident Commander**: ตัดสินใจ block outbound traffic และประเมินข้อมูลที่รั่วไหล
- **Network Security Engineer**: วิเคราะห์ NetFlow, ระบุ destination IP, block ที่ Firewall
- **DLP Analyst**: วิเคราะห์ DLP alert, ระบุ data classification ของ file ที่ถูก exfiltrate
- **SOC Analyst (L2/L3)**: correlate file access log กับ network transfer, ระบุ user/process ที่ทำ exfil
- **Legal/Compliance**: ประเมิน data breach notification obligation (PDPA, GDPR)
- **CISO**: อนุมัติการตัดสินใจ business-critical เช่น block internet access ชั่วคราว

### Sub: comm_plan
- แจ้ง **Legal และ Compliance** ทันทีเมื่อยืนยันว่า sensitive data ถูก exfiltrate
- ส่ง **P1 Critical Alert** เพราะ data loss อาจมีผลต่อ regulatory compliance
- ใช้ **out-of-band communication** เพราะ attacker อาจ monitor internal communication
- ประสาน **PR/Communications team** เตรียม statement หากต้องแจ้งลูกค้า
- บันทึก **data classification** และ **volume** ของข้อมูลที่ถูก exfiltrate สำหรับ legal reporting

## Phase: detection
### Sub: log_sources
- **Firewall/NetFlow**: outbound traffic volume ผิดปกติ, destination IP ที่ไม่เคยเห็นมาก่อน
- **Web Proxy Log**: HTTP POST ขนาดใหญ่, upload ไปยัง file-sharing site (Dropbox, Mega, WeTransfer)
- **DLP Alert**: policy violation สำหรับ sensitive data (PII, credit card, classified document)
- **Sysmon Event ID 11 (File Create)** และ **Event ID 23 (File Delete)**: ไฟล์ถูก copy ไปยัง temp location ก่อน upload
- **DNS Log**: query ไปยัง domain ที่ใช้ DNS tunneling สำหรับ data exfil
- **Email Gateway Log**: email ที่มี attachment ขนาดใหญ่ส่งออกไปยัง external address
- **Cloud Storage Log**: unusual upload activity บน OneDrive, SharePoint, Google Drive, S3

### Sub: detection_queries
**Splunk — ตรวจ outbound traffic spike (NetFlow):**
```spl
index=netflow direction=outbound
| eval MB = round(bytes/1048576, 2)
| stats sum(MB) as total_MB by src_ip, dest_ip, _time
| where total_MB > 500
| sort -total_MB
```

**Splunk — ตรวจ upload ไปยัง cloud storage (Proxy Log):**
```spl
index=proxy_logs http_method=POST
| where (url LIKE "*dropbox.com*" OR url LIKE "*mega.nz*" OR url LIKE "*wetransfer.com*"
         OR url LIKE "*drive.google.com*" OR url LIKE "*onedrive.live.com*")
| eval MB = round(bytes_out/1048576, 2)
| stats sum(MB) as total_MB by src_ip, user, url
| where total_MB > 100
| sort -total_MB
```

**Splunk — ตรวจ DLP alert สำหรับ sensitive data:**
```spl
index=dlp_logs severity IN ("High","Critical")
| stats count by user, src_ip, rule_name, file_name, destination
| sort -count
```

**CLI — ตรวจ large file transfer จาก Windows (Sysmon Event ID 15 - FileCreateStreamHash):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=15} -MaxEvents 100 |
  Where-Object {$_.Message -match "\.zip|\.rar|\.7z|\.tar"} |
  Select-Object TimeCreated, Message | Format-List
```

**Elastic (KQL) — ตรวจ DNS exfiltration (long subdomain):**
```kql
dns.question.name: * AND dns.question.name.length > 50
| stats count by dns.question.name, source.ip
| sort count desc
```

**CLI — ตรวจ outbound FTP/SFTP connection ผิดปกติ:**
```bash
ss -tnp | grep -E ":21\b|:22\b|:990\b" | grep ESTABLISHED
netstat -anp | grep -E "ESTABLISHED.*:21|ESTABLISHED.*:22" | grep -v "127.0.0.1\|192.168"
```

### Sub: ioc_list
- **Large outbound transfer**: > 500 MB ออกจาก endpoint เดียวใน 1 ชั่วโมง ผิดปกติจาก baseline
- **Destination domains**: Dropbox, Mega.nz, Pastebin, Anonfiles, 0bin.net, transfer.sh
- **Archiving before exfil**: `7z.exe`, `WinRAR.exe`, `tar` รันบนไฟล์ sensitive ก่อน transfer
- **Unusual protocols**: FTP (port 21), DNS (port 53 with large payload), ICMP with data, port 443 ที่ไม่ใช่ HTTPS
- **Process**: `rclone.exe`, `megacmd.exe`, `gdrive.exe`, `aws.exe s3 cp` รันโดย user ที่ไม่ควรใช้
- **Time anomaly**: transfer เกิดช่วง 02:00-05:00 นอก business hours
- **Staged files**: ไฟล์ archive ขนาดใหญ่ใน `%TEMP%`, `C:\Windows\Temp`, `/tmp` ก่อน deletion

### Sub: scope_analysis
- ระบุ **data classification** ของไฟล์ที่ถูก exfiltrate: PII, financial data, IP, trade secret
- ประเมิน **ปริมาณข้อมูล** ที่ถูก transfer (GB) และ destination
- ตรวจสอบ **user account** ที่ทำ transfer: เป็น insider threat หรือ compromised account
- ระบุ **method ที่ใช้**: HTTP POST, FTP, DNS tunneling, email, physical media (USB)
- ตรวจสอบ **time window** ที่ exfil เกิดขึ้น และ correlate กับ access log ของ data source
- ประเมิน **downstream impact**: ข้อมูลที่ถูก exfil มีผลต่อ compliance obligation อะไรบ้าง (PDPA, PCI DSS)

## Phase: containment
### Sub: short_term
1. **Block destination IP/domain** ที่ระบุได้ที่ Firewall ทันที: `iptables -A OUTPUT -d <destination_ip> -j DROP`
2. **Isolate endpoint** ที่ทำการ exfil จาก network
3. **Revoke cloud access token** สำหรับ account ที่ upload ไปยัง cloud storage
4. **ปิด outbound port** ที่ผิดปกติชั่วคราว: FTP (21), SFTP (22 จาก endpoint ทั่วไป), IRC (6667)
5. **Reset credential** ของ user account ที่สงสัยว่าถูก compromise และใช้ exfil
6. **สั่ง DLP** ให้ block อัตโนมัติ (switch จาก audit-only → block mode) สำหรับ sensitive data category
7. **ปิด USB/removable media** ชั่วคราวสำหรับ endpoint ที่เกี่ยวข้อง ผ่าน Group Policy

### Sub: long_term
- Implement **Data Classification** และ **labeling** บนทุก document ที่ sensitive
- Deploy **full DLP** ครอบคลุม endpoint, email, cloud, และ network
- ใช้ **Zero Trust Network Access (ZTNA)**: block outbound ยกเว้น whitelist destination
- Implement **CASB** สำหรับ monitor และ control cloud storage usage
- ทบทวน **data access permission**: apply least privilege บน file server และ cloud storage

### Sub: evidence_preservation
- เก็บ **NetFlow data** ช่วง exfil: export จาก NetFlow collector (nfdump, ntopng)
- บันทึก **proxy log** ทั้งหมดที่เกี่ยวข้องพร้อม timestamp
- เก็บ **DLP alert detail** รวมถึง file content fingerprint (ถ้า DLP solution support)
- ทำ **disk image** ของ endpoint เพื่อ forensic analysis (รวมถึง browser history, download folder)
- เก็บ **cloud audit log** จาก cloud storage provider (ถ้าสามารถ request ได้)
- บันทึก **pcap** ของ exfil traffic ถ้า IDS/IPS เก็บไว้

## Phase: eradication
### Sub: process_removal
- ลบ **exfiltration tool** ที่ถูก install (rclone, megacmd, custom script):
  ```powershell
  Get-ChildItem -Path C:\Users -Recurse -Include "rclone.exe","megacmd.exe","gdrive.exe" -ErrorAction SilentlyContinue
  ```
- Kill **ongoing transfer process**: `Stop-Process -Name rclone,curl,wget -Force`
- ตรวจสอบ **browser extension** ที่อาจใช้สำหรับ exfil ผ่าน browser

### Sub: persistence_removal
- ลบ **scheduled task** ที่ตั้งค่า periodic exfil:
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Actions.Execute -match "rclone|curl|ftp|powershell"} | Format-List
  ```
- ตรวจสอบ **cron job** บน Linux ที่มี script upload ข้อมูล
- ลบ **rclone config** ที่มี cloud storage credential: `~/.config/rclone/rclone.conf`
- ตรวจสอบ **SSH config** ที่อาจตั้ง tunnel สำหรับ exfil: `~/.ssh/config`

### Sub: patching
- อัปเดต **DLP policy** ให้ครอบคลุม exfil technique ที่ตรวจพบ
- ปรับ **Firewall rule**: block outbound ไปยัง known file-sharing domains
- อัปเดต **Proxy category blocking**: เพิ่ม anonymous file sharing ใน blocked category
- ทบทวน **cloud storage policy**: อนุญาตเฉพาะ corporate-approved cloud storage

## Phase: post_incident
### Sub: lessons_learned
- ประเมินว่า **DLP** ครอบคลุม channel ที่ใช้ exfil หรือไม่ (email, HTTP, DNS, USB)
- วิเคราะห์ว่า **data classification** ถูกต้องและ up-to-date หรือไม่
- ตรวจสอบว่า **UEBA** สามารถตรวจ anomalous access pattern ได้ก่อน exfil หรือไม่
- ประเมิน **data breach notification timeline**: แจ้งได้ทันภายใน regulatory deadline หรือไม่
- วิเคราะห์ว่าเป็น **insider threat** หรือ **external attacker** ที่ใช้ compromised account

### Sub: improvements
- Deploy **full-spectrum DLP**: endpoint + email + network + cloud
- Implement **UEBA** สำหรับ anomaly detection บน data access pattern
- ทำ **Data Classification Workshop** เพื่อ label sensitive data ให้ครบ
- เพิ่ม **SIEM rule** สำหรับ large outbound transfer > threshold ที่กำหนดตาม baseline
- ทบทวน **insider threat program** และ off-boarding procedure สำหรับ account revocation
