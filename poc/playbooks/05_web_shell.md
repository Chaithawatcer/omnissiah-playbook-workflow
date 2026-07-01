---
threat_name: Web Shell
technique_ids: ["T1505.003", "T1190", "T1059.004"]
severity: Critical
source_doc: Web_Shell_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- ติดตั้ง **LOKI / Thor Lite** (Florian Roth) สำหรับ scan web shell ด้วย YARA rules
- เตรียม **Linux Malware Detect (LMD)** และ **ClamAV** สำหรับ scan ไฟล์ใน web root
- เตรียม script `find` สำหรับค้นหาไฟล์ที่ถูกสร้างใหม่ใน web directory โดยเร็ว
- มี **Volatility Framework** สำหรับ memory analysis หาก web shell เป็น in-memory variant
- ติดตั้ง **auditd** บน Linux web server สำหรับ monitor file creation และ process execution
- เตรียม **offline backup** ของ web application สำหรับ comparison กับ production
- มี read-only access ไปยัง **Git repository** ของ web application เพื่อ diff ไฟล์ที่เปลี่ยนแปลง

### Sub: team_roles
- **Incident Commander**: ตัดสินใจ isolate web server หรือ keep online ขณะ investigate
- **Web Security Analyst**: วิเคราะห์ web shell code, ระบุ capability (reverse shell, file manager, DB access)
- **System Administrator**: ตรวจสอบ process tree, file system, และ cron jobs บน web server
- **SOC Analyst (L2/L3)**: correlate web log กับ shell activity, ระบุ attacker's C2 IP
- **Application Developer**: ตรวจสอบ upload vulnerability ใน code และ patch
- **Forensic Analyst**: collect disk image และ memory dump ก่อน cleanup

### Sub: comm_plan
- แจ้ง **System Admin และ App Owner** ทันทีที่ยืนยันพบ web shell
- ส่ง **P1 Critical Alert** ไปยัง CISO เนื่องจาก attacker มี command execution บน server
- ใช้ **out-of-band communication** (โทรศัพท์, Signal) หากสงสัยว่า email server ถูก compromise ด้วย
- ประเมินว่าต้อง **แจ้ง regulator** หรือไม่ (หาก web shell ใช้ access ข้อมูลลูกค้า)
- Lock down **change management**: ห้าม deploy code ใหม่จนกว่าจะ clear incident

## Phase: detection
### Sub: log_sources
- **Web Server Access Log** (Apache/Nginx/IIS): ดู HTTP request ไปยัง ไฟล์ `.php`, `.asp`, `.aspx`, `.jsp` ที่ไม่รู้จัก
- **Web Server Error Log**: ดู PHP/ASP error จากการรัน command ผิดพลาด
- **Sysmon Event ID 1 (Process Create)**: process ที่ parent เป็น `httpd`, `nginx`, `w3wp.exe`, `tomcat`
- **Sysmon Event ID 11 (File Create)**: ไฟล์ใหม่ถูกสร้างใน web root directory
- **auditd log**: `execve` syscall จาก process ที่ run as www-data/apache user
- **Linux /var/log/messages**: ดู outbound connection จาก web server process ไปยัง IP ภายนอก
- **EDR (CrowdStrike/Defender)**: alert เรื่อง `cmd.exe` หรือ `powershell.exe` spawned จาก `w3wp.exe`

### Sub: detection_queries
**Splunk — ตรวจ Web Shell access (URI ผิดปกติที่มี command parameter):**
```spl
index=web_logs sourcetype=access_combined
| rex field=uri "(?i)(?P<shell_param>cmd=|exec=|command=|shell=|pass=|passwd=|system\(|eval\(|base64_decode)"
| where isnotnull(shell_param)
| stats count by src_ip, uri, http_method, status
| sort -count
```

**Splunk — ตรวจ process spawned จาก web server (Sysmon Event ID 1):**
```spl
index=sysmon EventCode=1
| where (ParentImage LIKE "%w3wp.exe%" OR ParentImage LIKE "%httpd%" OR ParentImage LIKE "%nginx%")
  AND (Image LIKE "%cmd.exe%" OR Image LIKE "%powershell.exe%" OR Image LIKE "%sh%" OR Image LIKE "%bash%")
| table _time, ComputerName, ParentImage, Image, CommandLine, User
```

**CLI — หาไฟล์ PHP ที่สร้างใหม่ใน web root (ไม่มีใน Git):**
```bash
find /var/www/html -name "*.php" -newer /var/www/html/index.php -not -path "*/.git/*" -exec ls -la {} \;
```

**CLI — ค้นหา web shell signature ใน PHP files:**
```bash
grep -rE "(eval\s*\(|base64_decode\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\()" /var/www/html/ --include="*.php" -l
```

**CLI — ตรวจ ASPX web shell บน IIS:**
```powershell
Get-ChildItem -Path "C:\inetpub\wwwroot" -Recurse -Include "*.aspx","*.asp","*.ashx" | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName, LastWriteTime, Length
```

**Sysmon — ตรวจ outbound connection จาก web process (Event ID 3):**
```spl
index=sysmon EventCode=3
| where (Image LIKE "%w3wp.exe%" OR Image LIKE "%httpd%") AND NOT (DestinationIp STARTSWITH "10." OR DestinationIp STARTSWITH "192.168.")
| table _time, Image, DestinationIp, DestinationPort
```

### Sub: ioc_list
- **Web Shell filenames**: `c99.php`, `r57.php`, `WSO.php`, `b374k.php`, `shell.aspx`, `cmd.asp`, `info.php` (ถ้าสร้างใหม่)
- **URI patterns**: request ไปยัง ไฟล์ `.php` ที่มี parameter `cmd=`, `exec=`, `c=`, `pass=`
- **HTTP method**: POST request ไปยัง static-looking file พร้อม base64 body
- **Process anomaly**: `cmd.exe`, `bash`, `sh`, `nc`, `wget`, `curl` spawn จาก `w3wp.exe` หรือ `httpd`
- **Sysmon Event ID 1**: CommandLine มี `whoami`, `net user`, `ipconfig`, `cat /etc/passwd`
- **Outbound connection**: web server process เปิด connection ไปยัง port 4444, 1337, 443 (non-HTTPS traffic)
- **File with encoded content**: ไฟล์ PHP ที่มี `eval(base64_decode(...))` หรือ `eval(gzinflate(...))`

### Sub: scope_analysis
- ระบุ **web shell ทุก ตัว** บน server โดยใช้ LOKI scan: `python3 loki.py -p /var/www/html/`
- ตรวจสอบ **web log** ว่า shell ถูก access ครั้งแรกเมื่อไหร่ และมีกี่ IP ที่ใช้งาน
- วิเคราะห์ **command ที่ถูกรัน** ผ่าน shell: ดูจาก HTTP POST body ใน log หรือ auditd
- ตรวจสอบว่ามี **lateral movement**: shell ถูกใช้ pivot ไปยัง server อื่นหรือไม่
- ประเมิน **data exfiltration**: ไฟล์อะไรถูก read หรือ download ผ่าน shell
- หา **initial access vector**: shell ถูก upload ผ่าน file upload, SQLi INTO OUTFILE, หรือ vulnerable plugin

## Phase: containment
### Sub: short_term
1. **Isolate web server** จาก internet ทันที (หาก business impact ยอมรับได้): block port 80/443 ที่ Firewall
2. **Rename/move web shell** ออกจาก web root เพื่อหยุด access แต่เก็บ evidence ไว้: `mv /var/www/html/shell.php /tmp/evidence/shell.php`
3. **Block source IP** ของ attacker ที่ access web shell: `iptables -I INPUT -s <attacker_ip> -j DROP`
4. **Kill process** ที่ spawn จาก web shell: `pkill -u www-data -f "nc\|bash -i\|python -c"`
5. **Terminate reverse shell connection**: `ss -tp | grep ESTABLISHED` และ kill connection ไปยัง C2
6. **Reset credential** ทุกอย่างที่ web server เข้าถึงได้ (DB password, API key, service account)
7. **ปิด write permission** ของ web root ชั่วคราว: `chmod -R a-w /var/www/html/`

### Sub: long_term
- ใช้ **read-only file system** สำหรับ web root โดยใช้ `chattr +i` หรือ mount as read-only
- Implement **File Integrity Monitoring (FIM)**: AIDE, Wazuh FIM, หรือ Tripwire
- ปิด **PHP dangerous functions** ใน `php.ini`: `disable_functions = exec,passthru,shell_exec,system,proc_open,popen`
- ใช้ **Web Application Firewall** ที่ scan request body สำหรับ shell command pattern
- แยก **web server** ออกจาก database server และ internal network ด้วย DMZ architecture

### Sub: evidence_preservation
- สร้าง **disk image** ก่อน cleanup: `dd if=/dev/sda of=/evidence/webserver_disk.img bs=4M`
- เก็บ **web shell file** พร้อม hash: `cp shell.php /evidence/ && sha256sum /evidence/shell.php`
- Export **web access log** ช่วง incident และ lock ไม่ให้แก้ไข
- ดึง **process memory** ของ web shell process: `gcore <pid>`
- บันทึก **network connection** ขณะ shell ยังทำงาน: `ss -tnp`, `netstat -anp`
- เก็บ **auditd log** ที่แสดง execve calls จาก web process

## Phase: eradication
### Sub: process_removal
- Kill และ verify ว่าไม่มี **reverse shell process** ทำงานอยู่:
  ```bash
  ps aux | grep -E "(nc|ncat|socat|bash -i|python.*socket)" | grep -v grep
  ```
- ตรวจสอบ **open network connection** ที่ผิดปกติ:
  ```bash
  ss -tnp | grep ESTABLISHED | grep -v ":80\|:443\|:22"
  ```
- ลบ **cron job** ที่ถูกสร้างโดย attacker:
  ```bash
  crontab -u www-data -l && crontab -u root -l && ls -la /etc/cron.d/ /etc/cron.hourly/
  ```

### Sub: persistence_removal
- ลบ **web shell ทุก ตัว** ที่ค้นพบ (หลังเก็บ evidence แล้ว)
- ตรวจสอบ **crontab ทุก user**: `for user in $(cat /etc/passwd | cut -d: -f1); do crontab -u $user -l 2>/dev/null; done`
- ตรวจสอบ **SSH authorized_keys** ทุก user ที่มี shell access
- ตรวจสอบ **.bashrc, .bash_profile, .profile** ว่ามี command ที่ถูก inject หรือไม่
- ตรวจสอบ **systemd service** ที่ถูกสร้างใหม่: `systemctl list-units --type=service --state=active | grep -v "@"`

### Sub: patching
- **Patch file upload vulnerability**: ตรวจสอบ file type ด้วย magic bytes ไม่ใช่แค่ extension
- อัปเดต **CMS / framework**: WordPress, Joomla, Laravel เป็น version ล่าสุด
- **Remove unused plugins**: ปิดหรือลบ plugin ที่ไม่ได้ใช้ใน WordPress/Joomla
- ทำ **full web application scan** (Nikto, OWASP ZAP) บน staging environment หลัง patch
- Restore web files จาก **known-good backup** หลัง clean เครื่อง

## Phase: post_incident
### Sub: lessons_learned
- ระบุว่า **initial access** เกิดจากช่องโหว่อะไร: file upload, RCE, SQLi, vulnerable plugin
- ประเมินว่า **FIM (File Integrity Monitoring)** จะตรวจได้เร็วกว่านี้หรือไม่
- วิเคราะห์ว่า **web shell ทำงานนานเท่าไหร่** ก่อนถูกตรวจพบ — dwell time
- ตรวจสอบว่า attacker มี **privilege escalation** สำเร็จหรือไม่ (จาก www-data → root)
- ประเมิน **ข้อมูลที่ถูก access** ผ่าน web shell และผลกระทบต่อ data confidentiality

### Sub: improvements
- Deploy **FIM** ครอบคลุม web root ทุก server
- บังคับใช้ **principle of least privilege** สำหรับ web server process (ไม่ run as root)
- ทำ **web application penetration test** ทุก 6 เดือน หรือก่อน release ใหม่
- เพิ่ม **SIEM rule**: alert เมื่อมี new file สร้างใน web root โดย web process user
- ปิด **dangerous PHP functions** และ disable execution บน upload directory
