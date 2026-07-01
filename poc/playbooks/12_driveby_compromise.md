---
threat_name: Drive-by Compromise
technique_ids: ["T1189", "T1204.001", "T1059.007"]
severity: High
source_doc: Driveby_Compromise_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- ติดตั้ง **web proxy (Zscaler, Blue Coat, Squid)** ที่ log full URL, referrer, content-type, และ response code
- เตรียม **Cuckoo Sandbox** หรือ **ANY.RUN** สำหรับ analyze malicious URL และ JavaScript payload
- ติดตั้ง **Sysmon** พร้อม config ที่ log child process ของ browser (chrome.exe, firefox.exe, msedge.exe)
- เตรียม **Browser forensic tool** (BrowsingHistoryView, ChromeCacheView) สำหรับ extract browser history
- มี **threat intel feed** สำหรับ known malicious URL/domain lookup (VirusTotal, URLscan.io)
- ติดตั้ง **exploit kit indicator database** (Emerging Threats rules) บน IDS/IPS
- เตรียม **JavaScript deobfuscator** (JStillery, de4js) สำหรับ analyze malicious JavaScript

### Sub: team_roles
- **Incident Commander**: ประเมินว่า exploit สำเร็จและ payload ถูก execute หรือไม่
- **Browser/Endpoint Forensic Analyst**: วิเคราะห์ browser history, cache, และ process ที่ spawn จาก browser
- **Malware Analyst**: decode JavaScript payload, ระบุ exploit kit (RIG, Magnitude, Angler), analyze dropped malware
- **Web Proxy Analyst**: ระบุ URL ที่ deliver exploit, ตรวจ redirect chain, block ที่ proxy
- **SOC Analyst (L2/L3)**: hunt endpoint อื่นที่ visit URL เดียวกัน จาก proxy log
- **Threat Intelligence**: attribute exploit kit, ระบุ campaign และ dropped malware family

### Sub: comm_plan
- แจ้ง **endpoint team** ทันทีเมื่อพบ browser spawn process ผิดปกติ
- ส่ง **P2 Alert** ไปยัง CISO — drive-by อาจ deliver ransomware, RAT, หรือ credential stealer
- แจ้ง **user** ที่ visit URL นั้นให้หยุดใช้ machine และรายงาน ทันที
- ประสาน **IT ทั้งหมด** เพื่อ block malicious URL ที่ proxy และ DNS
- ตรวจสอบว่า **user อื่น** visit URL เดียวกันหรือไม่ผ่าน proxy log

## Phase: detection
### Sub: log_sources
- **Web Proxy Log**: URL ที่ถูก visit, referrer, content-type ที่เป็น `text/html` ตามด้วย `application/javascript` หรือ `.swf`
- **Sysmon Event ID 1**: child process spawn จาก browser process (`chrome.exe`, `firefox.exe`, `msedge.exe`, `iexplore.exe`)
- **Sysmon Event ID 3**: browser process เปิด outbound connection ไปยัง unusual IP
- **Sysmon Event ID 11**: ไฟล์ถูก drop ใน `%TEMP%`, `%APPDATA%` โดย browser process
- **Windows Defender/EDR**: alert สำหรับ exploit payload หรือ dropped malware
- **IDS/IPS (Suricata/Snort)**: ET rule `EXPLOIT_KIT` หรือ `MALICIOUS_URL` alert
- **DNS Log**: browser query domain ที่อยู่ใน threat intel blacklist

### Sub: detection_queries
**Splunk — ตรวจ process spawn จาก browser (Sysmon Event ID 1):**
```spl
index=sysmon EventCode=1
| where (ParentImage LIKE "%chrome.exe%" OR ParentImage LIKE "%firefox.exe%"
         OR ParentImage LIKE "%msedge.exe%" OR ParentImage LIKE "%iexplore.exe%")
  AND NOT (Image LIKE "%chrome.exe%" OR Image LIKE "%firefox.exe%"
           OR Image LIKE "%msedge.exe%" OR Image LIKE "%plugin-container.exe%"
           OR Image LIKE "%crashpad_handler.exe%" OR Image LIKE "%GPUProcess%")
| table _time, ComputerName, User, ParentImage, Image, CommandLine
| sort -_time
```

**Splunk — ตรวจ malicious URL pattern ใน proxy log:**
```spl
index=proxy_logs
| where (url LIKE "%.php?id=%" OR url LIKE "%landing%sid=%" OR url LIKE "%gate.php%"
         OR url LIKE "%/ad/%/%/%" OR url LIKE "%exploit%")
  AND (content_type LIKE "%javascript%" OR content_type LIKE "%application/x-shockwave-flash%")
| stats count by src_ip, url, referrer, user_agent
| sort -count
```

**Splunk — ตรวจ file drop ใน TEMP โดย browser process (Sysmon Event ID 11):**
```spl
index=sysmon EventCode=11
| where (Image LIKE "%chrome.exe%" OR Image LIKE "%firefox.exe%" OR Image LIKE "%msedge.exe%")
  AND (TargetFilename LIKE "%\\Temp\\%.exe" OR TargetFilename LIKE "%\\Temp\\%.dll"
       OR TargetFilename LIKE "%\\Temp\\%.js" OR TargetFilename LIKE "%AppData%\\%.exe")
| table _time, ComputerName, User, Image, TargetFilename
```

**CLI — ตรวจ browser child process บน Windows:**
```powershell
Get-WmiObject Win32_Process | Where-Object {$_.ParentProcessId -in (Get-Process -Name "chrome","firefox","msedge" -ErrorAction SilentlyContinue).Id} |
  Select-Object ProcessId, Name, CommandLine, @{N='ParentName';E={(Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue).Name}}
```

**CLI — ตรวจ browser cache สำหรับ malicious content:**
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\" |
  Where-Object {$_.Length -gt 1MB -and $_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
  Select-Object FullName, Length, LastWriteTime
```

**Splunk — ตรวจ IDS alert สำหรับ exploit kit:**
```spl
index=ids_alerts
| where signature LIKE "*EXPLOIT*KIT*" OR signature LIKE "*MALICIOUS*URL*" OR signature LIKE "*DRIVEBY*"
| stats count by src_ip, dest_ip, signature, url
| sort -count
```

### Sub: ioc_list
- **URL patterns**: URL ที่มี redirect chain หลายขั้น, URL สั้นจาก URL shortener, URL ที่มี random parameter
- **Referrer chain**: ถูก redirect จาก legitimate site ที่ถูก compromise ไปยัง exploit kit landing page
- **Content-type anomaly**: web page ที่ serve `.exe`, `.dll`, `.jar`, `.swf` file
- **Process anomaly**: `cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe` spawn จาก browser
- **File drop**: executable ใน `%TEMP%` ที่ถูกสร้างโดย browser process
- **JavaScript obfuscation**: JavaScript ที่มี `eval()`, `unescape()`, `String.fromCharCode()` ซ้อนกันหลายชั้น
- **Exploit kit signatures**: Suricata/Snort alert สำหรับ RIG EK, Magnitude EK, PurpleFox

### Sub: scope_analysis
- ระบุ **URL ที่เป็น exploit kit landing page** จาก proxy log
- ตรวจสอบว่า **exploit สำเร็จหรือไม่**: browser process spawn child process หรือมี file drop หรือไม่
- ระบุ **endpoint อื่น** ที่ visit URL เดียวกัน (อาจมีหลาย user ที่โดน drive-by เดียวกัน)
- วิเคราะห์ **redirect chain**: เริ่มจาก website ใด → intermediate URL → exploit kit → payload
- ระบุ **payload ที่ถูก drop**: ransomware, RAT, banking trojan, cryptominer
- ตรวจสอบว่า **browser และ plugin** บน endpoint เป็น version เก่าที่มี vulnerability หรือไม่

## Phase: containment
### Sub: short_term
1. **Block malicious URL** ที่ web proxy ทันที (landing page, payload URL, C2)
2. **Block malicious domain** ที่ DNS server: เพิ่มใน RPZ sinkhole
3. **Isolate endpoint** ที่พบ browser spawn unusual process
4. **Kill suspicious process** ที่ spawn จาก browser: `Stop-Process -Id <pid> -Force`
5. **ลบ downloaded payload** ใน `%TEMP%` และ `%APPDATA%` (เก็บ hash ก่อน): `Remove-Item "$env:TEMP\*.exe" -Force`
6. **Block C2 IP/domain** ที่ payload เชื่อมต่อ ที่ Firewall
7. **Force browser update** บน affected endpoint เพื่อ patch browser vulnerability

### Sub: long_term
- ใช้ **web proxy ที่มี SSL inspection** เพื่อ inspect HTTPS traffic สำหรับ malicious content
- Deploy **browser isolation** (Zscaler ZIA, Symantec Web Isolation) สำหรับ high-risk browsing
- บังคับ **browser auto-update policy** บน endpoint ทุกเครื่อง
- ใช้ **DNS-based blocking** ด้วย threat intel feed ที่ block malicious domain โดยอัตโนมัติ
- Implement **application whitelisting** เพื่อ block execution ของ unknown binary ใน `%TEMP%`

### Sub: evidence_preservation
- เก็บ **browser history** และ **cache** ก่อน reimage: `Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\" C:\evidence\chrome_data\ -Recurse`
- Export **web proxy log** ช่วง incident พร้อม full URL, referrer, user-agent
- เก็บ **dropped malware file** พร้อม hash (เก็บใน quarantine): `sha256sum malware.exe > malware.exe.sha256`
- บันทึก **Sysmon log** (Event 1, 3, 11) ช่วง incident
- Capture **JavaScript payload** จาก browser cache สำหรับ static analysis

## Phase: eradication
### Sub: process_removal
- ลบ **malware process** ที่ถูก drop และรันอยู่:
  ```powershell
  Get-Process | Where-Object {$_.Path -match "Temp|AppData\\Roaming"} | Select-Object Name, Id, Path
  ```
- ลบ **injected DLL** ที่ browser process โหลด (Sysmon Event ID 7)
- Scan ด้วย **EDR offline scan** เพื่อ detect rootkit หรือ fileless component

### Sub: persistence_removal
- ลบ **registry Run key** ที่ dropped malware สร้าง
- ลบ **scheduled task** สำหรับ malware persistence
- ลบ **browser extension** ที่ malicious ที่อาจถูก install โดย exploit:
  ```powershell
  Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\" | Select-Object Name, LastWriteTime
  ```
- ตรวจสอบ **startup folder** และ **Winlogon registry** ที่อาจถูกแก้ไข

### Sub: patching
- **อัปเดต browser** ทุกตัวเป็น version ล่าสุดทันที: `winget upgrade --all`
- ปิด/อัปเดต **browser plugin ที่เก่า**: Java, Flash (ซึ่งควรปิดทั้งหมดแล้ว), Silverlight
- อัปเดต **Windows** โดยเฉพาะ patch สำหรับ JScript/VBScript engine
- บังคับ **browser auto-update** ผ่าน Group Policy

## Phase: post_incident
### Sub: lessons_learned
- วิเคราะห์ว่า **web proxy** สามารถ block malicious URL ก่อน endpoint โหลดได้หรือไม่
- ตรวจสอบว่า **browser version** เป็น version ที่มี patch ที่จำเป็นหรือไม่
- ประเมิน **จำนวน user** ที่ visit URL เดียวกันและอาจถูก exploit
- วิเคราะห์ว่า **IDS/IPS** detect exploit kit signature ได้หรือไม่
- ตรวจสอบว่า **user awareness** เพียงพอหรือไม่ในการ recognize suspicious URL

### Sub: improvements
- Deploy **browser isolation** สำหรับ high-risk activity (เปิด email link, ดาวน์โหลดจาก external)
- เพิ่ม **threat intel URL feed** ใน web proxy สำหรับ auto-block
- บังคับ **browser update policy** ผ่าน SCCM/Intune
- เพิ่ม **SIEM rule** สำหรับ browser child process spawning และ file drop ใน TEMP
- จัด **user awareness campaign** เรื่องการ recognize suspicious website และ report
