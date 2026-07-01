---
threat_name: Cryptomining
technique_ids: ["T1496", "T1059.001", "T1053.005"]
severity: Medium
source_doc: Cryptomining_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เตรียม **CPU/GPU monitoring tool** (Zabbix, Prometheus + Grafana) สำหรับ baseline CPU usage ต่อ host
- ติดตั้ง **Process Explorer (Sysinternals)** สำหรับ inspect process และ DLL ที่ load
- เตรียม **XMRig signature** และ **YARA rule** สำหรับ scan binary ที่น่าสงสัย
- มี **network monitoring** สำหรับ detect connection ไปยัง mining pool (port 3333, 4444, 14444, 45700)
- เตรียม **hash database** ของ known cryptominer (XMRig, XMRstak, CGMiner variants)
- ติดตั้ง **Sysmon** พร้อม config log Process Create, Network Connection
- เตรียม list ของ **mining pool IP/domain** จาก threat intel feed (MoneroOcean, nanopool, f2pool)

### Sub: team_roles
- **Incident Commander**: ประเมิน business impact (system performance degradation, electricity cost, cloud bill spike)
- **System Administrator**: ระบุ process ที่กิน CPU สูง, ตรวจสอบ scheduled task และ persistence
- **SOC Analyst (L2/L3)**: hunt network connection ไปยัง mining pool, ระบุเครื่องที่ infected
- **Cloud/Infrastructure Team**: ตรวจสอบ cloud instance ที่ถูก spin up เพิ่มสำหรับ mining (resource hijacking)
- **Malware Analyst**: ระบุ cryptominer variant, C2 infrastructure, และ initial access vector
- **Finance/Cloud Ops**: ตรวจสอบ cloud cost spike ที่อาจเกิดจาก unauthorized instance

### Sub: comm_plan
- แจ้ง **Sysadmin** ทันทีเมื่อพบ CPU usage > 90% จาก process ที่ไม่รู้จักบนหลาย host
- ส่ง **P3/P2 Alert** ขึ้นอยู่กับว่า production system ได้รับผลกระทบหรือไม่
- แจ้ง **Cloud Ops** หากพบ cryptomining ใน cloud environment (AWS/Azure) เพราะค่าใช้จ่ายสูง
- แจ้ง **application team** หากระบบช้าเนื่องจาก CPU ถูกแย่งใช้โดย miner
- บันทึก **wallet address** และ **mining pool** ที่ระบุได้ สำหรับ attribution

## Phase: detection
### Sub: log_sources
- **System Performance Log**: CPU utilization > 80-90% จาก process ที่ไม่ใช่ business application
- **Sysmon Event ID 1**: process ชื่อ `xmrig.exe`, `xmrstak.exe`, หรือ binary ที่ rename ตัวเอง
- **Sysmon Event ID 3**: outbound connection ไปยัง mining pool domain/IP บน port 3333, 4444, 14444, 45700
- **Windows Task Manager / perfmon**: process ที่ใช้ CPU > 80% ต่อเนื่อง
- **Firewall Log**: outbound connection ไปยัง known mining pool domain หรือ Stratum protocol
- **Cloud Billing Alert**: unexpected spike ใน compute cost ใน AWS/Azure/GCP
- **Sysmon Event ID 11**: cryptominer binary ถูก drop ใน `%TEMP%`, `%APPDATA%`, หรือ system directory

### Sub: detection_queries
**Splunk — ตรวจ process ที่มี CPU สูงผิดปกติ (จาก perfmon/WMI log):**
```spl
index=windows_perf counter_name="% Processor Time" object_name="Process"
| where instance NOT IN ("_Total","Idle","System","svchost","lsass","csrss")
| stats avg(Value) as avg_cpu by instance, host
| where avg_cpu > 80
| sort -avg_cpu
```

**Splunk — ตรวจ connection ไปยัง mining pool (Sysmon Event ID 3):**
```spl
index=sysmon EventCode=3
| where (DestinationPort IN (3333, 4444, 14444, 45700, 3334, 5555, 7777, 9999, 14433))
  OR (DestinationHostname LIKE "*monerohash*" OR DestinationHostname LIKE "*nanopool*"
      OR DestinationHostname LIKE "*moneroocean*" OR DestinationHostname LIKE "*2miners*"
      OR DestinationHostname LIKE "*f2pool*" OR DestinationHostname LIKE "*supportxmr*")
| table _time, ComputerName, Image, DestinationIp, DestinationHostname, DestinationPort
| sort -_time
```

**Splunk — ตรวจ XMRig process (Sysmon Event ID 1):**
```spl
index=sysmon EventCode=1
| where (Image LIKE "%xmrig%"  OR Image LIKE "%xmrstak%" OR Image LIKE "%minerd%"
         OR CommandLine LIKE "*--donate-level*" OR CommandLine LIKE "*stratum+tcp*"
         OR CommandLine LIKE "*-o pool.*" OR CommandLine LIKE "*--coin*monero*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

**Splunk — ตรวจ Stratum protocol pattern ในconnection:**
```spl
index=firewall
| where dest_port IN (3333, 4444, 14444, 45700)
| stats count, sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where count > 100
| sort -count
```

**CLI — ตรวจ process ที่ใช้ CPU สูงบน Linux:**
```bash
ps aux --sort=-%cpu | head 20 | awk '{print $1, $2, $3, $4, $11}'
```

**CLI — ตรวจ outbound connection ไปยัง mining port บน Linux:**
```bash
ss -tnp | grep -E ":3333|:4444|:14444|:45700" | grep ESTABLISHED
```

**CLI — ค้นหา XMRig binary บน Windows:**
```powershell
Get-ChildItem -Path C:\ -Recurse -Include "*.exe" -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} |
  ForEach-Object { $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash; "$hash $($_.FullName)" } |
  Select-String -Pattern "KNOWN_XMRIG_HASH_1|KNOWN_XMRIG_HASH_2"
```

### Sub: ioc_list
- **Process name**: `xmrig.exe`, `xmrstak.exe`, `minergate.exe`, หรือ binary ที่ renamed เป็น `svchost32.exe`, `update.exe`
- **CPU pattern**: CPU utilization > 80% ต่อเนื่อง > 30 นาที จาก non-business process
- **Network**: outbound TCP ไปยัง port 3333, 4444, 14444, 45700 หรือ domain ที่มี `pool`, `mine`, `hash` ใน domain name
- **Stratum protocol**: network payload ที่ขึ้นต้นด้วย `{"method":"mining.subscribe"` หรือ `{"method":"login"`
- **Command line flags**: `--donate-level`, `-o stratum+tcp://`, `--coin monero`, `-u <wallet_address>`
- **File**: `config.json` ที่มี wallet address และ pool URL ใน `%TEMP%` หรือ hidden directory
- **Cloud anomaly**: cloud instance ที่มี CPU utilization สูงมากแต่ไม่มี legitimate workload

### Sub: scope_analysis
- ระบุ **จำนวน host ที่ infected**: ตรวจสอบว่า cryptominer ถูก deploy ผ่าน lateral movement หรือ vulnerability scan
- ตรวจสอบ **mining pool และ wallet address** ที่ใช้ — อาจ attribute ไปยัง known threat actor group
- ประเมิน **ระยะเวลา** ที่ miner ทำงาน: ดูจาก creation timestamp ของ malware file
- ตรวจสอบ **initial access vector**: ช่องโหว่ web application, phishing, brute force, supply chain
- ประเมิน **ผลกระทบ**: performance degradation บน production system, cloud cost, electricity cost
- ตรวจสอบ **cloud environment**: มี unauthorized EC2/Azure VM ถูก spin up หรือไม่

## Phase: containment
### Sub: short_term
1. **Kill cryptominer process** ทันที: `Stop-Process -Name xmrig -Force` / `pkill -f xmrig`
2. **Block outbound port 3333, 4444, 14444, 45700** ที่ Firewall สำหรับ endpoint ทั่วไป
3. **Block mining pool domain** ที่ DNS: เพิ่มใน sinkhole (nanopool.org, moneroocean.stream, etc.)
4. **Isolate endpoint** ที่ infected ออกจาก network
5. **ปิด cloud instance** ที่ spin up โดยไม่ได้รับอนุญาต (terminate unauthorized EC2/Azure VM)
6. **Revoke cloud API key/credential** ที่ถูกใช้สร้าง mining instance
7. **ตั้ง CPU throttling** ชั่วคราวหาก isolate ทันทีไม่ได้ (Linux: `cpulimit -l 30 -p <pid>`)

### Sub: long_term
- ใช้ **cloud cost alert**: set budget alert สำหรับ compute cost spike > 20% จาก baseline
- Deploy **EDR** ที่ detect cryptominer behavior (high CPU + network to mining pool)
- ใช้ **network egress filtering**: block outbound Stratum protocol ที่ perimeter
- Implement **cloud security posture management (CSPM)**: detect unauthorized resource creation
- ทบทวน **IAM policy** สำหรับ cloud: จำกัด permission สร้าง compute instance

### Sub: evidence_preservation
- เก็บ **cryptominer binary** พร้อม hash ก่อนลบ: `sha256sum xmrig.exe > xmrig.sha256`
- บันทึก **config.json** ที่มี wallet address และ pool URL (เป็น IOC สำคัญ)
- Export **process list** พร้อม CPU usage ณ เวลา incident
- เก็บ **network connection log** ที่แสดง mining pool connection
- บันทึก **cloud billing data** ที่แสดง anomalous compute usage

## Phase: eradication
### Sub: process_removal
- Kill และ verify ไม่มี miner process เหลืออยู่:
  ```bash
  # Linux
  ps aux | grep -E "(xmrig|minerd|cpuminer|cryptonight)" | grep -v grep | awk '{print $2}' | xargs kill -9
  ```
  ```powershell
  # Windows
  Get-Process | Where-Object {$_.CPU -gt 1000} | Select-Object Name, Id, CPU, Path | Format-Table
  ```
- ตรวจสอบว่า **miner ไม่ได้ inject** เข้าไปใน process อื่น (process hollowing)

### Sub: persistence_removal
- ลบ **scheduled task** ที่ restart miner:
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Actions.Execute -match "xmrig|minerd|update"} | Unregister-ScheduledTask -Confirm:$false
  ```
- ลบ **cron job** บน Linux: `crontab -l | grep -v "xmrig\|minerd" | crontab -`
- ลบ **registry Run key** ที่ miner สร้าง
- ตรวจสอบ **systemd service** ที่ถูกสร้างสำหรับ auto-start miner: `systemctl list-units | grep -E "(mining|update|sync)"`

### Sub: patching
- **Patch vulnerability** ที่ attacker ใช้ initial access (เช่น EternalBlue, Log4Shell, Apache Struts)
- อัปเดต **web server และ application framework** ทุกตัว
- ทบทวน **cloud IAM permission** และ revoke unused access key
- อัปเดต **AV/EDR signature** สำหรับ cryptominer variant ที่ตรวจพบ

## Phase: post_incident
### Sub: lessons_learned
- ระบุ **initial access vector**: patch vulnerability อะไรที่ยังไม่ได้ apply ก่อน incident
- ประเมิน **ระยะเวลา** ที่ miner ทำงานและ cost ที่เกิดขึ้น (electricity, cloud cost)
- วิเคราะห์ว่า **CPU monitoring** มีอยู่และทำไมไม่ alert เร็วกว่านี้
- ตรวจสอบว่า **miner spread** ไปยัง machine อื่น ผ่าน lateral movement หรือไม่
- ประเมิน **severity จริง**: มีข้อมูลถูก exfiltrate ควบคู่กับ cryptomining หรือไม่

### Sub: improvements
- ติดตั้ง **CPU/performance monitoring** พร้อม alert เมื่อ CPU สูงต่อเนื่อง > threshold
- เพิ่ม **SIEM rule** ตรวจ Stratum protocol connection และ known mining pool domain
- Deploy **patch management** ที่ enforce patch บน critical vulnerability ภายใน 72 ชั่วโมง
- Implement **cloud cost monitoring** พร้อม automatic alert และ terminate unauthorized instance
- ทำ **regular vulnerability scan** เพื่อ identify exposed service ก่อน attacker
