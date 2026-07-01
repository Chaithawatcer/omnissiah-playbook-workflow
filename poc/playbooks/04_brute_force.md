---
threat_name: Brute Force
technique_ids: ["T1110.001", "T1078", "T1021.001"]
severity: High
source_doc: Brute_Force_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เตรียม **fail2ban** หรือ **Windows Account Lockout Policy** กำหนด lockout หลัง 5 ครั้ง
- ติดตั้ง **Hydra / Medusa** บน sandbox สำหรับ simulate brute force และทดสอบ detection
- เตรียม **GoAccess** หรือ script parse auth log (`/var/log/auth.log`, `/var/log/secure`)
- มี access ไปยัง **Active Directory Audit Log** (Event ID 4625, 4740, 4771)
- เตรียม **GeoIP lookup tool** (MaxMind GeoLite2) สำหรับระบุประเทศของ source IP
- ติดตั้ง **Duo Security MFA** หรือ **Azure AD MFA** สำหรับ remediation ฉุกเฉิน
- เตรียม **password reset workflow** ที่ผ่าน out-of-band verification (SMS/email ที่ไม่ได้ compromise)

### Sub: team_roles
- **Incident Commander**: ตัดสินใจ lockout account หรือ block IP ระดับ network
- **SOC Analyst (L2)**: monitor auth log แบบ real-time, ยืนยัน brute force pattern
- **Active Directory Admin**: reset password, unlock account, ตรวจสอบ group membership ที่เปลี่ยนแปลง
- **Network Engineer**: block source IP ที่ Firewall/ISP level
- **Application Owner**: ตรวจสอบ application login log, ยืนยัน account ที่สำเร็จ login
- **Help Desk**: รับแจ้งจาก user ที่ account ถูก lockout และ verify identity ก่อน unlock

### Sub: comm_plan
- แจ้ง **AD Admin** ทันทีเมื่อพบ account ถูก lockout > 10 accounts ในเวลาสั้น
- ส่ง **P2 Alert** ไปยัง CISO หากพบว่า admin account ถูก target
- ใช้ **Secure Channel** แจ้ง account ที่อาจถูก compromise ให้ reset password ทันที
- แจ้ง **ISP** หากพบ botnet IP ขนาดใหญ่ เพื่อขอ block upstream
- บันทึก **จำนวน account ที่ถูก lockout** และ IP ที่เกี่ยวข้องใน timeline
- ประสาน **HR** หาก executive account ถูก target เพื่อแจ้งเตือนล่วงหน้า

## Phase: detection
### Sub: log_sources
- **Windows Security Event Log**: Event ID 4625 (logon failure), 4740 (account lockout), 4771 (Kerberos pre-auth failure)
- **Linux auth log**: `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS)
- **SSH log**: `/var/log/auth.log` — ดู `Failed password for` และ `Invalid user`
- **Web Application Log**: ดู POST /login endpoint ที่มี HTTP 401/403 ซ้ำจาก IP เดียว
- **VPN Access Log** (Cisco ASA, Palo Alto): ดู authentication failure สำหรับ remote access
- **Azure AD Sign-in Log**: ดู `Sign-in risk` และ `Failure reason: Invalid username or password`
- **RADIUS Log**: สำหรับ WiFi หรือ VPN ที่ใช้ RADIUS authentication

### Sub: detection_queries
**Splunk — ตรวจ Windows Brute Force (Event ID 4625):**
```spl
index=windows_security EventCode=4625
| stats count by src_ip, Account_Name, Logon_Type
| where count > 20
| sort -count
| eval alert="Possible Brute Force"
```

**Splunk — ตรวจ Account Lockout (Event ID 4740):**
```spl
index=windows_security EventCode=4740
| stats count by TargetUserName, _time
| sort -_time
| table _time, TargetUserName, count
```

**CLI — grep SSH brute force บน Linux:**
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head 20
```

**CLI — นับ failed login ต่อ IP บน Linux:**
```bash
grep "Failed password" /var/log/secure | grep -oP '(?<=from )\S+' | sort | uniq -c | sort -rn | awk '$1 > 10 {print $0}'
```

**Elastic (KQL) — Login failure rate:**
```kql
event.code: "4625" AND winlog.event_data.FailureReason: "Unknown user name or bad password"
| where count() > 20 by source.ip, winlog.event_data.TargetUserName
```

**CLI — ตรวจสอบ account ที่ถูก lockout ใน AD:**
```powershell
Search-ADAccount -LockedOut | Select-Object Name, LockedOut, LastLogonDate, DistinguishedName
```

### Sub: ioc_list
- **High failure rate**: IP เดียว > 50 failed login ภายใน 5 นาที (threshold ปรับตาม baseline)
- **Sequential username pattern**: ลอง admin, administrator, admin1, admin2, user1, user2
- **Password spray pattern**: username หลาย account แต่ใช้ password เดียว (เช่น `Summer2024!`)
- **Non-business hour activity**: login attempt ช่วง 02:00-05:00 จาก IP ต่างประเทศ
- **Tor exit nodes / VPN IP**: IP ที่อยู่ใน known Tor exit node list หรือ commercial VPN ranges
- **Logon Type 3 (Network) หรือ Type 10 (RemoteInteractive)** จาก IP ที่ไม่เคยใช้มาก่อน
- **Kerberos Error Code 0x18** (KDC_ERR_PREAUTH_FAILED): บ่งบอก wrong password สำหรับ valid user

### Sub: scope_analysis
- นับ **จำนวน account ที่ถูก target** — ถ้า > 100 accounts อาจเป็น password spray ในระดับ domain
- ตรวจสอบว่า **account ใดสำเร็จ login** หลังจาก failed หลายครั้ง (Event ID 4624 หลัง 4625)
- ระบุ **Logon Type**: Type 3 = network logon, Type 10 = RDP — แต่ละ type มีความเสี่ยงต่างกัน
- ตรวจสอบ **geographic source**: IP มาจากประเทศที่ผิดปกติสำหรับ organization หรือไม่
- หาว่า attack เป็น **targeted** (username จำเพาะ) หรือ **spray** (username หลาย account, password น้อย)
- ตรวจสอบ **privileged account** ที่ถูก target: DA, Schema Admin, Service Account

## Phase: containment
### Sub: short_term
1. **Lock account ที่ถูก target** ชั่วคราวจาก AD: `Disable-ADAccount -Identity <username>`
2. **Block source IP** ที่ Firewall ทันที: `netsh advfirewall firewall add rule name="Block Brute Force" dir=in action=block remoteip=<attacker_ip>`
3. **เปิด fail2ban** สำหรับ SSH บน Linux หากยังไม่ได้เปิด: `systemctl enable --now fail2ban`
4. **บังคับ CAPTCHA** ที่ login page สำหรับ IP ที่มี failure > 5 ครั้ง
5. **Reset password** ทันทีสำหรับ account ที่มี Event ID 4624 (successful login) หลังถูก brute force
6. **Revoke active session** สำหรับ account ที่สงสัยถูก compromise
7. **เปิด MFA ฉุกเฉิน** สำหรับ privileged account ทุก account ที่ยังไม่มี MFA

### Sub: long_term
- บังคับใช้ **Account Lockout Policy**: lockout หลัง 5 failures, reset counter ทุก 30 นาที
- Deploy **MFA สำหรับ remote access ทุก protocol** (VPN, RDP, OWA, SSH)
- ใช้ **Geo-blocking**: block ประเทศที่ไม่มี business relationship
- Implement **Adaptive Authentication**: เพิ่ม friction เมื่อ login จาก IP/device ใหม่
- ติดตั้ง **Honeypot account** (เช่น account ชื่อ "admin" ที่ไม่ได้ใช้จริง) สำหรับ early warning

### Sub: evidence_preservation
- Export **Windows Security Event Log** ทั้งหมด ช่วง incident: `wevtutil epl Security C:\evidence\security_log.evtx`
- เก็บ **auth.log** บน Linux: `cp /var/log/auth.log /evidence/auth.log && sha256sum /evidence/auth.log`
- บันทึก **IP list ที่เกี่ยวข้อง** พร้อม timestamp และ GeoIP ลงใน CSV
- เก็บ **AD audit log** โดยเฉพาะ Event 4625, 4740, 4624 ช่วง incident
- Screenshot **SIEM dashboard** ที่แสดง attack pattern

## Phase: eradication
### Sub: process_removal
- ยืนยันว่าไม่มี **backdoor process** ที่ถูกสร้างหลัง successful login:
  ```powershell
  Get-Process | Where-Object {$_.StartTime -gt (Get-Date).AddHours(-24)} | Select-Object Name, Id, StartTime, Path
  ```
- ตรวจสอบ **scheduled task** ที่สร้างโดย account ที่ถูก compromise:
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "<compromised_user>"}
  ```
- ตรวจสอบ **new local user** ที่ถูกสร้างหลัง brute force สำเร็จ: `net user` และ `Get-LocalUser`

### Sub: persistence_removal
- **Reset password** ทุก account ที่ถูก brute force สำเร็จ และ force password change at next logon
- ลบ **SSH authorized_keys** ที่ถูกเพิ่มโดย attacker: `cat ~/.ssh/authorized_keys` และลบ key ที่ไม่รู้จัก
- ตรวจสอบ **sudoers file** บน Linux: `cat /etc/sudoers` และ `/etc/sudoers.d/`
- ลบ **registry Run key** ที่ถูกเพิ่มโดย account ที่ถูก compromise:
  ```powershell
  Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  ```

### Sub: patching
- **อัปเดต Account Lockout Policy** ผ่าน Group Policy: Computer Configuration → Windows Settings → Security Settings → Account Policies
- ติดตั้ง **MFA solution** สำหรับ all remote access: Azure AD MFA, Duo, Google Authenticator
- อัปเดต **SSH configuration**: ปิด `PasswordAuthentication no`, ใช้ key-based auth เท่านั้น
- ทบทวน **password complexity policy**: minimum 14 characters, check against HaveIBeenPwned wordlist

## Phase: post_incident
### Sub: lessons_learned
- วิเคราะห์ว่า **Lockout Policy** มีอยู่แล้วหรือไม่ และทำไมถึงไม่ block attacker ได้เร็วพอ
- ตรวจสอบว่า **MFA** ถูก enforce สำหรับ account ที่ถูก target หรือไม่
- ประเมิน **MTTD**: SIEM alert trigger เร็วพอที่จะป้องกัน successful login หรือไม่
- วิเคราะห์ว่า **account ที่ถูก lockout** ส่งผลกระทบต่อ business operations มากน้อยแค่ไหน
- ตรวจสอบว่ามี **password reuse** ข้าม system หลาย ระบบหรือไม่

### Sub: improvements
- **บังคับ MFA** ทุก account โดยเฉพาะ privileged account ภายใน 30 วัน
- เพิ่ม **SIEM rule** ตรวจ password spray pattern (failed login หลาย username จาก IP เดียว)
- Deploy **Identity Protection** (Azure AD Identity Protection หรือ equivalent)
- ทำ **Privileged Access Workstation (PAW)** สำหรับ admin account
- จัด training เรื่อง **Password Manager** และ unique password per service
