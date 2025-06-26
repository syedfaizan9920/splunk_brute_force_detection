# 🚨 Brute Force Detection in Linux using Splunk Correlation Search & Alerts


## 🔍 Overview

This project demonstrates how to detect **brute force login attempts** on Linux servers using **Splunk SPL**, correlation searches, and real-time alerting. Failed SSH login attempts from the same IP or user are correlated and flagged, helping Security Operations Center (SOC) teams respond faster.

> 🔐 Developed by [Faizanullah Syed](https://unmaskcyber.com) — SOC Analyst Trainee & Cybersecurity Enthusiast

---

## 🛠️ Technologies Used

- 💡 **Splunk Enterprise**
- 🐧 **Linux (Ubuntu / RHEL)**
- 📄 **Log Source**: `/var/log/auth.log`
- 📊 **SPL (Search Processing Language)**
- 📧 **Alerting System** (Email / Notable Events)

---

## 📘 Use Case Description

**Goal**: Correlate failed SSH login attempts from the same user or IP and raise a security alert when they exceed a threshold.

---

## 🔎 SPL Query

```spl
host=splunkufserver index=* sourcetype="auth-2" OR sourcetype="auth-4" OR source="/var/log/auth.log"
("Invalid user" OR "Failed password")
| rex "Invalid user (?<user>\w+)" 
| rex "Failed password for (invalid user )?(?<user>\w+)"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as attempt_count earliest(_time) as first_attempt latest(_time) as last_attempt by src_ip, user, host
| where attempt_count >= 5
| eval duration = last_attempt - first_attempt
| table _time, host, src_ip, user, attempt_count, duration, first_attempt, last_attempt
| sort -attempt_count

```

📊 Sample Output
Time	Host	IP Address	User	Attempts	Duration (s)	First Attempt	Last Attempt
2025-06-26 10:45:32	splunkufserver	192.168.1.10	admin	8	32	2025-06-26 10:45:00	2025-06-26 10:45:32

---

⚙️ Setting Up the Alert
Paste the SPL query into Splunk's Search & Reporting app.

Click Save As > Alert.

Configure:

Schedule: Every 5 minutes

Trigger condition: If results > 0

Action: Email / Webhook / Notable Event

Severity: High

---

🌐 Optional Enhancements
🌍 Add geolocation:

```spl

| iplocation src_ip
| table src_ip, Country, City
```

📁 Store attack logs:

| outputlookup brute_force_alerts.csv append=true

---

📈 Tags
#Splunk #SIEM #SOCAnalyst #CyberSecurity #BruteForceDetection #LinuxSecurity #FailedLogin #SplunkSPL #ThreatDetection #BlueTeam #LogAnalysis

---

👨‍💻 Author
Faizanullah Syed
🔗 Website: UnmaskCyber.com
📫 Email: faizanullah.syed19@gmail.com
💼 Role: SOC Analyst Trainee & Cybersecurity Enthusiast


