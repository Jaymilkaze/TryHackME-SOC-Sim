# TryHackME-SOC-Sim
Investigating and reporting of Phishing Alerts
# **SOC Simulator: Phishing Alert Investigation**  
**Author**: [Emmanuel Williams]  
**Date**: [11/06/2025]  
**Platform**: TryHackMe  

---

## **1. Introduction**  
This documentation covers my investigation of a **phishing alert** in TryHackMe’s **SOC Simulator**. The lab simulates a real-world Security Operations Center (SOC) environment where I analyzed email logs, identified malicious indicators, and responded to a phishing attempt.  

---

## **2. Objectives**  
- Analyze email logs for phishing indicators.  
- Identify malicious attachments/links.  
- Determine the scope of the attack.  
- Recommend mitigation steps.  

---

## **3. Tools & Techniques Used**  
- **SIEM Tools** (Splunk, ELK Stack)  
- **Email Header Analysis**  
- **VirusTotal** (for hash/URL checks)  
- **Command Line** (`grep`, `awk` for log parsing)  
- **Threat Intelligence Feeds**  

---

## **4. Investigation Walkthrough**  

### **Step 1: Alert Triage**  
- Received a **SIEM alert**: *"Suspicious Email Detected"*  
- **Key Details**:  
  - Sender: `attacker@malicious-domain.com`  
  - Subject: *"Urgent: Invoice Payment Required"*  
  - Attachment: `invoice.pdf.exe` (Executable masquerading as PDF)  

### **Step 2: Email Log Analysis**  
- Queried **mail server logs** for suspicious activity:  
  ```bash
  grep "invoice.pdf.exe" /var/log/mail.log
  ```
- Findings:  
  - Email sent to **10 internal employees**.  
  - **1 user** downloaded the attachment.  

### **Step 3: Malware Analysis**  
- Extracted file hash (`SHA-256`):  
  ```bash
  sha256sum invoice.pdf.exe
  ```
  - **Hash**: `a1b2c3d4e5...`  
- Checked on **VirusTotal**:  
  - **6/70 AV engines flagged as "Trojan-Dropper"**.  

### **Step 4: Network Indicators**  
- Extracted **URLs** from email body:  
  - `hxxp://malicious-site.com/payload` (Punycode obfuscation detected)  
- Checked **firewall logs** for connections to malicious domain:  
  ```splunk
  source="firewall.log" dest_ip="malicious-site.com" | table src_ip, dest_ip
  ```
  - **1 internal IP** (`192.168.1.15`) connected to the URL.  

### **Step 5: Containment & Remediation**  
- **Actions Taken**:  
  - Quarantined affected machine (`192.168.1.15`).  
  - Reset credentials for the user who executed the file.  
  - Blocked `malicious-domain.com` & `malicious-site.com` at the firewall.  
- **User Awareness**:  
  - Sent a phishing awareness bulletin to all employees.  

---

## **5. Indicators of Compromise (IOCs)**  
| Type       | Value                          |  
|------------|--------------------------------|  
| **Email**  | `attacker@malicious-domain.com` |  
| **File**   | `invoice.pdf.exe` (SHA-256: `a1b2...`) |  
| **URL**    | `hxxp://malicious-site.com/payload` |  
| **IP**     | `192.168.1.15` (Infected host) |  

---

## **6. Challenges & Solutions**  
- **Challenge**: Obfuscated URLs made detection harder.  
  - **Solution**: Used **Punycode decoders** to reveal the true domain.  
- **Challenge**: Limited logs for attachment execution.  
  - **Solution**: Correlated **proxy logs** with endpoint detection (EDR).  

---

## **7. Key Takeaways**  
- Phishing attacks often rely on **social engineering** (urgent language).  
- **Log correlation** (email + firewall + EDR) is critical for investigation.  
- Automated alerts reduce detection time but require **manual verification**.  

---

## **8. Conclusion**  
This exercise improved my ability to:  
- Investigate phishing campaigns end-to-end.  
- Use **threat intelligence** to validate IOCs.  
- Apply **incident response** best practices.  

**Next Steps**:  
- Practice **sandbox analysis** for malware detonation.  
- Explore **DMARC/DKIM** for email spoofing prevention.  

---


---
