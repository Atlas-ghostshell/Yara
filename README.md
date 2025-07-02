# Yara

#  YARA Malware Detection & Auto-Removal with Wazuh

This project implements a *hybrid malware response system* using *YARA rules* and *Wazuh Active Response*.

##  What It Does

- Scans all newly added files using YARA
- Detects signs of Python-based malware (e.g., eval(base64.b64decode(...)))
- Automatically deletes malicious files *only if the YARA rule matches*
- Logs every action taken

## Components

### 1. detect_obfuscated_python.yar
A custom YARA rule that matches:
- eval, exec, base64.b64decode
- Signs of command execution like os.system
- Obfuscated strings (base64 ≥ 50 characters)

### 2. remove-threat.sh
The Active Response script that:
- Triggers only on rule match
- Logs everything for audit
- Does not delete safe files

### 3. Triggering Logic
The response is bound to *Rule ID 87104*:
- This rule fires on file creation via Wazuh’s FIM
- When it fires, remove-threat.sh scans the file with YARA
- If a match occurs → the file is deleted 
##  Screenshots
- Successful match and deletion
- False positive avoided
- Real-time logs from /var/ossec/logs/active-responses.log

##  Why This Matters
Traditional AV can miss obfuscated malware. This system gives defenders full control, speed, and transparency — especially useful in SOC environments or homelabs.
![Screenshot 2025-07-02 182454](https://github.com/user-attachments/assets/d153ae9b-a9b4-439d-b633-560d03a93428)

---

Built by Jeffrey (aka Ghost-Shell) & Atlas Maru Shepherd
