## TTPs for CAPTCHA Attack Threat Hunt

### Tactic: Initial Access
- **Technique: Spearphishing via Malicious Link (T1566.001)**: Fake CAPTCHA prompts are typically delivered through phishing emails or compromised websites, where users are tricked into clicking on malicious links.

### Tactic: Execution
- **Technique: PowerShell (T1059.001)**: Attackers may use PowerShell to execute commands that download the malware from a remote server after users interact with the fake CAPTCHA.

### Tactic: Persistence
- **Technique: PowerShell Profile (T1059.001)**: Attackers could leverage PowerShell profiles to maintain persistence by executing malicious scripts upon system startup.

### Tactic: Defense Evasion
- **Technique: Obfuscated Files or Information (T1027)**: The attack might employ obfuscated scripts or command-line arguments to evade detection by security tools like EDR and SIEM.

### Tactic: Command and Control
- **Technique: Application Layer Protocol (T1071.001)**: The malware might communicate with the attacker’s server using HTTP/S protocols to send or receive stolen data.

### Tactic: Exfiltration
- **Technique: Exfiltration Over Command and Control Channel (T1041)**: The malware could exfiltrate data via encrypted HTTP/S channels to avoid detection.
