# Hypothesis-Driven Threat Hunt: Fake CAPTCHA Prompting Malicious PowerShell Execution

## Step 1: Define the Hypothesis
"Threat actors are deploying fake CAPTCHA challenges that instruct users to execute malicious PowerShell commands, leading to system compromise."

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

### For Google Chronicle (YARA-L)

**Detect Clipboard Copying of PowerShell Commands**:  
Focus on detecting subsequent PowerShell executions that could result from clipboard copying actions. YARA-L can be used to identify patterns indicative of PowerShell commands being executed after clipboard copying events.


### For Google Chronicle (YARA-L).

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

----------------------------------------------------------------------------------------------
### Identify PowerShell Download and Execution:

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

----------------------------------------------------------------------------------------------
### For SentinelOne (EDR):

SELECT 
    process_name, command_line, user, device_name, timestamp 
FROM 
    processes 
WHERE 
    process_name = 'powershell.exe' 
    AND command_line LIKE '%(New-Object Net.WebClient)%' 
    AND command_line LIKE '%DownloadString%'
ORDER BY timestamp DESC;

