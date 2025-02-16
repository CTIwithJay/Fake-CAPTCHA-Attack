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
While direct clipboard monitoring might be challenging, focus on detecting subsequent PowerShell executions that could result from actions involving clipboard copying. YARA-L can be used to identify patterns indicative of PowerShell commands being executed after clipboard copying events.
