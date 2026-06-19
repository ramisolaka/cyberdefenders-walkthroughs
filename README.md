# REvil Walkthrough

Simple CyberDefenders walkthrough for the `REvil` lab.

## Overview

This lab investigates a REvil ransomware infection using Splunk, CyberChef, VirusTotal, and ANY.RUN. The goal is to trace the attack from the ransom note back to the malware, identify what it did on the host, and collect the main indicators of compromise.

## Skills Demonstrated

- Splunk log analysis
- Process tracing
- Windows event investigation
- Base64 decoding
- Malware hash validation
- Threat intelligence correlation
- IOC identification

## Question 1

### Objective

Identify the filename of the ransom note left by the ransomware.

### Query

```spl
index=revil event.code=11
| search winlog.event_data.TargetFilename="*\\Downloads\\*"
| table time winlog.event_data.TargetFilename winlog.event_data.ProcessId winlog.event_data.User
```

### Evidence

![Question 1 search](REvil/images/q1-ransom-note-search.png)

### Answer

`5uizv5660t-readme.txt`

### Explanation

The same text file appears in multiple `Downloads` folders, which shows it is the ransom note dropped by the malware.

## Question 2

### Objective

Find the process ID linked to the ransom note creation.

### Query

```spl
index=revil event.code=11
| search winlog.event_data.TargetFilename="*\\Downloads\\*"
| table time winlog.event_data.TargetFilename winlog.event_data.ProcessId winlog.event_data.User
```

### Evidence

![Question 2 search](REvil/images/q2-process-id-search.png)

### Answer

`5348`

### Explanation

The ransom note creation events all point to the same process ID, so `5348` is the process behind that activity.

## Question 3

### Objective

Locate the ransomware executable on disk.

### Query

```spl
index=revil event.code=1
| search winlog.event_data.Image="*\\Downloads\\*"
| table time winlog.event_data.ParentImage winlog.event_data.Image winlog.event_data.ProcessId
```

### Evidence

![Question 3 search](REvil/images/q3-executable-path-search.png)

### Answer

`C:\Users\Administrator\Downloads\facebook assistant.exe`

### Explanation

The `Image` field shows the suspicious executable launched from the `Downloads` folder.

## Question 4

### Objective

Identify the command used to disrupt recovery.

### Query

```spl
index=revil event.code=1
| search winlog.event_data.CommandLine="*-e*"
| table time winlog.event_data.ParentImage winlog.event_data.Image winlog.event_data.ProcessId winlog.event_data.ParentCommandLine winlog.event_data.CommandLine
```

### Evidence

![Question 4 search](REvil/images/q4-encoded-command-search.png)

![Question 4 decode](REvil/images/q4-cyberchef-decode.png)

### Answer

```powershell
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```

### Explanation

The ransomware used an encoded PowerShell command to delete Volume Shadow Copies and make recovery harder.

## Question 5

### Objective

Extract the SHA256 hash of the ransomware executable.

### Query

```spl
index=revil event.code=1 "facebook assistant.exe"
| table _time winlog.event_data.Hashes
| dedup winlog.event_data.Hashes
```

### Evidence

![Question 5 hash search](REvil/images/q5-hash-search.png)

![Question 5 VirusTotal check](REvil/images/q5-virustotal-check.png)

### Answer

`b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa`

### Explanation

This hash matches the ransomware sample and can be validated in VirusTotal for known detections.

## Question 6

### Objective

Identify the ransomware author's onion domain.

### Method

Check sandbox or threat intelligence results and review DNS activity for suspicious `.onion` domains.

### Evidence

![Question 6 ANY.RUN DNS activity](REvil/images/q6-onion-domain-anyrun.png)

### Answer

`aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketr56nf6aq2nmyoyd.onion`

### Explanation

The DNS results show a Tor hidden service domain, which is likely part of the ransomware operator's infrastructure.

## Final Answers

| Question | Answer |
| --- | --- |
| Ransom note filename | `5uizv5660t-readme.txt` |
| Process ID | `5348` |
| Executable path | `C:\Users\Administrator\Downloads\facebook assistant.exe` |
| Recovery disruption command | `Get-WmiObject Win32_Shadowcopy \| ForEach-Object {$_.Delete();}` |
| SHA256 hash | `b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa` |
| Onion domain | `aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketr56nf6aq2nmyoyd.onion` |
