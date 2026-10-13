# Detections

Detection rules mapped to [MITRE ATT&CK](https://attack.mitre.org/), organized by tactic and technique.

Each technique folder holds the Sigma rule (`.yml`), the Splunk query (`.spl`), and a README explaining the detection.

## Rules

| Rule | ATT&CK | Log source | Level |
|---|---|---|---|
| [PowerShell Download Cradle](execution/T1059.001-powershell/) | T1059.001, T1105 | Sysmon EID 1 | High |
