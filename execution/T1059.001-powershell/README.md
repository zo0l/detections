# PowerShell Download Cradle

| | |
|---|---|
| **Tactics** | Execution ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)) · Command and Control ([T1105](https://attack.mitre.org/techniques/T1105/)) |
| **Log source** | Sysmon Event ID 1 (Process Creation) |
| **Type** | Behavioral |
| **Confidence** | High |
| **Rules** | [Sigma](powershell-download-cradle.yml) · [Splunk SPL](powershell-download-cradle.spl) |

## Why it's suspicious

PowerShell downloads code from the internet and executes it directly in memory. Nothing is written to disk, which makes this a classic attacker technique for avoiding file-based detection and leaving fewer forensic artifacts.

## Logic

The rule fires when a single process matches all three conditions:

1. **Process** is `powershell.exe` or `pwsh.exe`
2. **Download** - the command line contains `DownloadString`, `DownloadFile`, `Net.WebClient`, or `Invoke-WebRequest`
3. **Execution** - the command line contains `IEX` or `Invoke-Expression`

## False positives

- Software installers that use this pattern (e.g. the Chocolatey install script)
