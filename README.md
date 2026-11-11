# sigma-detection-as-code

Detection rules written in the Sigma format, mapped to MITRE ATT&CK v19, and validated by a GitHub Actions pipeline on every push.

## How it works

1. Each detection is a Sigma rule (a YAML file) under `rules/`.
2. The pipeline runs `sigma check` and fails the build on any error or issue, including invalid MITRE ATT&CK tags.
3. The pipeline converts every rule to Splunk queries, which proves the rules can be deployed to a real SIEM.

## Detection coverage

| Rule | ATT&CK technique | Tactic | Level |
|---|---|---|---|
| PowerShell Encoded Command Execution | T1059.001 PowerShell | Execution | Medium |
| Scheduled Task Created With User-Writable Path | T1053.005 Scheduled Task | Persistence | Medium |
| Windows Security Event Log Cleared | T1685.005 Clear Windows Event Logs (formerly T1070.001) | Defense Impairment | High |

## What the quality gate caught 

<img width="732" height="662" alt="Red" src="https://github.com/user-attachments/assets/8266eb76-5480-491b-a9ea-3b6ea74ce87d" /> 


<img width="742" height="678" alt="Green" src="https://github.com/user-attachments/assets/a812f459-bf8a-4850-8e57-7e5f24a6758e" />



My first version of the log-clearing rule used the pre-v19 ATT&CK tags (`attack.defense-evasion` and `attack.t1070.001`). MITRE ATT&CK v19 retired the Defense Evasion tactic, split it into Stealth and Defense Impairment, and moved Clear Windows Event Logs to T1685.005. The validator flagged both tags, the strict gate failed the build, and the build passed once I updated the rule.

## Limitations

- The rules are written for Windows logs and have not been tested against live log data yet.
- False-positive notes come from the rule logic, not from a production environment.
