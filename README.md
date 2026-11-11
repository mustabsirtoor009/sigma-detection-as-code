# sigma-detection-as-code

Detection rules written in the Sigma format, mapped to MITRE ATT&CK, and validated by a GitHub Actions pipeline on every push.

## How it works

1. Each detection is a Sigma rule (a YAML file) under `rules/`.
2. The pipeline runs `sigma check` to validate every rule. A broken rule fails the build.
3. The pipeline converts every rule to Splunk queries, which proves the rules can be deployed to a real SIEM.

## Detection coverage

| Rule | ATT&CK technique | Tactic | Level |
|---|---|---|---|
| PowerShell Encoded Command Execution | T1059.001 PowerShell | Execution | Medium |
| Scheduled Task Created With User-Writable Path | T1053.005 Scheduled Task | Persistence | Medium |
| Windows Security Event Log Cleared | T1070.001 Clear Windows Event Logs | Defense Evasion | High |

## Repository layout 


## Limitations

- The rules are written for Windows logs and have not been tested against live log data yet.
- Rule thresholds and false-positive notes come from the rule logic, not from a production environment.
