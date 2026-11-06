## Purpose

This repository serves as a centralized, version-controlled collection of PowerShell scripts I create for application packaging, software deployment, and administrative tasks. Storing these scripts in GitHub allows me to document their purpose, track changes, reuse tested solutions, and maintain a reliable history as they are improved.

## ScreenConnect investigation collector

[`Collect-ScreenConnectInvestigation.ps1`](Collect-ScreenConnectInvestigation.ps1) collects existing Windows event logs and local system inventories to support investigation of an unexpected ScreenConnect installation or remote-access alert.

The collector runs locally and works without internet access. It exports evidence into a new directory and reports collection results. It does not remove software, stop processes or services, change auditing settings, clear event logs, reboot the computer, or upload files. Running the collector itself can create process and event-log records, so record when collection begins.

### Requirements

- Windows with Windows PowerShell 5.1 or a later supported PowerShell version.
- An elevated PowerShell session using an approved incident-response or local administrative account.
- Sufficient free space for the retained event logs and inventories.
- A local output destination. Network shares and mapped network drives are not supported.

No additional PowerShell modules or downloads are required on the computer being examined. Follow your organization's script-signing and execution-policy requirements; the collector does not change execution policy.

### Run

Download the script to an approved location before collection. On the computer being investigated, open **Windows PowerShell as administrator**, change to that location, and run:

```powershell
.\Collect-ScreenConnectInvestigation.ps1
```

To use a different local parent folder:

```powershell
.\Collect-ScreenConnectInvestigation.ps1 -OutputRoot 'D:\IncidentEvidence'
```

Keep the affected computer isolated through your established incident-response process. This script does not provide network isolation.

### Output location

By default, each collection is written beneath `%ProgramData%`, normally `C:\ProgramData`, into a unique folder whose name begins with the computer name and collection timestamp:

```text
C:\ProgramData\IR-COMPUTERNAME-yyyyMMdd-HHmmss...
```

The exact folder is printed at completion. Existing collections are not overwritten. The new evidence folder is restricted to SYSTEM and local Administrators; collection stops if those permissions cannot be applied.

### What is collected

| Evidence | Contents |
| --- | --- |
| Core EVTX exports | `System.evtx`, `Security.evtx`, `Application.evtx`, and `PowerShell.evtx`. The full retained logs are exported without a date or event-ID filter. |
| Additional EVTX exports, where available | The classic Windows PowerShell log, plus Defender, Task Scheduler, WMI Activity, Sysmon, and PowerShell Core operational logs. Missing or disabled channels are reported. The script does not enable channels. |
| Service and process inventories | Local snapshots, including available executable paths, command lines, service accounts, and process identifiers. |
| ScreenConnect-related inventory matches | Entries whose recorded names, paths, or command lines match ScreenConnect or ConnectWise. These are leads for review, not a malicious-software classification. |
| TCP connection snapshot | Current local/remote addresses, ports, states, and owning process IDs. Connections may already have ended after isolation. |
| Collection metadata and status | Collection times, host context, timezone, individual collection results, and any errors. |
| SHA-256 manifest | Hashes and sizes of finalized output files, excluding the manifest itself. |

Review `Collection-Status.csv` and `SHA256-Manifest.csv` even when some files were created successfully. `Collection-Metadata.json` identifies the host and collection context. A missing channel, export failure, or unavailable field is an evidence gap. The metadata's required-collection result does not account for optional failures or hash failures; inspect both reports. Partial collection is not equivalent to a complete collection.

### Investigate the exported logs

Use **Event Viewer > Action > Open Saved Log** to open an `.evtx` file. Include Information events; installation and remote-access activity may not appear as warnings or errors.

| Log | Starting point |
| --- | --- |
| System | Service Control Manager event **7045**: correlate service installation time, exact instance name, path, startup type, and service account. |
| Application | Filter by the **ScreenConnect** or **ScreenConnect Client (identifier)** source first. Look for operator-connected/disconnected messages, remote command activity, and file transfers. Event IDs vary by client version. |
| Application | **MsiInstaller 11707 / 1033**: installation success or completion details; inspect the product and status. |
| Security | **4688** for process creation; **4697** for service installation; **4698 / 4702** for scheduled tasks; **4720 / 4732** for account/group changes; **1102** for Security log clearing. Availability depends on auditing and retention. |
| PowerShell Operational | **4103 / 4104** for available module and script-block records. Logging enabled after an incident cannot recreate earlier activity. |
| Defender Operational | **1116 / 1117** for detections and recorded actions; **5001 / 5007** for protection/configuration changes. Read the actual action/result and compare with approved changes. |

Build a timeline across the logs and your EDR, identity, email, and network records. Record the full provider, event ID, timestamp, record ID, instance, path, and relevant event data. If event descriptions cannot be rendered on the reviewing computer, preserve the EVTX and inspect **Details > XML View**.

### Interpretation and evidence handling

- The inventory is a snapshot taken during collection. Zero matching processes or services does not establish that the client never ran or that the computer is clean.
- A ScreenConnect installation, a connection to its relay server, and an operator joining a session are different findings. An instance may belong to an approved support provider; validate its identity and context.
- Event logs are not a complete forensic acquisition. They may be missing, overwritten, incomplete, or altered. Local ScreenConnect logs may not account for every file viewed or transferred.
- An SHA-256 manifest helps detect later changes to the collected files. It does not prove that the source system or logs were trustworthy before collection.
- EVTX files and process command lines may contain usernames, internal addresses, tokens, or other confidential information. Keep the collection in controlled evidence storage. Publish source code and documentation only; do not commit collected evidence to this repository.

The repository ignore rules cover default `IR-*` output folders and EVTX files. They are an additional precaution, not an access control for evidence stored elsewhere.

### Validation status

The collector is intended for Windows PowerShell 5.1 compatibility. Source review and a third-party PowerShell grammar check were performed before publication. A Windows/PowerShell runtime was unavailable during this review, so Windows execution and EVTX readability have not been validated. Run a supervised collection on an approved Windows test machine before operational deployment; this version has not been executed against the affected machines.

### References

- [Microsoft: wevtutil export and archive commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [Microsoft: Get-CimInstance](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-5.1)
- [Microsoft: Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1)
- [Microsoft: process creation event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Microsoft: Windows Installer event logging](https://learn.microsoft.com/en-us/windows/win32/msi/event-logging)
- [Microsoft: Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [ScreenConnect client-side evidence: original lab research](https://dfirtnt.wordpress.com/2023/07/14/rmm-screenconnect-client-side-evidence/)
