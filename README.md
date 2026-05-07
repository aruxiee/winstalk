
# 🕵️‍♂️ winstalk: Manual Windows Enumeration

Just a simple post-exploitation recon script I wrote for Windows. Dumps high-risk indicators and a massive data footprint for manual forensics.

⚠️ **Please Note:** This project is strictly for **Educational and Authorized Penetration Testing**. I am not responsible for any of the shenanigans you guys pull.

---

## 📦 What It Fetches
The script performs a deep-dive audit across many domains.

*   **Triage (High-Priority Red Flags)**
    *   Scans for processes executing from world-writable locations like `\Temp`, `\Public`, or `\AppData`.
    *   Identifies **Unquoted Service Paths** which are prime targets for privesc.
*   **Process-to-Network Mapping**
    *   Correlates every active network socket (TCP/UDP) to the specific PID and the User account running it.
*   **Registry Recursion**
    *   Crawls critical persistence hives like `Run` keys and `Winlogon`, plus the massive `Services` configuration tree to depth of 3 levels.
*   **Module Inventory**
    *   Dumps a full map of every DLL and executable module currently loaded into memory for every running process.

---

## 🚀 Use Cases
`winstalk` can be used for identifying both misconfigurations and active compromise.

- **Connecting Dots:** You can distinguish between a legitimate browser connection and a LotL binary (like `cmd.exe`) communicating with an external IP by mapping network connections to processes.
- **Vulnerability Discovery:** The unquoted service path check identifies low-hanging fruits for privesc that standard automated tools might overlook in a noisy environment.
- **Forensic Artifacts:** The deep registry and module dumps allow researchers to see if libraries are being injected or if persistence mechanisms have been modified.

---

## 🛠 Leverage

### For Pentesters
*   **Privilege Escalation:** If `run_triage` flags a service with an unquoted path, a pentester can place a malicious binary in the intercepting path to gain SYSTEM privileges.
*   **Egress Discovery:** Use the network map to find which processes are allowed to bypass firewall rules to communicate externally.

### For Malware Analysts
*   **DLL Injection Detection:** Can spot non-standard DLLs loaded into core system processes (e.g. a suspicious DLL inside `lsass.exe`) by reviewing the module inventory.
*   **Persistence Analysis:** The recursive registry crawl allows to see exactly how a piece of malware has registered itself as a service or a driver.

---

## 🗺 MITRE

| Technique ID | Name | Description |
| :--- | :--- | :--- |
| **T1057** | Process Discovery | Enumerating all running processes and their owners. |
| **T1012** | Query Registry | Diving into registry keys for configuration and persistence. |
| **T1574.009** | Path Interception | Detecting Unquoted Service Paths. |
| **T1046** | Network Service Discovery | Mapping active connections and listening ports. |
| **T1124** | System Time Discovery | Establishing a timeline of system activity via the audit log. |

---

<p align="center">
  With ❤️ by <b>Aradhya</b>
</p>
