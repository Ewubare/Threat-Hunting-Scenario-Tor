
# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Ewubare/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Technology Used
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

The DeviceFileEvents table was searched for any file containing the string "tor" to identify installation artefacts and related files. This initial query successfully detected the incident beginning at 3:44:45 PM on July 5, 2025, revealing Tor browser components and a suspicious file named "tor-shopping-list.txt" on device "thl-machine".

**Query used:**

```kql

DeviceFileEvents
| where FileName contains "tor"
| project Timestamp, DeviceName, FileName, ActionType

```
<img width="1212" alt="image" src="https://github.com/Ewubare/Threat-Hunting-Scenario-Tor/blob/main/images/1.png">

---

### 2. Searched the `DeviceProcessEvents` Table

The DeviceProcessEvents table was then searched to identify if the Tor program had been installed. This then revealed evidence of a deliberate stealth installation of Tor using a silent installation command.

**Query used:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine, SHA256

```
<img width="1212" alt="image" src="https://github.com/Ewubare/Threat-Hunting-Scenario-Tor/blob/main/images/2.png">
---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

A search of DeviceProcessEvents was conducted to confirm active execution of the core Tor program after it was installed.

**Query used to locate events:**

```kql

DeviceProcessEvents  
| where FileName == "tor.exe"
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine, SHA256

```
<img width="1212" alt="image" src="https://github.com/Ewubare/Threat-Hunting-Scenario-Tor/blob/main/images/3.png">
---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Finally the DeviceNetworkEvents table was analyzed to detect Tor network connections from known Tor ports and confirm operational usage. Successful Tor network establishment was confirmed at 3:48:49 PM, with connections to the entry node `165.49.20.10:9001` and local proxy usage on `127.0.0.1:9150`, indicating Tor was actively browsed on the network.

**Query used:**

```kql

DeviceNetworkEvents
| where RemotePort in ("9001","9030","9040","9050","9051","9150")
| project Timestamp,DeviceName,ActionType,RemoteIP,RemotePort,RemoteUrl,InitiatingProcessFileName

```
<img width="1212" alt="image" src="https://github.com/Ewubare/Threat-Hunting-Scenario-Tor/blob/main/images/4.png">
---

## Chronological Event Timeline

### 1. File Activity - File Rename

- **Timestamp:** `2025-07-05T15:44:45Z`
- **Event:** The user "subcontractor" renamed the TOR browser installer file `tor-browser-windows-x86_64-portable-14.5.4.exe` in the Downloads folder.
- **Action:** File rename detected.
- **File Path:** `C:\Users\subcontractor\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`
- **Significance:** Initial file preparation for TOR browser installation.

### 2. Process Execution - TOR Browser Installer Launch

- **Timestamp:** `2025-07-05T15:44:58Z`
- **Event:** The user "subcontractor" executed the TOR browser installer.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe`
- **File Path:** `C:\Users\subcontractor\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`
- **SHA256:** `5035adc961d7ebae32a175061d102686c00728c750824b3099601259cead8866`
- **Significance:** First execution of TOR browser installer.

### 3. File Deletion - Installer Cleanup

- **Timestamp:** `2025-07-05T15:44:58Z`
- **Event:** The user "subcontractor" deleted the TOR installer file after extraction.
- **Action:** File deletion detected (2 occurrences).
- **File Path:** `C:\Users\subcontractor\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`
- **Significance:** Cleanup of installation files after extraction.

### 4. Process Execution - Silent Installation

- **Timestamp:** `2025-07-05T15:48:11Z`
- **Event:** The user "subcontractor" initiated a silent installation of the TOR browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- **SHA256:** `5035adc961d7ebae32a175061d102686c00728c750824b3099601259cead8866`
- **File Path:** `C:\Users\subcontractor\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`
- **Significance:** Silent installation indicates an intent to avoid detection.

### 5. File Creation - TOR License Files

- **Timestamp:** `2025-07-05T15:48:28Z`
- **Event:** TOR browser files were created during installation.
- **Action:** File creation detected.
- **Files Created:**
  - `Torbutton.txt`
  - `Tor-Launcher.txt`
  - `tor.txt`
- **File Path:** `C:\Users\subcontractor\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\`
- **Significance:** License documentation files.

### 6. File Creation - TOR Executable

- **Timestamp:** `2025-07-05T15:48:29Z`
- **Event:** Core TOR executable installed.
- **Action:** File creation detected.
- **File Path:** `C:\Users\subcontractor\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **Significance:** TOR executable ready for use.

### 7. Network Connection - TOR Entry Node

- **Timestamp:** `2025-07-05T15:48:49Z`
- **Event:** Connection established to TOR entry node.
- **Action:** Connection success detected.
- **Process:** `tor.exe`
- **Remote IP:** `65.49.20.10`
- **Remote Port:** `9001`
- **Remote URL:** `https://www.wqyoufhlhiqh.com`
- **File Path:** `C:\Users\subcontractor\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **Significance:** Successful connection to TOR network.

### 8. File Creation - Web Application Storage

- **Timestamp:** `2025-07-05T15:53:01Z`
- **Event:** Web application storage database created.
- **Action:** File creation detected.
- **File Path:** `C:\Users\subcontractor\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\webappsstore.sqlite`
- **Significance:** Indicates active web browsing.

### 9. Connection Failure - Firefox to TOR Proxy

- **Timestamp:** `2025-07-05T15:56:43Z`
- **Event:** Firefox lost connection to TOR proxy.
- **Action:** Connection failure detected.
- **Process:** `firefox.exe`
- **Remote IP:** `127.0.0.1`
- **Remote Port:** `9150`
- **Significance:** TOR session likely terminated.

### 10. File Creation - Form History Database

- **Timestamp:** `2025-07-05T16:13:11Z`
- **Event:** Form history database created.
- **Action:** File creation detected.
- **File Path:** `C:\Users\subcontractor\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\formhistory.sqlite`
- **Significance:** Evidence of active form usage and browsing.

### 11. File Creation - Suspicious Document

- **Timestamp:** `2025-07-05T16:17:04Z`
- **Event:** Suspicious document and recent file shortcut created.
- **Action:** File creation detected.
- **Files:**
  - `C:\Users\subcontractor\Documents\tor-shopping-list.txt`
  - `C:\Users\subcontractor\AppData\Roaming\Microsoft\Windows\Recent\tor-shopping-list.lnk`
- **Significance:** Potential planning for illicit marketplace activity.


---

## Summary

An unauthorized TOR browser installation and usage incident was identified on workstation "thl-machine" on July 5, 2025. The user performed a stealth installation and successfully established TOR network connections. There was also the creation of a file that indicated that the employee might have intened to shop using the Tor browser. The activity demonstrates a clear intent to bypass corporate security restrictions and may pose significant operational and data security risks.

---

## Response Taken

TOR usage was confirmed on the endpoint `thl-machine` by the user `subcontractor`. The device was isolated, and the user's direct manager was notified.

---
