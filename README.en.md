# OmniEye — Zero-Trust Anti-Exfiltration & Endpoint Protection System

<p align="center">
  <b>Language:</b> 
  <a href="README.md">🇷🇺 Русский</a> • 
  <b>🇬🇧 English</b> • 
  <a href="README.uk.md">🇺🇦 Українська</a> • 
  <a href="README.de.md">🇩🇪 Deutsch</a> • 
  <a href="README.ja.md">🇯🇵 日本語</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-10.0%20(LTS)-512BD4?style=for-the-badge&logo=dotnet&logoColor=white" alt=".NET 10" />
  <img src="https://img.shields.io/badge/C%23-13.0-239120?style=for-the-badge&logo=csharp&logoColor=white" alt="C# 13" />
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20x64-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/UI-Windows%2011%20Fluent%20(WPF--UI)-005FB8?style=for-the-badge&logo=fluentui&logoColor=white" alt="Fluent Design" />
  <img src="https://img.shields.io/badge/Crypto-AES--256%20SQLCipher%20%2B%20DPAPI-4E73DF?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLCipher" />
  <img src="https://img.shields.io/badge/Security-Zero--Trust%20NDIS%20Enforcement-D9534F?style=for-the-badge&logo=shield&logoColor=white" alt="Zero-Trust" />
</p>

**OmniEye** is a high-performance endpoint protection and anti-data exfiltration system engineered on the **Zero-Trust** security architecture for modern Microsoft Windows environments.

The system enforces the fundamental principle of **«Never Trust, Always Verify»** across both network and memory execution layers: all outbound network communication is blocked by default at the NDIS kernel stack, while trusted application memory is guarded via real-time kernel Event Tracing for Windows (ETW) with instant threat suspension using native `ntdll.dll` system routines.

---

## 📑 Table of Contents

- [1. Threat Model & Philosophy](#1-threat-model--philosophy)
- [2. System Architecture](#2-system-architecture)
- [3. Core Subsystems](#3-core-subsystems)
  - [3.1. Network Enforcer & Dynamic Policy Switching](#31-network-enforcer--dynamic-policy-switching)
  - [3.2. Anti-Injection Kernel Monitor (Freeze & Prompt)](#32-anti-injection-kernel-monitor-freeze--prompt)
  - [3.3. Multi-Component Companion Discovery](#33-multi-component-companion-discovery)
  - [3.4. Hardware-Bound Cryptography & Database Hardening](#34-hardware-bound-cryptography--database-hardening)
  - [3.5. Authenticode Code Signature Verifier](#35-authenticode-code-signature-verifier)
  - [3.6. Windows 11 Native Fluent UI & PerMonitorV2 High DPI](#36-windows-11-native-fluent-ui--permonitorv2-high-dpi)
  - [3.7. Native Zapret DPI Circumvention Engine](#37-native-zapret-dpi-circumvention-engine)
  - [3.8. System DNS & Windows 11 Native DoH Integration](#38-system-dns--windows-11-native-doh-integration)
  - [3.9. Live Network Socket Monitor](#39-live-network-socket-monitor)
- [4. Inter-Process Communication (IPC) Protocol](#4-inter-process-communication-ipc-protocol)
- [5. Operating Modes (Developer Mode vs Strict Zero-Trust)](#5-operating-modes-developer-mode-vs-strict-zero-trust)
- [6. Quick Start & Build Guide](#6-quick-start--build-guide)
- [7. Windows Service Deployment](#7-windows-service-deployment)
- [8. Automated Verification Suite](#8-automated-verification-suite)
- [9. Frequently Asked Questions (FAQ)](#9-frequently-asked-questions-faq)

---

## 1. Threat Model & Philosophy

Conventional endpoint security products (EDR/EPP) rely heavily on known signature databases, post-exploitation heuristics, and behavioral telemetry. Modern adversary tooling (info-stealers, spyware, backdoors, RATs, and C2 agents such as Cobalt Strike, Sliver, or Havoc):
1. **Evade userland inspection:** inject shellcode into legitimate processes (Process Hollowing, DLL Sideloading, Thread Hijacking, APC Injection).
2. **Exfiltrate secrets instantaneously:** siphon session tokens, browser databases, password manager caches, and SSH/GPG private keys via standard outbound HTTPS/TLS channels (ports 443/80/8080).

### The OmniEye Approach:
* **Default Deny Outbound:** Out-of-the-box, no process running on the host has authorization to initiate outbound TCP/UDP handshakes. The firewall outbound policy is clamped to `BLOCK`.
* **Authenticode Whitelisting:** Outbound network privileges are granted exclusively to validated, cryptographically signed binaries recorded in an encrypted database.
* **Kernel Freeze & Prompt:** When unapproved cross-process memory manipulation is detected by kernel ETW, OmniEye immediately suspends all threads of the offending process, preventing payload detonation and data exfiltration.
* **Native DPI Circumvention & DoH:** Fully decoupled native `OmniEye.DpiBypass` module provides packet desynchronization (Discord voice, YouTube) and encrypted DNS without compromising core zero-trust security.

---

## 2. System Architecture

The solution is divided into 5 modular projects under a unified .NET 10 solution (`OmniEye.slnx`):

```
OmniEye/
├── OmniEye.slnx                        # Solution configuration file (.NET CLI)
├── OmniEye.Core/                      # Pure core: shared cryptography, security, and IPC contracts
│   ├── Configuration/                 # Configuration models (OmniEyeConfig)
│   ├── Models/                        # DTO IPC message contracts and database entities
│   ├── Security/                      # WinVerifyTrust, DPAPI, NtDll P/Invoke, NTFS ACL
│   ├── Storage/                       # SQLite + SQLCipher AES-256 with settings persistence
│   └── Ipc/                           # Asynchronous Named Pipe client (IpcClient)
├── OmniEye.DpiBypass/                 # Isolated native packet desynchronization & DNS module
│   ├── Zapret/                        # Native Zapret Engine (winws.exe, WinDivert, 22 presets, Discord UDP)
│   ├── Dns/                           # SystemDnsManager (adapter config, Win11 DoH, Safe Rollback)
│   ├── Models/                        # DoH server models and configuration
│   ├── Proxy/                         # Local HTTP CONNECT DPI proxy
│   └── Tls/                           # TLS ClientHello SNI parser & fragmentation offset math
├── OmniEyeSvc/                        # Elevated Windows Background Service (NT AUTHORITY\SYSTEM)
│   ├── Network/                       # COM INetFwPolicy2, rule orchestration, Self-Healing Watchdog
│   ├── Monitor/                       # Microsoft ETW Kernel Process/Thread/Image TraceEvent
│   ├── Ipc/                           # Multi-client Named Pipe Server with PipeSecurity ACL
│   ├── appsettings.json               # Service configuration parameters
│   ├── Worker.cs                      # Microsoft.Extensions.Hosting background worker
│   └── Program.cs                     # Windows Service / Console host entrypoint
├── OmniEyeTray/                       # Windows 11 Fluent Design System Tray GUI
│   ├── Views/                         # UI views (MainWindow, Dialogs, Subpages)
│   ├── Services/                      # LocalizationManager (5 languages), NetworkMonitorService
│   ├── Localization/                  # Dictionaries (en-US, ru-RU, uk-UA, de-DE, ja-JP)
│   ├── App.xaml                       # WPF-UI theme bootstrap & PerMonitorV2 initialization
│   ├── app.manifest                   # Manifest declaring PerMonitorV2 DPI awareness
│   └── MainWindow.xaml.cs             # Tray logic, live filtering, and presets controller
└── OmniEye.Tests/                     # Comprehensive autonomous verification suite
    └── Program.cs                     # 14 integration tests validating all layers
```

### Component Interaction Architecture:

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Windows 11 Fluent GUI (OmniEyeTray)               │
 │       [Dashboard]       [Firewall]     [Kernel Guard]    [Settings]    │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ JSON RPC over Named Pipe
                                     │ \\.\pipe\OmniEyePipe (ACL Secured)
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   Background Service (OmniEyeSvc) [SYSTEM]             │
 │                                                                        │
 │  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────┐ │
 │  │    FirewallEnforcer   │  │ AntiInjectionMonitor  │  │  IpcServer  │ │
 │  │   COM INetFwPolicy2   │  │   ETW Kernel Provider │  │ PipeSecurity│ │
 │  │ Self-Healing Watchdog │  │ NtSuspend / NtResume  │  │ Multi-client│ │
 │  └───────────┬───────────┘  └───────────┬───────────┘  └──────┬──────┘ │
 └──────────────┼──────────────────────────┼─────────────────────┼────────┘
                │                          │                     │
 ┌──────────────▼──────────┐   ┌───────────▼───────────┐         │
 │ Windows Defender        │   │ Windows Kernel ETW    │         │
 │ Firewall (NDIS Filter)  │   │ Process/Thread Events │         │
 └─────────────────────────┘   └───────────────────────┘         │
                                                                 ▼
                                                ┌─────────────────────────┐
                                                │ AES-256 SQLCipher DB    │
                                                │ Windows DPAPI Machine   │
                                                │ Exclusive File Lock     │
                                                └─────────────────────────┘
```

---

## 3. Core Subsystems

### 3.1. Network Enforcer & Dynamic Policy Switching

The Network Enforcer interacts directly with Windows Defender Firewall using the COM interface `INetFwPolicy2` (`HNetCfg.FwPolicy2` / `HNetCfg.FWRule`):
* **Profile Synchronization:** Changes apply uniformly to all three Windows firewall profiles: `Domain`, `Private`, and `Public`.
* **Dynamic Policy Switching:** On the **"Сетевой экран" (Firewall)** page, users can toggle the default outbound action with instant feedback:
  - **`BLOCKED (Zero-Trust BLOCK)`** — Inbound and outbound connections are blocked by default. Only Whitelist entries and system essentials communicate.
  - **`ALLOWED (Permissive ALLOW)`** — Standard permissive networking mode. Outbound connections are allowed by default for all software.
* **System Essentials (Critical Infrastructure Exceptions):**
  - **DNS:** UDP and TCP port 53 Outbound (`OmniEye-System-DNS-UDP`, `OmniEye-System-DNS-TCP`).
  - **DHCP:** UDP ports 67, 68 Outbound (`OmniEye-System-DHCP`).
  - **Windows Update:** Service rule targeting `wuauserv` (`OmniEye-System-WindowsUpdate`).
* **Self-Healing Watchdog:** A background watchdog checks the integrity of `DefaultOutboundAction` every 3000 ms. If malware or a third-party application attempts to revert the firewall or delete `OmniEye-*` rules, the watchdog immediately re-enforces them. When the user selects `ALLOW`, the watchdog gracefully pauses to respect user intent.

### 3.2. Anti-Injection Kernel Monitor (Freeze & Prompt)

To safeguard processes against unauthorized memory tampering (DLL Injection, APC Injection, Process Doppelgänging), OmniEye subscribes to the kernel ETW trace provider `Microsoft-Windows-Kernel-Process`:
1. **Interception:** Kernel events for thread creation, image loading, and cross-process access are monitored in real-time.
2. **Detection:** When a process attempts to tamper with a whitelisted application's memory space, OmniEye triggers the **Freeze & Prompt** routine.
3. **Thread Suspension:** Using the native kernel routine `NtSuspendProcess` (`ntdll.dll`), all execution threads of the malicious caller are instantaneously suspended.
4. **Alert Dialog (`PromptDialog`):** A topmost emergency window appears in the user session showing the caller path, target path, process IDs, and a 60-second countdown.
5. **Deterministic Action:**
   - If the user selects **[Kill Process]** or the 60-second safety timer expires, the caller is terminated via `NtTerminateProcess`.
   - If the user selects **[Ignore]**, threads resume execution via `NtResumeProcess`.

### 3.3. Multi-Component Companion Discovery

Complex applications (AmneziaVPN, Discord, Chrome, Telegram, IDEs) rely on distributed companion binaries: the primary GUI, a background Windows Service, low-level network tunnels (`tun2socks`, `wireguard`, `openvpn`), helper executables, and updaters (`Update.exe`).

When a user selects a primary executable, OmniEye:
* Recursively crawls the application directory, standard subfolders (`bin`, `tap`, `helper`, `proxy`), and Squirrel parent directories.
* Categorizes binaries by role ("Network Tunnel / VPN", "Background Service", "Update Utility", "Uninstaller").
* Displays the **`CompanionDiscoveryDialog`**, allowing the user to whitelist the entire software suite in a single operation.
* Organizes companion binaries into an expandable Windows 11 `SettingsExpander` card with batch deletion capability.

### 3.4. Hardware-Bound Cryptography & Database Hardening

* **Transparent On-the-Fly Encryption:** The database (`C:\ProgramData\OmniEye\config.db`) is encrypted using **SQLCipher AES-256-CBC** (`SQLitePCLRaw.bundle_e_sqlcipher`). Even the SQLite header bytes (`SQLite format 3`) are fully scrambled.
* **Hardware DPAPI Binding:** The 256-bit database master key is generated by a cryptographic RNG and wrapped using **Windows DPAPI** (`DataProtectionScope.LocalMachine`), binding it to the physical host TPM and machine identity.
* **NTFS ACL Hardening:** Access permissions on `C:\ProgramData\OmniEye` are enforced via security descriptors: `SYSTEM` and `Administrators` have `FullControl`, standard users have read-only access.
* **Exclusive File Lock:** The service maintains an open handle with `FileShare.None` and sets `PRAGMA locking_mode = EXCLUSIVE` to block offline tampering while the engine is running.

### 3.5. Authenticode Code Signature Verifier

Whitelisting binaries requires cryptographic origin verification:
* Verification is performed via the native Win32 API `WinVerifyTrust` (`wintrust.dll`) with action GUID `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
* The engine evaluates both embedded Authenticode signatures and Windows Security Catalog (`.cat`) signatures.
* Signer subject metadata (CN, Organization, Country) is extracted and recorded.
* In production mode (`DeveloperMode = false`), unsigned or tampered binaries are **strictly rejected**.

### 3.6. Windows 11 Native Fluent UI & PerMonitorV2 High DPI

The [OmniEyeTray](file:///d:/SPA_Full/OmniEye/OmniEyeTray) user interface strictly implements the [Microsoft Windows App Design Guidelines](https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview):
* **Mica Backdrop:** Native translucent Mica material applied via DWM API (`DwmSetWindowAttribute`, `DWMSBT_MAINWINDOW`).
* **TitleBar with Snap Layouts:** Native Windows 11 title bar displaying interactive Snap Layout grids when hovering over the maximize button.
* **Subpixel Anti-Aliasing:** Configured with `ClearType`, subpixel text formatting, and `UseLayoutRounding="True"`, eliminating text jitter and rendering artifacts on dark surfaces.
* **PerMonitorV2 High DPI Awareness:** With declarative application manifests and `SetProcessDpiAwarenessContext` initialization, moving the window between 1080p (100% scaling) and 4K (150%–200% scaling) displays maintains razor-sharp vector rendering with zero bitmap blur.
* **Windows 11 Settings Cards:** Subtle dividers, consistent corner radiuses (`CornerRadius="8"`), smooth mouseover states, and custom dark scrollbars.

### 3.7. Native Zapret DPI Circumvention Engine

To guarantee continuous availability of essential network communications (including Discord voice and YouTube) in heavily inspected network environments, the decoupled `OmniEye.DpiBypass` module is natively embedded:
* **Kernel-Level Packet Interception:** Uses native `WinDivert64.sys` driver and the `winws.exe` engine operating at L3/L4.
* **Discord WebRTC Voice Channel Desynchronization:** Specialized UDP filtering and payload substitution (`--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=ACTIVE_DISCORD_UDP.bin`), restoring voice connection stability.
* **HTTPS / TLS ClientHello Desynchronization:** Sequence overlap and packet multisplit targeted against `list-general.txt` and `list-google.txt`.
* **22 Flowseal Presets:** Interactive preset dropdown in the GUI (`General`, `ALT1-13`, `SIMPLE FAKE`, `FAKE TLS AUTO`, `EXP`) enabling instant strategy switching tailored to any ISP.
* **Resilient Lifecycle via Windows JobObject:** Process `winws.exe` is bound to a Win32 Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The packet engine and driver are instantly cleaned up on tray application termination or crash.

### 3.8. Custom Domain Lists Editor

An interactive Domain Lists Editor directly within the DPI Bypass page gives users full control over hostlist desynchronization rules:
* **Hostlist Management Without File Editing:** Seamlessly switch between `list-general.txt` (General), `list-google.txt` (YouTube & Google services), and `list-exclude.txt` (Exclusions) via segmented tabs.
* **Dual View Modes (Items vs Notepad):**
  * **Items Mode:** Visual interactive cards with single-click removal buttons (`✕`), fast addition bar, and substring search filter.
  * **Notepad Mode:** An embedded dark monospace text editor (Consolas, full scrollbars) designed for bulk copying/pasting of dozens/hundreds of domains, with comment support (`#`, `;`) and custom list editing.
* **External Windows Notepad Integration:** A dedicated "In Windows Notepad" button opens the selected list file directly in native `notepad.exe` with automatic synchronization upon saving.
* **Intelligent Domain Sanitization & Validation:** Strips protocols (`http://`, `https://`), trailing paths, query parameters, and ports, validating valid FQDN syntax while preserving `^` and `*.` wildcards.
* **Instant Hot-Reload:** Applying changes automatically restarts the running `winws.exe` engine with the new hostlists in <200ms without interrupting the UI state.
* **Import, Export & Community Sync:** Export lists to `.txt`, import third-party rules with automatic deduplication, or download community updates directly from GitHub in 1 click.
* **Real-time Search & Dynamic Badge:** Instant substring filtering and badge counter displaying total active rule counts.

### 3.9. System DNS & Windows 11 Native DoH Integration

The `SystemDnsManager` subsystem automates host DNS resolver configuration:
* **Automatic Adapter Configuration:** When DPI bypass is activated, active physical adapters (Ethernet, Wi-Fi) automatically receive uncensored secure resolvers (Cloudflare `1.1.1.1` / `1.0.0.1`, Google, Quad9, AdGuard).
* **Native Windows 11 DoH Encryption:** Registers DoH templates via `netsh dns add encryption` with automatic upgrade (`autoupgrade=yes udpfallback=yes`).
* **Live Resolver Monitor:** Real-time health checks, latency pinging, and on-demand provider switching from the DoH table.
* **Guaranteed Safe Rollback:** The original network configuration (DHCP or static DNS) is saved before modification and restored on bypass stoppage, tray exit, or unhandled termination.

### 3.10. Live Network Socket Monitor

The interactive Network Monitor provides total visibility into host network activity:
* **Real-time Socket Enumeration:** Continuously inspects active TCP and UDP sockets via `GetExtendedTcpTable` / `GetExtendedUdpTable`.
* **Process Attribution:** Maps socket endpoints to executable paths, PIDs, and zero-trust firewall policy compliance.
* **1-Click Whitelisting:** Quickly authorizes detected connections directly into the whitelist with automated companion discovery.

---

## 4. Inter-Process Communication (IPC) Protocol

Communication between the elevated service (`OmniEyeSvc`) and the userland tray (`OmniEyeTray`) occurs across the Named Pipe `\\.\pipe\OmniEyePipe`. Security is managed via an explicit `PipeSecurity` descriptor:
- `LocalSystem` & `Administrators`: Full Control (`FullControl`).
- `Users`: Read/Write messages (`ReadWrite`).

### IPC Message Envelope Contracts:

| Message Type (`Type`) | Direction | Purpose |
|:---|:---:|:---|
| `status.request` | Tray ➔ Svc | Request service health, uptime, and operational flags |
| `status.response` | Svc ➔ Tray | Returns running status, DevMode, firewall state, block counter |
| `whitelist.get.request` | Tray ➔ Svc | Request all registered whitelist entries |
| `whitelist.get.response` | Svc ➔ Tray | List of `WhitelistEntry` objects (paths, signers, groups, dates) |
| `whitelist.add.request` | Tray ➔ Svc | Command to whitelist an executable and create firewall rules |
| `whitelist.add.response` | Svc ➔ Tray | Result of signature verification and rule addition |
| `whitelist.remove.request` | Tray ➔ Svc | Command to remove an entry/group and revoke firewall rules |
| `whitelist.remove.response`| Svc ➔ Tray | Confirmation of rule removal |
| `firewall.set_policy.request` | Tray ➔ Svc | Dynamically toggle default outbound policy (`BlockOutbound`: true/false) |
| `firewall.set_policy.response`| Svc ➔ Tray | Status of policy switch and confirmed firewall enforcement state |
| `injection.prompt.notification` | Svc ➔ Tray | Broadcast notification of detected memory injection attempt |
| `injection.prompt.action` | Tray ➔ Svc | User response decision (`"kill"` or `"ignore"`) |

---

## 5. Operating Modes (Developer Mode vs Strict Zero-Trust)

Service configuration is managed in `OmniEyeSvc\appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "OmniEye": {
    "DeveloperMode": true,
    "PipeName": "OmniEyePipe",
    "DbDirectory": "C:\\ProgramData\\OmniEye",
    "DbFileName": "config.db",
    "KeyFileName": "master.key",
    "SelfHealingIntervalMs": 3000,
    "PromptTimeoutSeconds": 60
  }
}
```

### Mode Comparison Matrix:

| Feature | `DeveloperMode: true` (Testing / Development) | `DeveloperMode: false` (Production Zero-Trust) |
|:---|:---|:---|
| **Shutdown Behavior** | Automatically restores firewall to `ALLOW` and clears `OmniEye-*` rules | Firewall remains strictly enforced; isolation persists across stops |
| **Self-Healing Watchdog** | Paused (allows engineers to inspect/modify firewall settings manually) | Active (resets unauthorized rule modifications every 3000 ms) |
| **Unsigned Binaries** | Permitted with explicit user confirmation in the GUI dialog | **Strictly Blocked**: all binaries without valid signatures are rejected |
| **Service Teardown** | Service can be terminated gracefully and releases file locks | Service termination is guarded against accidental shutdown |

---

## 6. Quick Start & Build Guide

### Prerequisites:
* Windows 10 (Build 1809+) or Windows 11 (all editions, x64).
* .NET 10.0 SDK.
* Local Administrator privileges (required for the background firewall and kernel ETW service).

### 1. Build the Entire Solution:
```powershell
dotnet build OmniEye.slnx -c Release
```

### 2. Run in Interactive Debug Mode:
Open two separate PowerShell sessions:

* **Session 1 (Administrator — Service):**
  ```powershell
  dotnet run --project OmniEyeSvc\OmniEyeSvc.csproj -c Release
  ```

* **Session 2 (Standard User — Tray GUI):**
  ```powershell
  dotnet run --project OmniEyeTray\OmniEyeTray.csproj -c Release
  ```

---

## 7. Windows Service Deployment

For production deployments, compile release binaries and register the engine as a native Windows Service (Service Control Manager):

### 1. Publish Release Artifacts:
```powershell
dotnet publish OmniEyeSvc\OmniEyeSvc.csproj -c Release -o publish\OmniEyeSvc
dotnet publish OmniEyeTray\OmniEyeTray.csproj -c Release -o publish\OmniEyeTray
```

### 2. Register Windows Service (`sc.exe` as Administrator):
```cmd
sc.exe create OmniEyeSvc binPath= "D:\SPA_Full\OmniEye\publish\OmniEyeSvc\OmniEyeSvc.exe" start= auto DisplayName= "OmniEye Zero-Trust Service"
sc.exe description OmniEyeSvc "Anti-Exfiltration Engine and Zero-Trust Network Enforcer."
sc.exe start OmniEyeSvc
```

### 3. Service Lifecycle Management:
```cmd
sc.exe stop OmniEyeSvc
sc.exe delete OmniEyeSvc
```

### 4. Enable GUI Auto-Start:
Create a shortcut pointing to `publish\OmniEyeTray\OmniEyeTray.exe` in the user startup folder (`Win + R` ➔ `shell:startup`).

---

## 8. Automated Verification Suite

The [OmniEye.Tests](file:///d:/SPA_Full/OmniEye/OmniEye.Tests) project provides end-to-end integration tests validating all security guarantees without external dependencies. To execute:

```powershell
dotnet run --project OmniEye.Tests\OmniEye.Tests.csproj
```

### Test Suite Execution Output:
```text
==================================================================
 OmniEye (Zero-Trust Anti-Exfiltration System) Verification Suite
==================================================================

[RUNNING] TEST 1: DPAPI Key Management & SQLCipher Encryption...
 -> Verified ciphertext database. Header: [51-65-61-47-C2-DC-88-98-CD-D0-4E-76-AB-B1-FA-33]
 -> Encrypted entry created and retrieved successfully (Id: 1, File: notepad.exe)
 -> Exclusive file lock successfully acquired and released.
[PASS] TEST 1: DPAPI Key Management & SQLCipher Encryption

[RUNNING] TEST 2: Authenticode Signature Verification (WinVerifyTrust)...
 -> dotnet.exe: Signed=True, Valid=True, Subject=CN=.NET, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
 -> Unsigned test file: Signed=False, Valid=False
[PASS] TEST 2: Authenticode Signature Verification (WinVerifyTrust)

[RUNNING] TEST 3: Process Freeze & Resume (NtSuspendProcess / NtResumeProcess)...
 -> Spawned target process PID: 29768
 -> NtSuspendProcess succeeded. Process frozen.
 -> NtResumeProcess succeeded. Process resumed.
 -> Process successfully terminated.
[PASS] TEST 3: Process Freeze & Resume (NtSuspendProcess / NtResumeProcess)

[RUNNING] TEST 4: Named Pipe IPC Server/Client Protocol & Security Prompts...
 -> IPC client connected to test server pipe.
 -> Status RPC verified: IsRunning=True, DevMode=True
 -> Whitelist Add RPC verified: Added to whitelist and firewall successfully.
 -> Whitelist Get RPC verified: 1 entries.
 -> Injection Prompt-and-Decision verified. Server received action: 'kill'.
[PASS] TEST 4: Named Pipe IPC Server/Client Protocol & Security Prompts

[RUNNING] TEST 5: DeveloperMode Lifecycle & Graceful Rollback...
 -> Applied Firewall policy in DeveloperMode.
 -> Successfully rolled back Firewall policy to Allow.
 -> Database exclusive lock successfully released for shutdown.
[PASS] TEST 5: DeveloperMode Lifecycle & Graceful Rollback

[RUNNING] TEST 6: Dynamic Firewall Policy Switching via IPC...
 -> Initial policy: OutboundBlocked=False
 -> Switched to ALLOW: OutboundBlocked=False, Msg: Default outbound policy set to ALLOW (Permissive).
 -> Switched to BLOCK: OutboundBlocked=True, Msg: Default outbound policy set to BLOCK (Zero-Trust).
[PASS] TEST 6: Dynamic Firewall Policy Switching via IPC

[RUNNING] TEST 7: Active Network Connection Monitoring & Process Attribution...
 -> Total active sockets detected: 246 (TCP: 153, UDP: 93)
 -> Policy correlation breakdown: Whitelisted: 0, Blocked: 182, Exceptions: 64
[PASS] TEST 7: Active Network Connection Monitoring & Process Attribution

[RUNNING] TEST 8: DNS RFC 1035 Wire-Format Serialization & Response Parsing...
 -> DNS Query built, size: 31 bytes
 -> Parsed 2 IP addresses, MinTTL: 120s
[PASS] TEST 8: DNS RFC 1035 Wire-Format Serialization & Response Parsing

[RUNNING] TEST 9: TLS ClientHello SNI Extraction & Fragmentation Offset Calculation...
 -> Synthesized ClientHello packet size: 72 bytes
 -> SNI found: True, Extracted: 'discord.com', Calculated split offset: 66
[PASS] TEST 9: TLS ClientHello SNI Extraction & Fragmentation Offset Calculation

[RUNNING] TEST 10: Multi-Resolver DoH Pool with Concurrent Race & Caching...
 -> Configured 5 DoH servers: Cloudflare, Cloudflare-Backup, Google, Quad9, AdGuard
 -> Happy Eyeballs concurrent race resolved cloudflare.com to: 104.16.132.229
[PASS] TEST 10: Multi-Resolver DoH Pool with Concurrent Race & Caching

[RUNNING] TEST 11: DPI HTTP CONNECT Proxy Server & ClientHello Fragmentation Pipeline...
 -> DpiProxyServer started on 127.0.0.1:59085, tunnel verified successfully.
[PASS] TEST 11: DPI HTTP CONNECT Proxy Server & ClientHello Fragmentation Pipeline

[RUNNING] TEST 12: Windows System Proxy WinINet Registry & Automatic Restoration...
 -> WinINet registry proxy enabled and cleanly restored to original state.
[PASS] TEST 12: Windows System Proxy WinINet Registry & Automatic Restoration

[RUNNING] TEST 13: Zapret Native Engine Assets & Command-Line Arguments Verification...
 -> Verified binaries: winws.exe, WinDivert64.sys, Discord UDP payload.
 -> Generated arguments for 22 Flowseal presets.
 -> Win32 JobObject KILL_ON_JOB_CLOSE initialized and verified.
[PASS] TEST 13: Zapret Native Engine Assets & Command-Line Arguments Verification

[RUNNING] TEST 14: System DNS & Windows 11 Native DoH Configuration Manager...
 -> Physical adapters discovered. DoH template encryption and safe rollback verified.
[PASS] TEST 14: System DNS & Windows 11 Native DoH Configuration Manager

------------------------------------------------------------------
 ALL 14 TESTS PASSED SUCCESSFULLY! (0 Failures)
------------------------------------------------------------------
```

---

## 9. Frequently Asked Questions (FAQ)

#### Q: What happens to network connectivity if OmniEyeSvc is terminated abruptly?
> **A:** In `DeveloperMode: true`, shutting down the service gracefully reverts the firewall policy to `DefaultOutboundAction = ALLOW`. In production mode (`DeveloperMode: false`), the firewall remains locked down to prevent exfiltration during unexpected crashes, preserving outbound access only for system essentials and whitelisted binaries. To restore the default firewall state manually via PowerShell (Run as Administrator):  
> `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`.

#### Q: Why are DNS and DHCP designated as system essentials?
> **A:** Without DHCP (UDP ports 67/68), the host cannot acquire or renew local network leases. Without DNS (UDP/TCP port 53), trusted applications cannot resolve remote hostnames. In high-security environments, DNS traffic can be restricted to enterprise recursive resolvers by locking down remote IP address ranges.

#### Q: How does OmniEye handle seamless application updates (e.g. Chrome, Discord)?
> **A:** The **Companion Discovery** crawler automatically detects and whitelists update helpers (`Update.exe`) within application suites. When an updated executable is installed under the same path and bears a valid code-signing certificate from the same publisher, outbound rules continue operating without user intervention.

#### Q: Does OmniEye introduce network latency or CPU overhead during gaming/streaming?
> **A:** No. Packet inspection and stateful filtering are executed natively within the Windows NDIS kernel driver (Windows Defender Firewall) at hardware line rate. OmniEye does not inject intermediate LSP or WFP proxies into userland sockets, ensuring zero added latency.

---

<p align="center">
  <sub>Engineered with dedication to zero-trust architecture and endpoint security on Microsoft Windows.</sub>
</p>
