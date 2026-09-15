# OmniEye — Zero-Trust-System zur Endpoint-Sicherheit & Verhinderung von Datenexfiltration

<p align="center">
  <b>Language:</b> 
  <a href="README.md">🇷🇺 Русский</a> • 
  <a href="README.en.md">🇬🇧 English</a> • 
  <a href="README.uk.md">🇺🇦 Українська</a> • 
  <b>🇩🇪 Deutsch</b> • 
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

**OmniEye** ist ein hochperformantes Endpoint-Protection- und Anti-Exfiltrations-System, das auf der **Zero-Trust-Architektur** für moderne Microsoft Windows-Umgebungen entwickelt wurde.

Das System setzt das fundamentale Prinzip **«Never Trust, Always Verify» (Niemals vertrauen, immer verifizieren)** auf Netzwerk- und Prozessebene durch: Sämtlicher ausgehender Netzwerkverkehr wird standardmäßig auf Kernel-NDIS-Ebene blockiert, während der Speicher vertrauenswürdiger Anwendungen durch Echtzeit-Kernel-ETW (Event Tracing for Windows) und sofortige Prozess-Einfrierung via native `ntdll.dll`-Systemaufrufe geschützt wird.

---

## 📑 Inhaltsverzeichnis

- [1. Bedrohungsmodell & Philosophie](#1-bedrohungsmodell--philosophie)
- [2. Systemarchitektur](#2-systemarchitektur)
- [3. Kernsubsysteme](#3-kernsubsysteme)
  - [3.1. Netzwerk-Enforcer & Dynamische Richtlinienumschaltung](#31-netzwerk-enforcer--dynamische-richtlinienumschaltung)
  - [3.2. Kernel-Speicherschutz (Anti-Injection: Freeze & Prompt)](#32-kernel-speicherschutz-anti-injection-freeze--prompt)
  - [3.3. Begleitkomponenten-Erkennung (Companion Discovery)](#33-begleitkomponenten-erkennung-companion-discovery)
  - [3.4. Hardwaregebundene Kryptographie & Datenbankhärtung](#34-hardwaregebundene-kryptographie--datenbankhärtung)
  - [3.5. Authenticode-Codesignatur-Prüfung](#35-authenticode-codesignatur-prüfung)
  - [3.6. Windows 11 Native Fluent UI & PerMonitorV2 High DPI](#36-windows-11-native-fluent-ui--permonitorv2-high-dpi)
  - [3.7. Natives Zapret DPI-Umgehungsmodul](#37-natives-zapret-dpi-umgehungsmodul)
  - [3.8. Sicherer DNS-Manager & Windows 11 DoH](#38-sicherer-dns-manager--windows-11-doh)
  - [3.9. Echtzeit-Netzwerk-Socket-Monitor](#39-echtzeit-netzwerk-socket-monitor)
- [4. Interprozesskommunikation (IPC-Protokoll)](#4-interprozesskommunikation-ipc-protokoll)
- [5. Betriebsmodi (Developer Mode vs. Strict Zero-Trust)](#5-betriebsmodi-developer-mode-vs-strict-zero-trust)
- [6. Schnelleinstieg & Build-Anleitung](#6-schnelleinstieg--build-anleitung)
- [7. Windows-Dienst-Bereitstellung](#7-windows-dienst-bereitstellung)
- [8. Automatisiertes Testpaket](#8-automatisiertes-testpaket)
- [9. Häufig gestellte Fragen (FAQ)](#9-häufig-gestellte-fragen-faq)

---

## 1. Bedrohungsmodell & Philosophie

Herkömmliche Antiviren- und EDR-Lösungen verlassen sich vorwiegend auf bekannte Signaturdatenbanken und nachgelagerte Heuristiken. Moderne Schadsoftware (Infostealer, Spyware, Backdoors, RATs und C2-Agenten wie Cobalt Strike, Sliver oder Havoc):
1. **Umgehen die Userland-Erkennung:** schleusen bösartigen Shellcode in legitime Windows-Prozesse ein (Process Hollowing, DLL Sideloading, Thread Hijacking, APC Injection).
2. **Exfiltrieren Geheimnisse augenblicklich:** entwenden Sitzungstoken, Browserdatenbanken, Passwörter und SSH/GPG-Schlüssel über unauffällige ausgehende TLS-Verbindungen (Ports 443/80/8080).

### Der OmniEye-Ansatz:
* **Default Deny Outbound:** Kein Programm auf dem Computer darf standardmäßig ausgehende TCP/UDP-Pakete versenden. Die ausgehende Firewall-Richtlinie ist auf `BLOCK` geschaltet.
* **Authenticode-Positivliste:** Ausgehender Netzwerkzugriff wird ausschließlich geprüften, digital signierten Binärdateien gewährt, die in einer verschlüsselten Datenbank hinterlegt sind.
* **Kernel Freeze & Prompt:** Bei unbefugtem Zugriff auf den Speicher geschützter Prozesse friert der Windows-Kernel den Angreifer augenblicklich ein, bis der Benutzer eine Entscheidung trifft.
* **Natives DPI-Bypass & DoH:** Das vollständig isolierte Modul `OmniEye.DpiBypass` ermöglicht Paketdesynchronisation (Discord Voice, YouTube) und verschlüsseltes DNS ohne Beeinträchtigung des Zero-Trust-Kerns.

---

## 2. Systemarchitektur

Die Lösung besteht aus 5 modularen Projekten in einer gemeinsamen .NET 10 Solution (`OmniEye.slnx`):

```
OmniEye/
├── OmniEye.slnx                        # Solution-Konfigurationsdatei (.NET CLI)
├── OmniEye.Core/                      # Reine Kryptographie-, Sicherheits- und IPC-Bibliothek
│   ├── Configuration/                 # Konfigurationsmodelle (OmniEyeConfig)
│   ├── Models/                        # DTO-Verträge und Datenbankentitäten (WhitelistEntry)
│   ├── Security/                      # WinVerifyTrust, DPAPI, NtDll P/Invoke, NTFS ACL
│   ├── Storage/                       # SQLite + SQLCipher AES-256 (Einstellungen und Positivliste)
│   └── Ipc/                           # Asynchroner Named-Pipe-Client (IpcClient)
├── OmniEye.DpiBypass/                 # Isoliertes Paketdesynchronisations- und DNS-Modul
│   ├── Zapret/                        # Native Zapret Engine (winws.exe, WinDivert, 22 Profile, Discord UDP)
│   ├── Dns/                           # SystemDnsManager (Adapterkonfiguration, Win11 DoH, Safe Rollback)
│   ├── Models/                        # DTOs für DoH-Server und Konfiguration
│   ├── Proxy/                         # Lokaler HTTP CONNECT DPI-Proxy
│   └── Tls/                           # TLS ClientHello SNI Parser & Fragmentierungsberechnung
├── OmniEyeSvc/                        # Privilegierter Windows-Hintergrunddienst (SYSTEM)
│   ├── Network/                       # COM INetFwPolicy2, Regelsätze, Self-Healing Watchdog
│   ├── Monitor/                       # Microsoft ETW Kernel Process/Thread/Image TraceEvent
│   ├── Ipc/                           # Named-Pipe-Server mit PipeSecurity ACL
│   ├── appsettings.json               # Dienst-Konfigurationsdatei
│   ├── Worker.cs                      # Microsoft.Extensions.Hosting Hintergrunddienst
│   └── Program.cs                     # Dienst-Einstiegspunkt (Service Host / Console)
├── OmniEyeTray/                       # Windows 11 Fluent Design Infobereich-App (Tray)
│   ├── Views/                         # UI-Ansichten (MainWindow, Dialogs, Unterseiten)
│   ├── Services/                      # LocalizationManager (5 Sprachen), NetworkMonitorService
│   ├── Localization/                  # Wörterbücher (de-DE, en-US, ru-RU, uk-UA, ja-JP)
│   ├── App.xaml                       # WPF-UI Themes & PerMonitorV2 DPI-Setup
│   ├── app.manifest                   # Anwendungsmanifest für PerMonitorV2 DPI
│   └── MainWindow.xaml.cs             # Tray-Logik, Echtzeit-Filterung, Profile und DoH
└── OmniEye.Tests/                     # Autonomes Testpaket
    └── Program.cs                     # 14 Integrationstests zur Verifikation aller Ebenen
```

### Interaktionsarchitektur der Komponenten:

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Windows 11 Fluent GUI (OmniEyeTray)               │
 │       [Dashboard]       [Firewall]     [Kernel-Schutz]   [Optionen]    │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ JSON RPC über Named Pipe
                                     │ \\.\pipe\OmniEyePipe (ACL-geschützt)
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   Hintergrunddienst (OmniEyeSvc) [SYSTEM]              │
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
 │ Firewall (NDIS-Filter)  │   │ Process/Thread Events │         │
 └─────────────────────────┘   └───────────────────────┘         │
                                                                 ▼
                                                ┌─────────────────────────┐
                                                │ AES-256 SQLCipher DB    │
                                                │ Windows DPAPI Machine   │
                                                │ Exklusive Dateisperre   │
                                                └─────────────────────────┘
```

---

## 3. Kernsubsysteme

### 3.1. Netzwerk-Enforcer & Dynamische Richtlinienumschaltung

Der Netzwerk-Enforcer steuert die Windows Defender Firewall direkt über die COM-Schnittstelle `INetFwPolicy2` (`HNetCfg.FwPolicy2` / `HNetCfg.FWRule`):
* **Profilsynchronisation:** Einstellungen gelten synchron für alle drei Windows-Firewall-Profile: `Domain`, `Private` und `Public`.
* **Interaktive Richtlinienwahl:** Auf der Registerkarte **«Сетевой экран» (Firewall)** kann die Standardrichtlinie mit einem Klick umgeschaltet werden:
  - **`BLOCKIEREN (Zero-Trust BLOCK)`** — Ein- und ausgehende Verbindungen sind standardmäßig gesperrt. Nur Whitelist und Systemausnahmen sind aktiv.
  - **`ERLAUBEN (Permissive ALLOW)`** — Standardmäßiger Netzwerkbetrieb. Ausgehende Verbindungen sind für alle Programme freigegeben.
* **Systemausnahmen (System Essentials):**
  - **DNS:** Ausgehender Port 53 UDP und TCP (`OmniEye-System-DNS-UDP`, `OmniEye-System-DNS-TCP`).
  - **DHCP:** Ausgehende Ports 67, 68 UDP (`OmniEye-System-DHCP`).
  - **Windows Update:** Dienst-Regel für `wuauserv` (`OmniEye-System-WindowsUpdate`).
* **Self-Healing Watchdog:** Ein Watchdog prüft alle 3000 ms die Integrität der Richtlinie. Versucht Fremdsoftware, die Blockierung aufzuheben, stellt der Watchdog die Regeln sofort wieder her. Bei Auswahl von `ALLOW` pausiert der Watchdog, um die Benutzerentscheidung zu respektieren.

### 3.2. Kernel-Speicherschutz (Anti-Injection: Freeze & Prompt)

Zum Schutz vor unbefugtem Einschleusen von Code nutzt OmniEye den Kernel-ETW-Provider `Microsoft-Windows-Kernel-Process`:
1. **Ereigniserfassung:** Thread-Erstellung und Modulladungen werden in Echtzeit überwacht.
2. **Erkennung:** Manipulationsversuche an Prozessen der Whitelist lösen den Algorithmus **Freeze & Prompt** aus.
3. **Thread-Einfrierung:** Über den nativen Kernel-Aufruf `NtSuspendProcess` (`ntdll.dll`) werden alle Threads des Angreifers sofort angehalten.
4. **Alarmfenster (`PromptDialog`):** Ein oberstes Fenster informiert über PIDs, Pfade und startet einen 60-Sekunden-Countdown.
5. **Entscheidung:**
   - Bei Klick auf **[Prozess beenden]** oder nach 60 Sekunden wird der Angreifer via `NtTerminateProcess` terminiert.
   - Bei Klick auf **[Ignorieren]** wird der Prozess via `NtResumeProcess` fortgesetzt.

### 3.3. Begleitkomponenten-Erkennung (Companion Discovery)

Moderne Software (AmneziaVPN, Discord, Chrome, Telegram, IDEs) besteht aus vielen Teilkomponenten: GUI, Hintergrunddienste, Netzwerktunnel (`tun2socks`, `wireguard`, `openvpn`), Hilfsprozesse und Updatemodule (`Update.exe`).

OmniEye:
* Durchsucht rekursiv den Ordner der Anwendung, Unterordner (`bin`, `tap`, `helper`, `proxy`) und Squirrel-Pfade.
* Klassifiziert Module nach ihrer Rolle («Netzwerktunnel / VPN», «Hintergrunddienst», «Updatedienst», «Deinstallierer»).
* Öffnet den Dialog **`CompanionDiscoveryDialog`**, um die gesamte Anwendungsgruppe mit einem Klick freizugeben.
* Fasst Module in einer ausklappbaren Windows 11 `SettingsExpander`-Karte zusammen.

### 3.4. Hardwaregebundene Kryptographie & Datenbankhärtung

* **Transparente Verschlüsselung:** Die Datenbank `C:\ProgramData\OmniEye\config.db` wird via **SQLCipher AES-256-CBC** (`SQLitePCLRaw.bundle_e_sqlcipher`) verschlüsselt. Auch der SQLite-Header ist vollständig unlesbar.
* **DPAPI-Hardwarebindung:** Der 256-Bit-Hauptschlüssel ist über **Windows DPAPI** (`DataProtectionScope.LocalMachine`) an das TPM und die physische Maschine gebunden.
* **NTFS-Rechtehärtung:** Zugriff auf `C:\ProgramData\OmniEye` ist strikt beschränkt: `SYSTEM` und `Administrators` haben Vollzugriff (`FullControl`), normale Benutzer nur Leserechte.
* **Exklusive Dateisperre:** Der Dienst hält die Datei mit `FileShare.None` und `PRAGMA locking_mode = EXCLUSIVE` geöffnet, um Manipulationen bei laufendem System auszuschließen.

### 3.5. Authenticode-Codesignatur-Prüfung

* Die Verifizierung erfolgt über die Win32-API `WinVerifyTrust` (`wintrust.dll`) mit der Aktions-GUID `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
* Unterstützt werden sowohl eingebettete Authenticode-Signaturen als auch Windows-Sicherheitskataloge (`.cat`).
* Metadaten des Ausstellers (CN, Organisation, Land) werden erfasst.
* Im Produktivmodus (`DeveloperMode = false`) werden unsignierte oder manipulierte Dateien **strikt abgewiesen**.

### 3.6. Windows 11 Native Fluent UI & PerMonitorV2 High DPI

Die Oberfläche [OmniEyeTray](file:///d:/SPA_Full/OmniEye/OmniEyeTray) setzt die [Microsoft Windows App Design Guidelines](https://learn.microsoft.com/de-de/windows/apps/design/guidelines-overview) um:
* **Mica-Material:** Transluzentes Mica-Hintergrundmaterial via DWM-API (`DwmSetWindowAttribute`, `DWMSBT_MAINWINDOW`).
* **TitleBar mit Snap Layouts:** Windows 11 Titelleiste mit nativer Snap-Layout-Vorschau beim Überfahren der Maximieren-Schaltfläche.
* **Subpixel-Anti-Aliasing:** `ClearType`, Subpixel-Textformatierung und `UseLayoutRounding="True"` verhindern Render-Artefakte auf dunklen Oberflächen.
* **PerMonitorV2 High DPI Awareness:** Durch das Anwendungsmanifest und `SetProcessDpiAwarenessContext` bleibt die Darstellung beim Verschieben zwischen 1080p (100%) und 4K (150%–200%) Monitoren gestochen scharf ohne Weichzeichner-Effekt.
* **Windows 11 Einstellungselemente:** Elegante Trennlinien, abgerundete Ecken (`CornerRadius="8"`), dezente Hover-Zustände (`IsMouseOver`) und dunkle Bildlaufleisten.

### 3.7. Natives Zapret DPI-Umgehungsmodul

Um den unterbrechungsfreien Zugriff auf Netzwerkdienste (wie Discord Voice und YouTube) unter aggressiver Deep Packet Inspection (DPI) zu gewährleisten, ist das entkoppelte Modul `OmniEye.DpiBypass` integriert:
* **Kernel-Paketabfang:** Nutzt den nativen Treiber `WinDivert64.sys` und den Prozess `winws.exe` auf L3/L4-Ebene.
* **Discord WebRTC Voice-Desynchronisation:** Gezielte UDP-Filterung und Payload-Ersetzung (`--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=ACTIVE_DISCORD_UDP.bin`) zur Stabilisierung von Sprachkanälen.
* **HTTPS / TLS ClientHello Desynchronisation:** Multisplit und Sequenzüberlappung auf Basis von `list-general.txt` und `list-google.txt`.
* **22 Flowseal-Profile:** Interaktive Profilauswahl in der GUI (`General`, `ALT1-13`, `SIMPLE FAKE`, `FAKE TLS AUTO`, `EXP`) zur schnellen Anpassung an jeden Provider.
* **Prozessbindung über Windows JobObject:** Prozess `winws.exe` ist an ein Win32 Job Object mit `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` gebunden. Beim Beenden des Programms werden Treiber und Prozess garantiert sofort beendet.

### 3.8. Sicherer DNS-Manager & Windows 11 DoH

Das `SystemDnsManager`-Subsystem steuert die DNS-Konfiguration des Systems:
* **Automatische Adapterkonfiguration:** Bei Aktivierung des Bypasses werden aktive Netzwerkadapter (Ethernet, Wi-Fi) automatisch auf sichere DNS-Server (Cloudflare `1.1.1.1` / `1.0.0.1`, Google, Quad9, AdGuard) umgestellt.
* **Native Windows 11 DoH-Verschlüsselung:** Registriert Vorlagen via `netsh dns add encryption` mit automatischer Aktualisierung (`autoupgrade=yes udpfallback=yes`).
* **Echtzeit-DoH-Monitor:** Überwachung von Latenzen (Ping) und Anbieterwechsel per Knopfdruck.
* **Garantierter Safe Rollback:** Die ursprüngliche Netzwerkkonfiguration (DHCP oder statische IPs) wird gesichert und beim Stoppen oder Beenden verlässlich wiederhergestellt.

### 3.9. Echtzeit-Netzwerk-Socket-Monitor

Der integrierte Netzwerk-Monitor bietet vollständige Transparenz über alle Verbindungen:
* **Socket-Inspektion:** Kontinuierliche Abfrage der TCP/UDP-Verbindungstabellen (`GetExtendedTcpTable`, `GetExtendedUdpTable`).
* **Prozesszuordnung:** Verknüpfung von Sockets mit PIDs, Dateipfaden und Zero-Trust-Konformität.
* **1-Klick-Freigabe:** Direkte Aufnahme erkannter Anwendungen in die Positivliste mit automatischer Modulsuche.

---

## 4. Interprozesskommunikation (IPC-Protokoll)

Die Kommunikation zwischen Dienst (`OmniEyeSvc`) und Benutzeroberfläche (`OmniEyeTray`) erfolgt über die Named Pipe `\\.\pipe\OmniEyePipe` mit strikter `PipeSecurity`:
- `LocalSystem` & `Administrators`: Vollzugriff (`FullControl`).
- `Users`: Nachrichten lesen und schreiben (`ReadWrite`).

### IPC-Nachrichtenverträge (JSON):

| Nachrichtentyp (`Type`) | Richtung | Zweck |
|:---|:---:|:---|
| `status.request` | Tray ➔ Svc | Statusabfrage des Dienstes, Uptime und Flags |
| `status.response` | Svc ➔ Tray | Antwort: Betriebszustand, DevMode, Firewall-Status, Blockierungszähler |
| `whitelist.get.request` | Tray ➔ Svc | Abfrage aller freigegebenen Programme |
| `whitelist.get.response` | Svc ➔ Tray | Liste von `WhitelistEntry`-Objekten (Pfade, Aussteller, Gruppen, Daten) |
| `whitelist.add.request` | Tray ➔ Svc | Befehl zum Hinzufügen einer Anwendung und Firewall-Regelerstellung |
| `whitelist.add.response` | Svc ➔ Tray | Ergebnis der Signaturprüfung und Regelerstellung |
| `whitelist.remove.request` | Tray ➔ Svc | Befehl zum Entfernen eines Eintrags und Widerruf der Regeln |
| `whitelist.remove.response`| Svc ➔ Tray | Bestätigung der Entfernung |
| `firewall.set_policy.request` | Tray ➔ Svc | Dynamische Umschaltung der Firewall-Richtlinie (`BlockOutbound`: true/false) |
| `firewall.set_policy.response`| Svc ➔ Tray | Bestätigung des Richtlinienstatus und Überprüfung der Firewall |
| `injection.prompt.notification` | Svc ➔ Tray | Benachrichtigung über erkannten Prozessmanipulationsversuch |
| `injection.prompt.action` | Tray ➔ Svc | Entscheidung des Benutzers (`"kill"` oder `"ignore"`) |

---

## 5. Betriebsmodi (Developer Mode vs. Strict Zero-Trust)

Die Konfiguration erfolgt über `OmniEyeSvc\appsettings.json`:

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

### Vergleich der Betriebsmodi:

| Funktion | `DeveloperMode: true` (Entwicklungs-/Testmodus) | `DeveloperMode: false` (Produktiv-Zero-Trust) |
|:---|:---|:---|
| **Verhalten beim Beenden** | Firewall wird automatisch auf `ALLOW` zurückgesetzt, `OmniEye-*`-Regeln entfernt | Firewall bleibt strikt blockiert; Isolierung bleibt bestehen |
| **Self-Healing Watchdog** | Pausiert (ermöglicht manuelle Netzwerkanalysen) | Aktiv (stellt manipulierte Regeln alle 3000 ms wieder her) |
| **Unsignierte Dateien** | Hinzufügen nach Benutzerbestätigung im Dialog erlaubt | **Strikt verboten**: Dateien ohne gültige Signatur werden abgewiesen |
| **Dienst-Stopp** | Dienst kann ordnungsgemäß gestoppt werden, gibt Dateisperren frei | Dienst ist gegen unbefugtes oder versehentliches Beenden geschützt |

---

## 6. Schnelleinstieg & Build-Anleitung

### Voraussetzungen:
* Windows 10 (Build 1809+) oder Windows 11 (alle Editionen, x64).
* .NET 10.0 SDK.
* Lokale Administratorrechte (erforderlich für den Firewall- und Kernel-ETW-Dienst).

### 1. Gesamte Solution kompilieren:
```powershell
dotnet build OmniEye.slnx -c Release
```

### 2. Im interaktiven Debug-Modus starten:
In zwei separaten PowerShell-Fenstern:

* **Fenster 1 (Administrator — Hintergrunddienst):**
  ```powershell
  dotnet run --project OmniEyeSvc\OmniEyeSvc.csproj -c Release
  ```

* **Fenster 2 (Standardbenutzer — Infobereichs-GUI):**
  ```powershell
  dotnet run --project OmniEyeTray\OmniEyeTray.csproj -c Release
  ```

---

## 7. Windows-Dienst-Bereitstellung

Für den Produktiveinsatz wird der Dienst als Release kompiliert und im Windows-Dienstmanager (SCM) registriert:

### 1. Release-Dateien veröffentlichen:
```powershell
dotnet publish OmniEyeSvc\OmniEyeSvc.csproj -c Release -o publish\OmniEyeSvc
dotnet publish OmniEyeTray\OmniEyeTray.csproj -c Release -o publish\OmniEyeTray
```

### 2. Windows-Dienst registrieren (`sc.exe` als Administrator):
```cmd
sc.exe create OmniEyeSvc binPath= "D:\SPA_Full\OmniEye\publish\OmniEyeSvc\OmniEyeSvc.exe" start= auto DisplayName= "OmniEye Zero-Trust Service"
sc.exe description OmniEyeSvc "Zero-Trust-Netzwerkfilter und Schutz vor Datenexfiltration."
sc.exe start OmniEyeSvc
```

### 3. Dienst verwalten:
```cmd
sc.exe stop OmniEyeSvc
sc.exe delete OmniEyeSvc
```

### 4. Tray-App zum Autostart hinzufügen:
Verknüpfung von `publish\OmniEyeTray\OmniEyeTray.exe` im Windows-Autostartordner ablegen (`Win + R` ➔ `shell:startup`).

---

## 8. Automatisiertes Testpaket

Das Projekt [OmniEye.Tests](file:///d:/SPA_Full/OmniEye/OmniEye.Tests) enthält isolierte Integrationstests zur Verifikation aller Sicherheitsmechanismen:

```powershell
dotnet run --project OmniEye.Tests\OmniEye.Tests.csproj
```

### Testergebnisse:
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

## 9. Häufig gestellte Fragen (FAQ)

#### Q: Was geschieht mit der Internetverbindung, wenn der Dienst unerwartet abstürzt?
> **A:** Im Modus `DeveloperMode: true` wird beim Beenden des Dienstes die Richtlinie auf `ALLOW` zurückgestellt. Im Produktivmodus (`DeveloperMode: false`) bleibt die Firewall zur Verhinderung von Datenabflüssen blockiert. Zur manuellen Wiederherstellung der Standard-Firewall in PowerShell (als Administrator):  
> `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`.

#### Q: Warum sind DNS und DHCP als Systemausnahmen definiert?
> **A:** Ohne DHCP (Ports 67/68 UDP) kann der Rechner keine IP-Adresse vom Router beziehen, und ohne DNS (Port 53 UDP/TCP) können Domänennamen nicht aufgelöst werden. In Hochsicherheitsumgebungen können DNS-Ports an feste IP-Adressen interner DNS-Server gebunden werden.

#### Q: Wie verhält sich OmniEye bei Software-Updates (z. B. Chrome, Discord)?
> **A:** Der **Companion Discovery**-Crawler erfasst Update-Module (`Update.exe`) automatisch in der Anwendungsgruppe. Wird ein Update eingespielt, das dieselbe Signatur desselben Herausgebers trägt, greifen die Firewall-Regeln unterbrechungsfrei weiter.

#### Q: Beeinflusst OmniEye die Netzwerklatenz oder Frameraten beim Gaming?
> **A:** Nein. Die Paketfilterung erfolgt direkt im nativen Windows NDIS-Kernel-Treiber auf Hardware-Leitungsgeschwindigkeit ohne zwischengeschaltete Userland-Proxys. OmniEye erzeugt keinen messbaren Latenz-Overhead.

---

<p align="center">
  <sub>Entwickelt für kompromisslose Privatsphäre und maximale Endpoint-Sicherheit auf Microsoft Windows.</sub>
</p>
