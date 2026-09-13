# OmniEye — Zero-Trust Anti-Exfiltration & Endpoint Protection System

<p align="center">
  <b>Language:</b> 
  <a href="README.md">🇷🇺 Русский</a> • 
  <a href="README.en.md">🇬🇧 English</a> • 
  <b>🇺🇦 Українська</b> • 
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

**OmniEye** — високопродуктивна система захисту кінцевих точок (Endpoint Protection) та запобігання ексфільтрації даних (Anti-Data Exfiltration System), спроєктована на основі архітектури **Zero-Trust** для операційної системи Windows.

Система втілює фундаментальний принцип **«Ніколи не довіряй, завжди перевіряй» (Never Trust, Always Verify)** на мережевому та процесному рівнях: весь вихідний мережевий трафік за замовчуванням блокується на рівні ядра NDIS, а пам'ять довірених процесів перебуває під безперервним моніторингом ядра ETW із миттєвим заморожуванням процесів-зловмисників за допомогою нативних викликів `ntdll.dll`.

---

## 📑 Зміст

- [1. Концепція та модель загроз](#1-концепція-та-модель-загроз)
- [2. Архітектура рішення](#2-архітектура-рішення)
- [3. Ключові підсистеми](#3-ключові-підсистеми)
  - [3.1. Мережевий фільтр (Network Enforcer) & Вибір політики](#31-мережевий-фільтр-network-enforcer--вибір-політики)
  - [3.2. Монітор ядра та захист пам'яті (Anti-Injection Kernel Monitor)](#32-монітор-ядра-та-захист-памяті-anti-injection-kernel-monitor)
  - [3.3. Групове виявлення компонентів (Companion Discovery)](#33-групове-виявлення-компонентів-companion-discovery)
  - [3.4. Апаратна криптографія та гарденінг БД](#34-апаратна-криптографія-та-гарденінг-бд)
  - [3.5. Верифікатор цифрових підписів (Authenticode Verifier)](#35-верифікатор-цифрових-підписів-authenticode-verifier)
  - [3.6. Нативний інтерфейс Windows 11 Fluent Design](#36-нативний-інтерфейс-windows-11-fluent-design)
- [4. Протокол міжпроцесної взаємодії (IPC)](#4-протокол-міжпроцесної-взаємодії-ipc)
- [5. Режими роботи (Developer Mode vs Strict)](#5-режими-роботи-developer-mode-vs-strict)
- [6. Швидкий старт та збірка](#6-швидкий-старт-та-збірка)
- [7. Встановлення служби Windows](#7-встановлення-служби-windows)
- [8. Автоматизований комплекс тестування](#8-автоматизований-комплекс-тестування)
- [9. Поширені запитання (FAQ)](#9-поширені-запитання-faq)

---

## 1. Концепція та модель загроз

Традиційні антивірусні рішення (EDR/EPP) здебільшого покладаються на бази відомих сигнатур, пост-фактум евристику та поведінковий аналіз. Проте сучасні шкідливі програми (інфостілери, шпигунське ПЗ, бекдори, RAT, C2-агенти Cobalt Strike, Sliver, Havoc):
1. **Оминають інспекцію користувацького простору:** впроваджують шелкод у легітимні процеси Windows (Process Hollowing, DLL Sideloading, Thread Hijacking, APC Injection).
2. **Миттєво викрадають конфіденційні дані:** ексфільтрують сесійні токени, паролі з диспетчерів паролів, приватні ключі SSH/GPG та бази даних браузерів через приховані вихідні з'єднання по портах 443/80/8080.

### Підхід OmniEye:
* **Мережева ізоляція (Default Deny):** за замовчуванням жодна програма не має права надсилати пакети у зовнішню мережу. Вихідна політика брандмауера встановлена в режим `BLOCK`.
* **Білий список Authenticode:** мережевий доступ надається виключно перевіреним бінарним файлам, підписаним валідним цифровим сертифікатом розробника.
* **Freeze & Prompt:** у разі виявлення спроби втручання в пам'ять довіреного процесу ядро операційної системи моментально заморожує атакуючий процес до прийняття рішення адміністратором.

---

## 2. Архітектура рішення

Рішення складається з 4 модульних проєктів у межах єдиного рішення .NET 10 (`OmniEye.slnx`):

```
OmniEye/
├── OmniEye.slnx                        # Файл конфігурації рішення (.NET CLI)
├── OmniEye.Core/                      # Спільна бібліотека безпеки, криптографії та IPC
│   ├── Configuration/                 # Моделі конфігурації (OmniEyeConfig)
│   ├── Models/                        # DTO-контракти повідомлень IPC та сутності БД
│   ├── Security/                      # WinVerifyTrust, DPAPI, NtDll P/Invoke, NTFS ACL
│   ├── Storage/                       # SQLite + SQLCipher AES-256 з ексклюзивним файловим локом
│   └── Ipc/                           # Асинхронний клієнт іменованих каналів (IpcClient)
├── OmniEyeSvc/                        # Фонова служба Windows підвищених привілеїв (SYSTEM)
│   ├── Network/                       # COM INetFwPolicy2, керування правилами, Self-Healing Watchdog
│   ├── Monitor/                       # Microsoft ETW Kernel Process/Thread/Image TraceEvent
│   ├── Ipc/                           # Сервер іменованих каналів (PipeSecurity ACL)
│   ├── appsettings.json               # Параметри конфігурації служби
│   ├── Worker.cs                      # Фонова служба Microsoft.Extensions.Hosting
│   └── Program.cs                     # Точка входу служби Windows
├── OmniEyeTray/                       # GUI трею в стилі Windows 11 Fluent Design
│   ├── Views/                         # Вікна інтерфейсу (MainWindow, CompanionDiscovery, PromptDialog)
│   ├── Models/                        # Моделі виявлених модулів
│   ├── App.xaml                       # Ініціалізація теми WPF-UI та PerMonitorV2 DPI
│   ├── app.manifest                   # Маніфест DPI-Awareness (PerMonitorV2)
│   └── MainWindow.xaml.cs             # Логіка трею, динамічної фільтрації та вибору політики
└── OmniEye.Tests/                     # Комплекс наскрізних автоматизованих тестів
    └── Program.cs                     # 6 ізольованих тестів для перевірки всіх рівнів
```

### Схема взаємодії компонентів:

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Windows 11 Fluent GUI (OmniEyeTray)               │
 │       [Головна]     [Сетевий екран]   [Захист ядра]   [Параметри]      │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ JSON RPC через Named Pipe
                                     │ \\.\pipe\OmniEyePipe (ACL Secured)
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    Фонова служба (OmniEyeSvc) [SYSTEM]                 │
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

## 3. Ключові підсистеми

### 3.1. Мережевий фільтр (Network Enforcer) & Вибір політики

Мережевий фільтр керує брандмауером Windows Defender через нативний COM-інтерфейс `INetFwPolicy2` (`HNetCfg.FwPolicy2` / `HNetCfg.FWRule`):
* **Синхронізація профілів:** параметри застосовуються синхронно до всіх мережевих профілів Windows: `Domain`, `Private` та `Public`.
* **Динамічний вибір політики:** на сторінці **«Сетевой экран»** користувач може в один клік перемикати режим роботи:
  - **`БЛОКУВАТИ ВСЕ (Zero-Trust BLOCK)`** — вхідні та вихідні з'єднання заблоковані за замовчуванням. Працюють лише Білий список та системні винятки.
  - **`ДОЗВОЛЯТИ ВСЕ (Permissive ALLOW)`** — стандартний режим. Вихідні з'єднання дозволені для всіх застосунків.
* **Системні винятки (System Essentials):**
  - **DNS:** вихідний порт 53 UDP та TCP (`OmniEye-System-DNS-UDP`, `OmniEye-System-DNS-TCP`).
  - **DHCP:** вихідні порти 67, 68 UDP (`OmniEye-System-DHCP`).
  - **Windows Update:** системна служба `wuauserv` (`OmniEye-System-WindowsUpdate`).
* **Сторожовий таймер (Self-Healing Watchdog):** фоновий таймер кожні 3000 мс перевіряє стан `DefaultOutboundAction`. При спробі стороннього ПЗ зняти блокування правила миттєво відновлюються. При виборі режиму `ALLOW` таймер призупиняє скидання, поважаючи вибір користувача.

### 3.2. Монітор ядра та захист пам'яті (Anti-Injection Kernel Monitor)

Для захисту процесів від впровадження шкідливого коду використовується провайдер ядра Windows ETW (`Microsoft-Windows-Kernel-Process`):
1. **Перехоплення подій:** служба аналізує створення потоків і завантаження модулів у реальному часі.
2. **Виявлення:** спроба модифікації пам'яті процесу з Білого списку активує алгоритм **Freeze & Prompt**.
3. **Миттєве заморожування:** системний виклик `NtSuspendProcess` (`ntdll.dll`) зупиняє всі потоки атакуючого процесу.
4. **Діалог тривоги (`PromptDialog`):** у сесії користувача з'являється вікно з інформацією про PID, шляхи до файлів та 60-секундним зворотним відліком.
5. **Прийняття рішення:**
   - При виборі **[Знищити процес]** або закінченні 60 секунд процес завершується через `NtTerminateProcess`.
   - При виборі **[Ігнорувати]** потоки розморожуються через `NtResumeProcess`.

### 3.3. Групове виявлення компонентів (Companion Discovery)

Сучасні програми (VPN-клієнти, месенджери, браузери, середовища розробки) складаються з багатьох компонентів: GUI, фонові служби Windows, мережеві тунелі (`tun2socks`, `wireguard`, `openvpn`), оновлювачі (`Update.exe`) та допоміжні процеси.

Модуль Companion Discovery:
* Сканує робочу директорію, підпапки (`bin`, `tap`, `helper`, `proxy`) та батьківські каталоги Squirrel-додатків.
* Визначає роль компонентів («Мережевий тунель / VPN», «Фонова служба», «Служба оновлення», «Деінсталятор»).
* Відкриває діалог **`CompanionDiscoveryDialog`**, що дозволяє додати всю екосистему застосунку до брандмауера в один клік.
* Об'єднує файли в акуратну інтерактивну картку Windows 11 `SettingsExpander`.

### 3.4. Апаратна криптографія та гарденінг БД

* **Прозоре шифрування:** База даних `C:\ProgramData\OmniEye\config.db` зашифрована **SQLCipher AES-256-CBC** (`SQLitePCLRaw.bundle_e_sqlcipher`). Заголовок SQLite (`SQLite format 3`) приховано за шифротекстом.
* **Прив'язка до апаратного профілю DPAPI:** Майстер-ключ захищено через **Windows DPAPI** (`DataProtectionScope.LocalMachine`) з прив'язкою до TPM комп'ютера.
* **NTFS Харденінг:** Права на каталог `C:\ProgramData\OmniEye` обмежені: `SYSTEM` і `Administrators` мають повний доступ (`FullControl`), стандартні користувачі — лише читання без можливості зміни.
* **Ексклюзивний лок:** Служба утримує дескриптор файлу (`FileShare.None`) та режим `PRAGMA locking_mode = EXCLUSIVE`, унеможливлюючи підміну або читання бази іншими процесами.

### 3.5. Верифікатор цифрових підписів (Authenticode Verifier)

* Перевірка здійснюється через нативну функцію Win32 API `WinVerifyTrust` (`wintrust.dll`) з GUID `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
* Підтримуються вбудовані цифрові підписи та системні каталоги безпеки Windows (`.cat`).
* З сертифіката витягуються дані видавця (`CN`, організація, країна).
* У бойовому режимі (`DeveloperMode = false`) непідписані або пошкоджені файли **суворо відхиляються**.

### 3.6. Нативний інтерфейс Windows 11 Fluent Design

Інтерфейс [OmniEyeTray](file:///d:/SPA_Full/OmniEye/OmniEyeTray) реалізовано згідно з [Microsoft Windows App Design Guidelines](https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview):
* **Mica Backdrop:** напівпрозорий системний матеріал Mica (`DwmSetWindowAttribute`, `DWMSBT_MAINWINDOW`).
* **TitleBar зі Snap Layouts:** фірмова панель заголовка Windows 11 із сіткою макетів при наведенні на кнопку розгортання.
* **Чіткий субпіксельний рендеринг:** апаратний `ClearType`, субпіксельне згладжування та `UseLayoutRounding="True"`.
* **Підтримка PerMonitorV2 High DPI:** завдяки маніфесту `PerMonitorV2` та ініціалізації контексту ядра переміщення вікна між екранами 1080p (100%) та 4K (150%–200%) не спричиняє розмиття чи мила.
* **Картки параметрів Windows 11:** плавні мікроанімації при наведенні, радіус закруглення `CornerRadius="8"` та темні смуги прокрутки.

---

## 4. Протокол міжпроцесної взаємодії (IPC)

Зв'язок між службою (`OmniEyeSvc`) та інтерфейсом трею (`OmniEyeTray`) забезпечується через іменований канал (Named Pipe) `\\.\pipe\OmniEyePipe` з дескриптором безпеки `PipeSecurity`:
- `LocalSystem` & `Administrators`: Повний доступ (`FullControl`).
- `Users`: Читання та запис повідомлень (`ReadWrite`).

### Контракти повідомлень (JSON Envelope):

| Тип повідомлення (`Type`) | Напрямок | Призначення |
|:---|:---:|:---|
| `status.request` | Tray ➔ Svc | Запит поточного стану служби, лічильників та режиму |
| `status.response` | Svc ➔ Tray | Відповідь: статус роботи, DevMode, стан брандмауера, заблоковані атаки |
| `whitelist.get.request` | Tray ➔ Svc | Запит повного списку дозволених програм |
| `whitelist.get.response` | Svc ➔ Tray | Список об'єктів `WhitelistEntry` (шляхи, видавці, групи, дати) |
| `whitelist.add.request` | Tray ➔ Svc | Команда додавання файлу до Білого списку та брандмауера |
| `whitelist.add.response` | Svc ➔ Tray | Результат перевірки підпису та додавання |
| `whitelist.remove.request` | Tray ➔ Svc | Команда видалення запису/групи та скасування правил Firewall |
| `whitelist.remove.response`| Svc ➔ Tray | Підтвердження видалення |
| `firewall.set_policy.request` | Tray ➔ Svc | Динамічна зміна політики вихідного трафіку (`BlockOutbound`: true/false) |
| `firewall.set_policy.response`| Svc ➔ Tray | Підтвердження перемикання політики та поточний стан Firewall |
| `injection.prompt.notification` | Svc ➔ Tray | Сповіщення про виявлену спробу впровадження коду в пам'ять |
| `injection.prompt.action` | Tray ➔ Svc | Рішення користувача (`"kill"` або `"ignore"`) |

---

## 5. Режими роботи (Developer Mode vs Strict)

Конфігураційний файл служби розташовано за шляхом `OmniEyeSvc\appsettings.json`:

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

### Порівняння режимів:

| Параметр | `DeveloperMode: true` (Режим розробника) | `DeveloperMode: false` (Бойовий Zero-Trust) |
|:---|:---|:---|
| **Поведінка при зупинці** | Брандмауер автоматично повертається в `ALLOW`, правила `OmniEye-*` видаляються | Політика брандмауера залишається активною; ізоляція зберігається |
| **Сторожовий таймер** | Призупинено (дозволяє інженерам змінювати налаштування вручну) | Активний (скидає несанкціоновані зміни мережі кожні 3 сек) |
| **Непідписані файли** | Дозволено додавання з підтвердженням користувача у діалозі | **Суворо заборонено**: файли без валідного підпису відхиляються |
| **Зупинка служби** | Службу можна зупинити у штатному режимі зі звільненням локів | Зупинка служби захищена від випадкових чи примусових дій |

---

## 6. Швидкий старт та збірка

### Системні вимоги:
* Windows 10 (версія 1809+) або Windows 11 (будь-яка редакція x64).
* .NET 10.0 SDK.
* Права локального адміністратора (для керування брандмауером та сесією ядра ETW).

### 1. Збірка всього рішення:
```powershell
dotnet build OmniEye.slnx -c Release
```

### 2. Запуск у режимі налагодження:
У двох окремих вікнах PowerShell:

* **Термінал 1 (Адміністратор — Фонова служба):**
  ```powershell
  dotnet run --project OmniEyeSvc\OmniEyeSvc.csproj -c Release
  ```

* **Термінал 2 (Звичайний користувач — Інтерфейс трею):**
  ```powershell
  dotnet run --project OmniEyeTray\OmniEyeTray.csproj -c Release
  ```

---

## 7. Встановлення служби Windows

Для постійної експлуатації служба компілюється у релізні бінарні файли та реєструється у диспетчері служб Windows (Service Control Manager):

### 1. Публікація Release-складання:
```powershell
dotnet publish OmniEyeSvc\OmniEyeSvc.csproj -c Release -o publish\OmniEyeSvc
dotnet publish OmniEyeTray\OmniEyeTray.csproj -c Release -o publish\OmniEyeTray
```

### 2. Реєстрація служби (`sc.exe` від імені Адміністратора):
```cmd
sc.exe create OmniEyeSvc binPath= "D:\SPA_Full\OmniEye\publish\OmniEyeSvc\OmniEyeSvc.exe" start= auto DisplayName= "OmniEye Zero-Trust Service"
sc.exe description OmniEyeSvc "Ядро захисту від ексфільтрації даних та мережевий екран Zero-Trust."
sc.exe start OmniEyeSvc
```

### 3. Керування службою:
```cmd
sc.exe stop OmniEyeSvc
sc.exe delete OmniEyeSvc
```

### 4. Додавання Tray в автозапуск користувача:
Створіть ярлик для `publish\OmniEyeTray\OmniEyeTray.exe` у папці автозавантаження Windows (`Win + R` ➔ `shell:startup`).

---

## 8. Автоматизований комплекс тестування

Проєкт [OmniEye.Tests](file:///d:/SPA_Full/OmniEye/OmniEye.Tests) містить повний набір автономних інтеграційних тестів для перевірки всіх рівнів захисту:

```powershell
dotnet run --project OmniEye.Tests\OmniEye.Tests.csproj
```

### Результат виконання тестів:
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

------------------------------------------------------------------
 ALL 6 TESTS PASSED SUCCESSFULLY! (0 Failures)
------------------------------------------------------------------
```

---

## 9. Поширені запитання (FAQ)

#### Q: Що станеться з інтернет-з'єднанням, якщо службу OmniEye буде раптово аварійно завершено?
> **A:** У режимі `DeveloperMode: true` при зупинці служби мережева політика автоматично відновлюється в `DefaultOutboundAction = ALLOW`. У бойовому режимі (`DeveloperMode: false`) брандмауер залишиться заблокованим задля безпеки, зберігаючи доступ лише для системних служб та раніше дозволених програм. Відновити стандартний стан брандмауера вручну можна командою PowerShell (від імені Адміністратора):  
> `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`.

#### Q: Чому сервіси DNS та DHCP винесено в системні винятки?
> **A:** Без протоколу DHCP (порти 67/68 UDP) комп'ютер не зможе отримати IP-адресу від маршрутизатора, а без DNS (порт 53 UDP/TCP) неможливе перетворення доменних імен у IP для довірених додатків. У закритих корпоративних мережах порти DNS можна додатково обмежити конкретними IP-адресами корпоративних DNS-серверів.

#### Q: Як OmniEye взаємодіє з оновленням програм (наприклад, браузера або месенджера)?
> **A:** Модуль **Companion Discovery** автоматично додає супутні процеси оновлення (`Update.exe`) до довіреної групи додатку. Коли виходить нова версія файлу з тим самим валідним цифровим підписом розробника, правила брандмауера продовжують працювати безшовно.

#### Q: Чи впливає OmniEye на швидкість мережі або пінг в іграх?
> **A:** Ні. Фільтрація здійснюється нативним драйвером ядра Windows NDIS (Windows Defender Firewall) на апаратній швидкості мережевого стека без використання проміжних користувацьких проксі. OmniEye лише налаштовує правила та політики ядра, не створюючи додаткового навантаження при передачі пакетів.

---

<p align="center">
  <sub>Розроблено з турботою про приватність та максимальну безпеку кінцевих точок Windows.</sub>
</p>
