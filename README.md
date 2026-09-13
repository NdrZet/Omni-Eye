# OmniEye — Zero-Trust Anti-Exfiltration & Endpoint Protection System

<p align="center">
  <b>Language:</b> 
  <b>🇷🇺 Русский</b> • 
  <a href="README.en.md">🇬🇧 English</a> • 
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

**OmniEye** — высокопроизводительная система эндпоинт-защиты и предотвращения эксфильтрации данных (Anti-Data Exfiltration System), спроектированная на базе модели **Zero-Trust** для операционной системы Windows.

Система реализует принцип **«Никогда не доверяй, всегда проверяй» (Never Trust, Always Verify)** на сетевом и процессном уровнях: весь исходящий сетевой трафик по умолчанию блокируется на уровне ядра NDIS, а память доверенных процессов находится под непрерывной защитой ядра ETW с мгновенной заморозкой процессов-атакующих через нативные вызовы `ntdll.dll`.

---

## 📑 Содержание

- [1. Концепция и модель угроз](#1-концепция-и-модель-угроз)
- [2. Архитектура решения](#2-архитектура-решения)
- [3. Ключевые подсистемы](#3-ключевые-подсистемы)
  - [3.1. Сетевой фильтр (Network Enforcer) & Выбор политики](#31-сетевой-фильтр-network-enforcer--выбор-политики)
  - [3.2. Монитор ядра и защита памяти (Anti-Injection Kernel Monitor)](#32-монитор-ядра-и-защита-памяти-anti-injection-kernel-monitor)
  - [3.3. Групповое обнаружение компонентов (Companion Discovery)](#33-групповое-обнаружение-компонентов-companion-discovery)
  - [3.4. Аппаратная криптография и харденинг БД](#34-аппаратная-криптография-и-харденинг-бд)
  - [3.5. Верификатор цифровых подписей (Authenticode Verifier)](#35-верификатор-цифровых-подписей-authenticode-verifier)
  - [3.6. Нативный интерфейс Windows 11 Fluent Design](#36-нативный-интерфейс-windows-11-fluent-design)
- [4. Протокол межпроцессного взаимодействия (IPC)](#4-протокол-межпроцессного-взаимодействия-ipc)
- [5. Режимы работы (Developer Mode vs Strict)](#5-режимы-работы-developer-mode-vs-strict)
- [6. Быстрый старт и сборка](#6-быстрый-старт-и-сборка)
- [7. Установка службы Windows](#7-установка-службы-windows)
- [8. Автоматизированный тестовый комплекс](#8-автоматизированный-тестовый-комплекс)
- [9. Часто задаваемые вопросы (FAQ)](#9-часто-задаваемые-вопросы-faq)

---

## 1. Концепция и модель угроз

Традиционные антивирусы (EDR/EPP) преимущественно полагаются на базы сигнатур, пост-фактум эвристику и поведенческий анализ. Однако современные вредоносные программы (инфостилеры, шпионское ПО, бэкдоры, RAT, C2-агенты Cobalt Strike / Sliver / Havoc):
1. **Обходят фарватер инспекции:** используют легитимные процессы Windows для внедрения кода (Process Hollowing, DLL Sideloading, Thread Hijacking).
2. **Мгновенно эксфильтруют секреты:** похищают сессионные токены, пароли из диспетчеров паролей, ключи SSH/GPG и базы данных браузеров через незаметные исходящие соединения по портам 443/80/8080.

### Подход OmniEye:
* **Сетевая изоляция:** по умолчанию ни одна программа на компьютере не имеет права отправлять байты во внешнюю сеть. Исходящий стек брандмауэра переведен в режим `BLOCK`.
* **Белый список Authenticode:** сетевой доступ предоставляется исключительно проверенным исполняемым файлам, подтвержденным сертификатом разработчика и зафиксированным в защищенной базе.
* **Freeze & Prompt:** при обнаружении несанкционированного воздействия на память доверенного процесса ядро моментально замораживает атакующий поток до принятия решения администратором.

---

## 2. Архитектура решения

Решение структурировано на 4 специализированных проекта в едином .NET 10 Solution (`OmniEye.slnx`):

```
OmniEye/
├── OmniEye.slnx                        # Решение Visual Studio / .NET CLI
├── OmniEye.Core/                      # Ядро криптографии, безопасности и протокола IPC
│   ├── Configuration/                 # Модели конфигурации (OmniEyeConfig)
│   ├── Models/                        # DTO-контракты IPC и сущности БД (WhitelistEntry)
│   ├── Security/                      # WinVerifyTrust, DPAPI, NtDll P/Invoke, NTFS ACL
│   ├── Storage/                       # SQLite + SQLCipher AES-256 с файловым локом
│   └── Ipc/                           # Асинхронный клиент именованных каналов (IpcClient)
├── OmniEyeSvc/                        # Фоновая служба Windows повышенных привилегий (SYSTEM)
│   ├── Network/                       # COM INetFwPolicy2, сетевые правила, Self-Healing Watchdog
│   ├── Monitor/                       # Microsoft ETW Kernel Process/Thread/Image TraceEvent
│   ├── Ipc/                           # Named Pipe Server (PipeSecurity ACL)
│   ├── appsettings.json               # Параметры конфигурации службы
│   ├── Worker.cs                      # Фоновый сервис Microsoft.Extensions.Hosting
│   └── Program.cs                     # Точка входа службы Windows
├── OmniEyeTray/                       # GUI трея в стиле Windows 11 Fluent Design
│   ├── Views/                         # Окна интерфейса (MainWindow, Dialogs)
│   ├── Models/                        # ViewModel обнаруженных модулей
│   ├── App.xaml                       # Инициализация стилей WPF-UI и PerMonitorV2 DPI
│   ├── app.manifest                   # Манифест DPI-Awareness (PerMonitorV2)
│   └── MainWindow.xaml.cs             # Логика трея, фильтрации и переключения политики
└── OmniEye.Tests/                     # Комплекс сквозных автоматических тестов
    └── Program.cs                     # 6 изолированных тестов всех подсистем
```

### Диаграмма взаимодействия компонентов:

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Windows 11 Fluent GUI (OmniEyeTray)               │
 │       [Dashboard]   [Сетевой экран]   [Защита ядра]   [Параметры]      │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ JSON RPC over Named Pipe
                                     │ \\.\pipe\OmniEyePipe (ACL Secured)
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    Фоновая служба (OmniEyeSvc) [SYSTEM]                │
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

## 3. Ключевые подсистемы

### 3.1. Сетевой фильтр (Network Enforcer) & Выбор политики

Сетевой фильтр управляет брандмауэром Windows Defender напрямую через COM-интерфейс `INetFwPolicy2` (`HNetCfg.FwPolicy2` / `HNetCfg.FWRule`):
* **Профили защиты:** настройки применяются синхронно ко всем трем сетевым профилям Windows: `Domain`, `Private` и `Public`.
* **Интерактивный выбор политики:** на странице **«Сетевой экран»** пользователь может в 1 клик переключать режим фильтрации:
  - **`БЛОКИРОВАТЬ ВСЕ (Zero-Trust BLOCK)`** — входящие и исходящие соединения запрещены по умолчанию. Работают только Белый список и системные исключения.
  - **`РАЗРЕШАТЬ ВСЕ (Permissive ALLOW)`** — стандартный сетевой режим. Исходящие соединения разрешены по умолчанию.
* **Системные исключения (System Essentials):**
  - **DNS:** UDP и TCP порт 53 Outbound (`OmniEye-System-DNS-UDP`, `OmniEye-System-DNS-TCP`).
  - **DHCP:** UDP порты 67, 68 Outbound (`OmniEye-System-DHCP`).
  - **Windows Update:** служба `wuauserv` (`OmniEye-System-WindowsUpdate`).
* **Сторожевой таймер (Self-Healing Watchdog):** фоновый таймер (по умолчанию каждые 3000 мс) опрашивает состояние `DefaultOutboundAction`. Если сторонний процесс или малварь попытается отключить блокировку или удалить правила `OmniEye-*`, сторожевой таймер мгновенно возвращает правила на место. При переключении политики в режим `ALLOW` сторожевой таймер временно приостанавливает принудительный откат, уважая выбор пользователя.

### 3.2. Монитор ядра и защита памяти (Anti-Injection Kernel Monitor)

Для защиты целостности процессов от внешнего внедрения кода (DLL Injection, APC Injection, Process Doppelgänging) используется провайдер ядра Windows ETW (`Microsoft-Windows-Kernel-Process`):
1. **Перехват:** служба в реальном времени получает события ядра о создании потоков и загрузке модулей.
2. **Анализ:** если источник пытается модифицировать память процесса, находящегося в Белом списке, срабатывает алгоритм **Freeze & Prompt**.
3. **Заморозка потоков:** через нативный системный вызов ядра `NtSuspendProcess` (библиотека `ntdll.dll`) все потоки атакующего процесса моментально переводятся в состояние ожидания.
4. **Окно тревоги (`PromptDialog`):** в GUI трея открывается topmost-диалог с предупреждением, путями исполняемых файлов, PID источника и цели, а также 60-секундным обратным отсчетом.
5. **Безопасное разрешение:**
   - Если пользователь выбирает **[Убить процесс]** или истекает таймер безопасности (60 сек) — служба уничтожает атакующий процесс через `NtTerminateProcess`.
   - Если пользователь выбирает **[Игнорировать]** — служба возобновляет работу процесса через `NtResumeProcess`.

### 3.3. Групповое обнаружение компонентов (Companion Discovery)

Большинство современных сетевых инструментов (AmneziaVPN, Discord, Google Chrome, Telegram, Visual Studio Code) состоят из нескольких бинарных файлов: основного GUI, фоновой службы (Windows Service), сетевого туннеля (`tun2socks`, `wireguard`, `openvpn`), вспомогательных процессов (helpers) и апдейтеров (`Update.exe`).

При добавлении одного `.exe` файла в Белый список OmniEye:
* Анализирует директорию приложения, подпапки (`bin`, `tap`, `helper`, `proxy`) и родительские каталоги Squirrel-приложений.
* Классифицирует модули по их назначению («Сетевой туннель / VPN», «Фоновая служба», «Служба обновления», «Деинсталлятор»).
* Открывает диалог **`CompanionDiscoveryDialog`**, позволяя добавить всю экосистему приложения в брандмауэр в один клик.
* В интерфейсе дочерние файлы автоматически объединяются в элегантную сворачиваемую карточку (Win11 SettingsExpander) с возможностью пакетного удаления группы.

### 3.4. Аппаратная криптография и харденинг БД

* **Шифрование БД:** База данных `C:\ProgramData\OmniEye\config.db` зашифрована на лету с использованием **SQLCipher AES-256-CBC** (`SQLitePCLRaw.bundle_e_sqlcipher`). Даже заголовок файла (`SQLite format 3`) полностью скрыт за шифротекстом.
* **Аппаратная привязка DPAPI:** 256-битный мастер-ключ шифрования генерируется криптографическим генератором случайных чисел и защищен через **Windows DPAPI** (`DataProtectionScope.LocalMachine`), привязываясь к уникальному TPM/аппаратному профилю данной машины.
* **NTFS Харденинг:** Права доступа на директорию `C:\ProgramData\OmniEye` принудительно ограничиваются через Windows ACL: полный доступ имеют только `SYSTEM` и `Administrators`, обычные пользователи имеют доступ только на чтение без права модификации.
* **Эксклюзивный лок:** Служба удерживает эксклюзивный дескриптор файла (`FileShare.None`) и режим `PRAGMA locking_mode = EXCLUSIVE`, предотвращая подмену или чтение базы сторонними процессами.

### 3.5. Верификатор цифровых подписей (Authenticode Verifier)

Включение исполняемого файла в сетевой Белый список требует подтверждения подлинности:
* Проверка осуществляется через нативную функцию Win32 API `WinVerifyTrust` (`wintrust.dll`) с GUID действия `WINTRUST_ACTION_GENERIC_VERIFY_V2`.
* Поддерживаются как встроенные подписи исполняемых файлов (Embedded Authenticode), так и подписи из системных каталогов безопасности Windows (`.cat` Security Catalogs).
* Из сертификата извлекается субъект издателя (`CN`, организация, страна).
* В боевом режиме (`DeveloperMode = false`) добавление неподписанных программ **категорически заблокировано**.

### 3.6. Нативный интерфейс Windows 11 Fluent Design

Пользовательский интерфейс [OmniEyeTray](file:///d:/SPA_Full/OmniEye/OmniEyeTray) строго следует принципам [Microsoft Windows App Design Guidelines](https://learn.microsoft.com/ru-ru/windows/apps/design/guidelines-overview):
* **Mica Backdrop:** полупрозрачный системный фон Mica (`DwmSetWindowAttribute`, тип `DWMSBT_MAINWINDOW`).
* **TitleBar с интеграцией Snap Layouts:** фирменный заголовок Windows 11 с всплывающей сеткой расположения окон при наведении на кнопку максимизации.
* **Шрифты и рендеринг без артефактов:** аппаратный `ClearType`, субпиксельное сглаживание и `UseLayoutRounding="True"`, устраняющие мыло на любых темных поверхностях.
* **Поддержка PerMonitorV2 High DPI:** приложение содержит декларативный манифест `PerMonitorV2` и инициализирует контекст DPI ядра. При перетаскивании окна между монитором 1080p (100% DPI) и 4K монитором (150%–200% DPI) рендеринг текста и векторных иконок остается бритвенно-четким.
* **Карточки параметров Windows 11:** разделители, округления (`CornerRadius="8"`), мягкие микроанимации при наведении курсора (`IsMouseOver`) и темные скроллбары.

---

## 4. Протокол межпроцессного взаимодействия (IPC)

Общение между системной службой (`OmniEyeSvc`) и интерфейсом трея (`OmniEyeTray`) происходит через именованный канал (Named Pipe) `\\.\pipe\OmniEyePipe`. Безопасность гарантируется дескриптором безопасности `PipeSecurity`:
- `LocalSystem` & `Administrators`: Полный контроль (`FullControl`).
- `Users`: Чтение/Запись сообщений (`ReadWrite`).

### Контракты сообщений (JSON Envelope):

| Тип сообщения (`Type`) | Направление | Назначение |
|:---|:---:|:---|
| `status.request` | Tray ➔ Svc | Запрос состояния службы, счетчиков и режима работы |
| `status.response` | Svc ➔ Tray | Ответ: флаг работы, DevMode, статус брандмауэра, количество блокировок |
| `whitelist.get.request` | Tray ➔ Svc | Запрос полного списка разрешенных программ |
| `whitelist.get.response` | Svc ➔ Tray | Список объектов `WhitelistEntry` (пути, издатели, группы, даты) |
| `whitelist.add.request` | Tray ➔ Svc | Команда добавления `.exe` в Белый список и брандмауэр |
| `whitelist.add.response` | Svc ➔ Tray | Результат верификации подписи и добавления |
| `whitelist.remove.request` | Tray ➔ Svc | Команда удаления файла/группы и отзыва правил Firewall |
| `whitelist.remove.response`| Svc ➔ Tray | Подтверждение удаления |
| `firewall.set_policy.request` | Tray ➔ Svc | Динамическая смена политики по умолчанию (`BlockOutbound`: true/false) |
| `firewall.set_policy.response`| Svc ➔ Tray | Статус переключения политики и текущее состояние брандмауэра |
| `injection.prompt.notification` | Svc ➔ Tray | Широковещательный алерт перехвата инъекции в память |
| `injection.prompt.action` | Tray ➔ Svc | Решение пользователя (`"kill"` или `"ignore"`) |

---

## 5. Режимы работы (Developer Mode vs Strict)

Конфигурационный файл службы расположен по пути `OmniEyeSvc\appsettings.json`:

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

### Сравнение режимов безопасности:

| Характеристика | `DeveloperMode: true` (Тестовый / Разработчик) | `DeveloperMode: false` (Боевой Zero-Trust) |
|:---|:---|:---|
| **Поведение при выходе** | Автоматический откат Firewall в `ALLOW`, удаление правил `OmniEye-*` | Правила брандмауэра остаются активными, изоляция не снимается |
| **Сторожевой таймер** | Отключен (позволяет тестировщикам вручную менять правила сети) | Активен (каждые 3 сек сбрасывает любые сторонние изменения сети) |
| **Неподписанные файлы** | Разрешено добавление с подтверждением пользователя в диалоге | **Запрещено**: отклоняются все файлы без валидной подписи Authenticode |
| **Остановка службы** | Разрешена штатная остановка и освобождение файловых локов | Служба защищена от случайной или принудительной остановки |

---

## 6. Быстрый старт и сборка

### Системные требования:
* Windows 10 (версия 1809+) или Windows 11 (любая редакция x64).
* .NET 10.0 SDK.
* Права локального администратора (для работы фоновой службы брандмауэра и ETW ядра).

### 1. Сборка всего решения:
```powershell
dotnet build OmniEye.slnx -c Release
```

### 2. Запуск в режиме отладки:
В двух отдельных терминалах PowerShell:

* **Терминал 1 (Администратор — Служба):**
  ```powershell
  dotnet run --project OmniEyeSvc\OmniEyeSvc.csproj -c Release
  ```

* **Терминал 2 (Пользователь — Интерфейс трея):**
  ```powershell
  dotnet run --project OmniEyeTray\OmniEyeTray.csproj -c Release
  ```

---

## 7. Установка службы Windows

Для промышленной эксплуатации служба публикуется в виде изолированных бинарных файлов и регистрируется в диспетчере служб Windows (Service Control Manager):

### 1. Публикация Release-сборки:
```powershell
dotnet publish OmniEyeSvc\OmniEyeSvc.csproj -c Release -o publish\OmniEyeSvc
dotnet publish OmniEyeTray\OmniEyeTray.csproj -c Release -o publish\OmniEyeTray
```

### 2. Регистрация службы Windows (`sc.exe` от имени Администратора):
```cmd
sc.exe create OmniEyeSvc binPath= "D:\SPA_Full\OmniEye\publish\OmniEyeSvc\OmniEyeSvc.exe" start= auto DisplayName= "OmniEye Zero-Trust Service"
sc.exe description OmniEyeSvc "Ядро защиты от эксфильтрации данных и сетевой экран Zero-Trust."
sc.exe start OmniEyeSvc
```

### 3. Управление службой:
```cmd
sc.exe stop OmniEyeSvc
sc.exe delete OmniEyeSvc
```

### 4. Добавление Tray в автозапуск пользователя:
Создайте ярлык для `publish\OmniEyeTray\OmniEyeTray.exe` в папке автозагрузки Windows (`Win + R` ➔ `shell:startup`).

---

## 8. Автоматизированный тестовый комплекс

Проект [OmniEye.Tests](file:///d:/SPA_Full/OmniEye/OmniEye.Tests) содержит полный цикл автономных тестов без внешних зависимостей. Для запуска выполните:

```powershell
dotnet run --project OmniEye.Tests\OmniEye.Tests.csproj
```

### Результат выполнения тестов:
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

## 9. Часто задаваемые вопросы (FAQ)

#### Q: Что произойдет с доступом в Интернет, если служба OmniEye будет принудительно завершена?
> **A:** В режиме `DeveloperMode: true` при остановке службы политика автоматически восстанавливается в `DefaultOutboundAction = ALLOW`. В боевом режиме (`DeveloperMode: false`) брандмауэр останется заблокированным в целях безопасности, сохраняя доступ только для системных служб и ранее разрешенных программ. Восстановить стандартный режим брандмауэра вручную можно командой PowerShell (от Администратора):  
> `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`.

#### Q: Почему системные сервисы DNS и DHCP вынесены в системные исключения?
> **A:** Без разрешения протоколов DHCP (UDP 67/68) операционная система не сможет получить локальный IP-адрес от маршрутизатора, а без DNS (UDP/TCP 53) невозможно разрешение доменных имен для всех доверенных приложений. В строгих корпоративных средах порты DNS можно дополнительно привязать к конкретным внутренним IP-адресам DNS-серверов предприятия.

#### Q: Как OmniEye ведет себя при обновлении приложений (например, браузера или Discord)?
> **A:** Модуль **Companion Discovery** автоматически включает вспомогательные процессы обновлений (`Update.exe`) в доверенную группу. При выходе новой версии исполняемого файла, подписанной тем же доверенным сертификатом издателя, правила брандмауэра продолжают действовать бесшовно.

#### Q: Влияет ли OmniEye на игровую производительность или пинг (Latency)?
> **A:** Нет. Блокировка и фильтрация выполняются нативным драйвером ядра Windows NDIS (Windows Defender Firewall) на аппаратной скорости сетевого стека без использования медленных пользовательских прокси (LSP/WFP proxy). OmniEye лишь конфигурирует политики и правила ядра, не создавая накладных расходов в процессе передачи сетевых пакетов.

---

<p align="center">
  <sub>Разработано с заботой о приватности и максимальной безопасности конечных точек Windows.</sub>
</p>