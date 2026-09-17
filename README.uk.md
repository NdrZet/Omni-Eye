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
  - [3.7. Нативний модуль обходу DPI (Native Zapret Engine)](#37-нативний-модуль-обходу-dpi-native-zapret-engine)
  - [3.8. Менеджер безпечного DNS та Windows 11 DoH](#38-менеджер-безпечного-dns-та-windows-11-doh)
  - [3.9. Монітор активних мережевих сокетів (Network Monitor)](#39-монітор-активних-мережевих-сокетів-network-monitor)
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
* **Нативний обхід DPI & DoH:** вбудований ізольований модуль `OmniEye.DpiBypass` забезпечує десинхронізацію пакетів (Discord голосовий зв'язок, YouTube) та захищений DNS без впливу на чистоту ядра безпеки.

---

## 2. Архітектура рішення

Рішення складається з 5 модульних проєктів у межах єдиного рішення .NET 10 (`OmniEye.slnx`):

```
OmniEye/
├── OmniEye.slnx                        # Файл конфігурації рішення (.NET CLI)
├── OmniEye.Core/                      # Чисте ядро безпеки, криптографії та IPC
│   ├── Configuration/                 # Моделі конфігурації (OmniEyeConfig)
│   ├── Models/                        # DTO-контракти повідомлень IPC та сутності БД
│   ├── Security/                      # WinVerifyTrust, DPAPI, NtDll P/Invoke, NTFS ACL
│   ├── Storage/                       # SQLite + SQLCipher AES-256 (БД налаштувань та білого списку)
│   └── Ipc/                           # Асинхронний клієнт іменованих каналів (IpcClient)
├── OmniEye.DpiBypass/                 # Ізольований нативний модуль обходу DPI та DNS
│   ├── Zapret/                        # Native Zapret Engine (winws.exe, WinDivert, 22 пресети, Discord UDP)
│   ├── Dns/                           # SystemDnsManager (адаптери Windows, Win11 DoH, Safe Rollback)
│   ├── Models/                        # DTO серверів DoH та конфігурації
│   ├── Proxy/                         # Локальний HTTP CONNECT DPI-проксі
│   └── Tls/                           # TLS ClientHello SNI парсер та розрахунок фрагментації
├── OmniEyeSvc/                        # Фонова служба Windows підвищених привілеїв (SYSTEM)
│   ├── Network/                       # COM INetFwPolicy2, керування правилами, Self-Healing Watchdog
│   ├── Monitor/                       # Microsoft ETW Kernel Process/Thread/Image TraceEvent
│   ├── Ipc/                           # Сервер іменованих каналів (PipeSecurity ACL)
│   ├── appsettings.json               # Параметри конфігурації служби
│   ├── Worker.cs                      # Фонова служба Microsoft.Extensions.Hosting
│   └── Program.cs                     # Точка входу служби Windows
├── OmniEyeTray/                       # GUI трею в стилі Windows 11 Fluent Design
│   ├── Views/                         # Вікна інтерфейсу (MainWindow, CompanionDiscovery, Підсторінки)
│   ├── Services/                      # LocalizationManager (5 мов), NetworkMonitorService
│   ├── Localization/                  # Словники (uk-UA, en-US, ru-RU, de-DE, ja-JP)
│   ├── App.xaml                       # Ініціалізація теми WPF-UI та PerMonitorV2 DPI
│   ├── app.manifest                   # Маніфест DPI-Awareness (PerMonitorV2)
│   └── MainWindow.xaml.cs             # Логіка трею, динамічної фільтрації, пресетів та DoH
└── OmniEye.Tests/                     # Комплекс наскрізних автоматизованих тестів
    └── Program.cs                     # 14 ізольованих тестів для перевірки всіх рівнів
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

### 3.7. Нативний модуль обходу DPI (Native Zapret Engine)

Для забезпечення безперервного доступу до мережевих сервісів (включно з Discord та YouTube) в умовах глибокої інспекції пакетів (DPI) у проєкт інтегровано ізольований нативний модуль `OmniEye.DpiBypass`:
* **Ядерне перехоплення пакетів:** використовується нативний драйвер `WinDivert64.sys` та процес `winws.exe`, які функціонують на рівні мережевого стека Windows (L3/L4).
* **Голосові канали Discord WebRTC:** спеціалізована фільтрація та підміна UDP-трафіку (`--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=ACTIVE_DISCORD_UDP.bin`), що відновлює стабільність голосового зв'язку.
* **Десинхронізація HTTPS / TLS ClientHello:** фрагментація та перекриття послідовностей TCP (multisplit, seqovl) за списками `list-general.txt` та `list-google.txt`.
* **22 стратегії Flowseal:** у консоль винесено селектор пресетів (`General`, `ALT1-13`, `SIMPLE FAKE`, `FAKE TLS AUTO`, `EXP`) для вибору оптимального профілю під будь-якого провайдера.
* **Надійне завершення через Windows JobObject:** процес `winws.exe` прив'язано до Win32 Job Object із прапорцем `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. При виході або аварійному завершенні програми драйвер та процес негайно вивантажуються з пам'яті.

### 3.8. Редактор кастомних списків доменів (Custom Domain Lists Editor)

Інтерактивний редактор списків доменів на сторінці обходу блокувань дозволяє керувати правилами десинхронізації безпосередньо з графічного інтерфейсу:
* **Керування списками без редагування файлів:** швидке перемикання між списками `list-general.txt` (загальний), `list-google.txt` (YouTube та сервіси Google) і `list-exclude.txt` (винятки) через сегментовані вкладки.
* **Подвійний режим відображення (Елементи vs Блокнот):**
  * **Режим «Елементи»:** візуальні інтерактивні картки з кнопками видалення (`✕`), рядок швидкого додавання та живий пошук за підрядком.
  * **Режим «Блокнот»:** вбудований моноширинний повнотекстовий редактор (Consolas, темна тема, смуги прокручування) для пакетної вставки десятків/сотень рядків, підтримки коментарів (`#`, `;`) і довільного редагування списку.
* **Інтеграція із зовнішнім «Блокнотом Windows»:** кнопка швидкого відкриття обраного файлу хостлиста безпосередньо в нативному `notepad.exe` з автозбереженням і синхронізацією.
* **Інтелектуальна нормалізація та валідація:** автоматичне очищення протоколів (`http://`, `https://`), портів, шляхів, параметрів запитів та валідація формату доменних імен із підтримкою масок `^` та `*.`.
* **Гаряче перезавантаження (Hot-Reload):** при збереженні змін активний процес `winws.exe` миттєво перезапускається з новими списками без переривання роботи GUI.
* **Імпорт, експорт та синхронізація:** експорт у текстові файли, пакетний імпорт сторонніх списків з автоматичною дедуплікацією та завантаження оновлень зі спільноти в 1 клік.
* **Живий пошук та динамічний лічильник:** миттєва фільтрація за підрядком і бейдж із загальною кількістю активних правил.

### 3.9. Менеджер безпечного DNS та Windows 11 DoH

Компонент `SystemDnsManager` автоматизує налаштування системних DNS-серверів:
* **Автоматичне підключення:** під час увімкнення обходу активні фізичні адаптери (Ethernet, Wi-Fi) автоматично перемикаються на безпечні резолвери (Cloudflare `1.1.1.1` / `1.0.0.1`, Google, Quad9, AdGuard).
* **Нативне шифрування Windows 11 DoH:** реєстрація шаблонів шифрування через `netsh dns add encryption` вмикає системний протокол DNS-over-HTTPS із автоматичним оновленням (`autoupgrade=yes udpfallback=yes`).
* **Монітор резолверів DoH:** перевірка доступності та затримки (ping) у реальному часі з можливістю перемикання провайдера в 1 клік.
* **Гарантований відкат (Safe Rollback):** поточна конфігурація адаптерів (DHCP або статичні IP) зберігається в пам'яті та безпечно відновлюється при вимкненні, закритті додатку або через хук `AppDomain.CurrentDomain.ProcessExit`.

### 3.10. Монітор активних мережевих сокетів (Network Monitor)

Вбудований мережевий монітор забезпечує повну прозорість з'єднань в операційній системі:
* **Інспекція сокетів:** безперервне опитування таблиці з'єднань TCP/UDP (`GetExtendedTcpTable`, `GetExtendedUdpTable`).
* **Атрибуція процесів:** зіставлення сокетів із PID, шляхом до бінарного файлу та статусом відповідності політиці Zero-Trust.
* **Додавання в 1 клік:** можливість авторизувати виявлену програму до Білого списку безпосередньо з таблиці монітора.

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

## 7. Упаковка, розповсюдження та встановлення служби Windows

Проєкт підтримує два формати розповсюдження: **єдиний `.exe` інсталятор** та **портативний ZIP-дистрибутив**.

### 1. Встановлення через єдиний інсталятор (`OmniEye-Setup-win-x64.exe`):
Найпростіший та рекомендований спосіб розгортання для користувачів:
* Завантажте та запустіть `OmniEye-Setup-win-x64.exe`.
* Майстер встановлення рідною мовою (українська, англійська, польська/німецька тощо):
  * Розпаковує службу та інтерфейс у `C:\Program Files\OmniEye\`.
  * Автоматично реєструє та запускає службу `OmniEyeSvc` у Windows Service Control Manager.
  * Створює ярлики в меню «Пуск» та на Робочому столі.
  * Опціонально додає інтерфейс Tray до автозапуску Windows (`Run`).
  * Реєструє коректний деінсталятор у меню «Параметри ➔ Програми» Windows.
* **Тихе корпоративне встановлення:**
  ```cmd
  OmniEye-Setup-win-x64.exe /VERYSILENT /NORESTART
  ```

---

### 2. Автоматичне збирання всіх дистрибутивів в 1 клік (`package.ps1`):
У корінь репозиторію додано універсальний скрипт пакування:
```powershell
powershell -ExecutionPolicy Bypass -File package.ps1
```
Скрипт автоматично виконує:
1. Очищення артефактів у каталозі `publish\`.
2. Публікацію служби `OmniEyeSvc` у `publish\OmniEye\Service\`.
3. Публікацію інтерфейсу `OmniEyeTray` з усіма нативними бібліотеками, драйвером `WinDivert64.sys` та пресетами Zapret у `publish\OmniEye\Tray\`.
4. Генерацію батників керування `InstallService.bat`, `UninstallService.bat`, `StartOmniEye.bat`.
5. Стиснення у портативний ZIP-архів `publish\OmniEye-Release-win-x64.zip`.
6. Компіляцію єдиного інсталятора `publish\OmniEye-Setup-win-x64.exe` через Inno Setup Compiler (`ISCC.exe`).

---

### 3. Ручна публікація Release-складання:
```powershell
dotnet publish OmniEyeSvc\OmniEyeSvc.csproj -c Release -o publish\OmniEye\Service
dotnet publish OmniEyeTray\OmniEyeTray.csproj -c Release -o publish\OmniEye\Tray
```

### 4. Ручна реєстрація служби Windows (портативний режим):
* **Через командний файл:** натисніть правою кнопкою миші на `InstallService.bat` у розпакованій папці ➔ *«Запуск від імені адміністратора»*.
* **Вручну через `sc.exe` (від імені Адміністратора):**
  ```cmd
  sc.exe create OmniEyeSvc binPath= "C:\Program Files\OmniEye\Service\OmniEyeSvc.exe" start= auto DisplayName= "OmniEye Zero-Trust Service"
  sc.exe description OmniEyeSvc "Ядро захисту від ексфільтрації даних та мережевий екран Zero-Trust."
  sc.exe start OmniEyeSvc
  ```

### 5. Керування службою:
```cmd
sc.exe stop OmniEyeSvc
sc.exe delete OmniEyeSvc
```

### 6. Додавання інтерфейсу Tray в автозапуск (для портативної версії):
Створіть ярлик для `Tray\OmniEyeTray.exe` у папці автозавантаження Windows (`Win + R` ➔ `shell:startup`).

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

[PASS] TEST 1: DPAPI Key Management & SQLCipher Encryption
[PASS] TEST 2: Authenticode Signature Verification (WinVerifyTrust)
[PASS] TEST 3: Process Freeze & Resume (NtSuspendProcess / NtResumeProcess)
[PASS] TEST 4: Named Pipe IPC Server/Client Protocol & Security Prompts
[PASS] TEST 5: DeveloperMode Lifecycle & Graceful Rollback
[PASS] TEST 6: Dynamic Firewall Policy Switching via IPC
[PASS] TEST 7: Active Network Connection Monitoring & Process Attribution
[PASS] TEST 8: DNS RFC 1035 Wire-Format Serialization & Response Parsing
[PASS] TEST 9: TLS ClientHello SNI Extraction & Fragmentation Offset Calculation
[PASS] TEST 10: Multi-Resolver DoH Pool with Concurrent Race & Caching
[PASS] TEST 11: DPI HTTP CONNECT Proxy Server & ClientHello Fragmentation Pipeline
[PASS] TEST 12: Windows System Proxy WinINet Registry & Automatic Restoration
[PASS] TEST 13: Zapret Native Engine Assets & Command-Line Arguments Verification
[PASS] TEST 14: System DNS & Windows 11 Native DoH Configuration Manager
[PASS] TEST 15: DomainListManager File Persistence, Sanitization & Import/Export
       -> Testing Domain Sanitization & Edge Cases...
       -> Testing Domain List Persistence & Deduplication...
       -> Testing Export to text file...
       -> Testing Import from text file...
       -> Testing Multiline Notepad Raw Text Parsing...
       -> Testing ZapretEngine.Restart() non-crashing invocation...
       -> DomainListManager & Hot-Reload verified successfully.

------------------------------------------------------------------
 ALL 15 TESTS PASSED SUCCESSFULLY! (0 Failures)
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
