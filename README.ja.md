# OmniEye — ゼロトラスト・データ流出防止およびエンドポイント保護システム

<p align="center">
  <b>Language:</b> 
  <a href="README.md">🇷🇺 Русский</a> • 
  <a href="README.en.md">🇬🇧 English</a> • 
  <a href="README.uk.md">🇺🇦 Українська</a> • 
  <a href="README.de.md">🇩🇪 Deutsch</a> • 
  <b>🇯🇵 日本語</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-10.0%20(LTS)-512BD4?style=for-the-badge&logo=dotnet&logoColor=white" alt=".NET 10" />
  <img src="https://img.shields.io/badge/C%23-13.0-239120?style=for-the-badge&logo=csharp&logoColor=white" alt="C# 13" />
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20x64-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/UI-Windows%2011%20Fluent%20(WPF--UI)-005FB8?style=for-the-badge&logo=fluentui&logoColor=white" alt="Fluent Design" />
  <img src="https://img.shields.io/badge/Crypto-AES--256%20SQLCipher%20%2B%20DPAPI-4E73DF?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLCipher" />
  <img src="https://img.shields.io/badge/Security-Zero--Trust%20NDIS%20Enforcement-D9534F?style=for-the-badge&logo=shield&logoColor=white" alt="Zero-Trust" />
</p>

**OmniEye** は、現代の Microsoft Windows 環境向けに**ゼロトラスト（Zero-Trust）**アーキテクチャに基づいて設計された、高性能エンドポイント保護およびデータ流出防止（Anti-Data Exfiltration）システムです。

本システムは、ネットワークおよびプロセスの両レイヤーにおいて**「決して信頼せず、常に検証せよ」（Never Trust, Always Verify）**という基本原則を徹底します。すべての送信ネットワークトラフィックは NDIS カーネルレベルでデフォルト遮断され、信頼されたプロセスのメモリ領域は Windows カーネル ETW（Event Tracing for Windows）を通じてリアルタイムに監視され、不正なインジェクション攻撃はネイティブな `ntdll.dll` システムコールによって即座に凍結されます。

---

## 📑 目次

- [1. 脅威モデルと設計思想](#1-脅威モデルと設計思想)
- [2. システムアーキテクチャ](#2-システムアーキテクチャ)
- [3. 主要サブシステム](#3-主要サブシステム)
  - [3.1. ネットワークエンフォーサーと動的ポリシー切り替え](#31-ネットワークエンフォーサーと動的ポリシー切り替え)
  - [3.2. カーネルメモリ保護とインジェクション阻止（Freeze & Prompt）](#32-カーネルメモリ保護とインジェクション阻止freeze--prompt)
  - [3.3. コンパニオンコンポーネント自動検出（Companion Discovery）](#33-コンパニオンコンポーネント自動検出companion-discovery)
  - [3.4. ハードウェアバインド暗号化とデータベース堅牢化](#34-ハードウェアバインド暗号化とデータベース堅牢化)
  - [3.5. Authenticode コード署名検証](#35-authenticode-コード署名検証)
  - [3.6. Windows 11 ネイティブ Fluent UI と PerMonitorV2 高DPI対応](#36-windows-11-ネイティブ-fluent-ui-と-permonitorv2-高dpi対応)
  - [3.7. ネイティブ Zapret DPI 回避エンジン](#37-ネイティブ-zapret-dpi-回避エンジン)
  - [3.8. 安全な DNS マネージャーと Windows 11 DoH 連携](#38-安全な-dns-マネージャーと-windows-11-doh-連携)
  - [3.9. リアルタイムネットワークソケットモニター](#39-リアルタイムネットワークソケットモニター)
- [4. プロセス間通信（IPC）プロトコル仕様](#4-プロセス間通信ipcプロトコル仕様)
- [5. 動作モード（開発モード vs 厳格ゼロトラスト）](#5-動作モード開発モード-vs-厳格ゼロトラスト)
- [6. クイックスタートとビルド手順](#6-クイックスタートとビルド手順)
- [7. Windows サービス展開手順](#7-windows-サービス展開手順)
- [8. 自動検証テストスイート](#8-自動検証テストスイート)
- [9. よくある質問（FAQ）](#9-よくある質問faq)

---

## 1. 脅威モデルと設計思想

従来のウイルス対策や EDR 製品は、既知のシグネチャデータベースや事後ヒューリスティック分析に大きく依存しています。しかし、現代のマルウェア（インフォスティーラー、スパイウェア、バックドア、RAT、Cobalt Strike / Sliver などの C2 エージェント）は：
1. **ユーザーランドの検知を回避:** 正当な Windows プロセス内にシェルコードを注入（Process Hollowing、DLL Sideloading、Thread Hijacking、APC Injection）。
2. **瞬時に機密情報を流出:** セッショントークン、ブラウザ内パスワード、SSH/GPG 秘密鍵を、目立たない送信 HTTPS 接続（ポート 443/80/8080）経由で外部 C2 サーバーへ送信。

### OmniEye のアプローチ：
* **送信トラフィックの原則遮断（Default Deny Outbound）:** 初期状態では、システム上で動作するいかなるソフトウェアも外部へのパケット送信を禁止されます。ファイアウォールの送信ポリシーは `BLOCK` に固定されます。
* **Authenticode ホワイトリスト:** 開発元の正規デジタル証明書によって検証され、暗号化データベースに登録された実行ファイルのみに送信アクセス権が与えられます。
* **カーネルフリーズ＆プロンプト（Freeze & Prompt）:** 保護されたプロセスのメモリへの不正アクセスを検知すると、Windows カーネルレベルで攻撃プロセスの全スレッドを即時凍結し、管理者の判断を仰ぎます。
* **ネイティブ DPI 回避 ＆ DoH:** 完全に疎結合された専用モジュール `OmniEye.DpiBypass` により、ゼロトラストコアの純粋性を損なうことなくパケット非同期化（Discord 音声通話、YouTube）と暗号化 DNS を実現します。

---

## 2. システムアーキテクチャ

ソリューションは、統一された .NET 10 ソリューション（`OmniEye.slnx`）下の 5 つのモジュールで構成されています：

```
OmniEye/
├── OmniEye.slnx                        # ソリューション構成ファイル (.NET CLI)
├── OmniEye.Core/                      # 純粋なコア：共通暗号化・セキュリティ・IPC ライブラリ
│   ├── Configuration/                 # 構成モデル (OmniEyeConfig)
│   ├── Models/                        # IPC メッセージ DTO および DB エンティティ
│   ├── Security/                      # WinVerifyTrust、DPAPI、NtDll P/Invoke、NTFS ACL
│   ├── Storage/                       # SQLite + SQLCipher AES-256 (設定とホワイトリスト)
│   └── Ipc/                           # 非同期名前付きパイプクライアント (IpcClient)
├── OmniEye.DpiBypass/                 # 独立したネイティブパケット非同期化・DNS モジュール
│   ├── Zapret/                        # Native Zapret Engine (winws.exe, WinDivert, 22 プリセット, Discord UDP)
│   ├── Dns/                           # SystemDnsManager (アダプター構成, Win11 DoH, Safe Rollback)
│   ├── Models/                        # DoH サーバーモデルと構成
│   ├── Proxy/                         # ローカル HTTP CONNECT DPI プロキシ
│   └── Tls/                           # TLS ClientHello SNI パーサーと分割オフセット計算
├── OmniEyeSvc/                        # 特権 Windows バックグラウンドサービス (SYSTEM)
│   ├── Network/                       # COM INetFwPolicy2、ルール制御、Self-Healing Watchdog
│   ├── Monitor/                       # Microsoft ETW Kernel Process/Thread/Image TraceEvent
│   ├── Ipc/                           # 名前付きパイプサーバー (PipeSecurity ACL)
│   ├── appsettings.json               # サービス構成ファイル
│   ├── Worker.cs                      # Microsoft.Extensions.Hosting バックグラウンドサービス
│   └── Program.cs                     # サービスエントリーポイント (Service Host / Console)
├── OmniEyeTray/                       # Windows 11 Fluent Design システムトレイ GUI
│   ├── Views/                         # UI ビュー (MainWindow、CompanionDiscovery、サブページ)
│   ├── Services/                      # LocalizationManager (5 言語), NetworkMonitorService
│   ├── Localization/                  # 多言語辞書 (ja-JP, en-US, ru-RU, uk-UA, de-DE)
│   ├── App.xaml                       # WPF-UI テーマおよび PerMonitorV2 初期化
│   ├── app.manifest                   # PerMonitorV2 DPI 対応宣言マニフェスト
│   └── MainWindow.xaml.cs             # トレイ制御、リアルタイム検索、プリセットおよび DoH
└── OmniEye.Tests/                     # 自律型自動検証テストスイート
    └── Program.cs                     # 全レイヤーを検証する 14 の統合テスト
```

### コンポーネント間連携図：

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Windows 11 Fluent GUI (OmniEyeTray)               │
 │       [ホーム]         [ファイアウォール]   [カーネル保護]    [設定]        │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ JSON RPC over Named Pipe
                                     │ \\.\pipe\OmniEyePipe (ACL 保護)
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                   バックグラウンドサービス (OmniEyeSvc) [SYSTEM]         │
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
 │ Firewall (NDIS フィルタ)│   │ Process/Thread Events │         │
 └─────────────────────────┘   └───────────────────────┘         │
                                                                 ▼
                                                ┌─────────────────────────┐
                                                │ AES-256 SQLCipher DB    │
                                                │ Windows DPAPI Machine   │
                                                │ 排他ファイルロック      │
                                                └─────────────────────────┘
```

---

## 3. 主要サブシステム

### 3.1. ネットワークエンフォーサーと動的ポリシー切り替え

COM インターフェース `INetFwPolicy2`（`HNetCfg.FwPolicy2` / `HNetCfg.FWRule`）を介して Windows Defender ファイアウォールを直接制御します：
* **プロファイル完全同期:** 設定は 3 つの Windows ファイアウォールプロファイル（`Domain`、`Private`、`Public`）すべてに一括適用されます。
* **動的ポリシー切り替え:** **「Сетевой экран」（ファイアウォール）**タブにて、ワンクリックでデフォルトの遮断方針を切り替えることが可能です：
  - **`遮断（Zero-Trust BLOCK）`** — 送信接続をデフォルト拒否。ホワイトリストおよび必須システム例外のみ通信可能。
  - **`許可（Permissive ALLOW）`** — 標準的なネットワーク動作。全アプリケーションの送信通信をデフォルト許可。
* **システム必須例外（System Essentials）:**
  - **DNS:** 送信 UDP/TCP ポート 53（`OmniEye-System-DNS-UDP`、`OmniEye-System-DNS-TCP`）。
  - **DHCP:** 送信 UDP ポート 67、68（`OmniEye-System-DHCP`）。
  - **Windows Update:** `wuauserv` サービスルール（`OmniEye-System-WindowsUpdate`）。
* **自己修復監視タイマー（Self-Healing Watchdog）:** 3000ms ごとにポリシー整合性を検証。外部ツールや不正ソフトウェアによってルールが改ざんされた場合、即座にルールを再生成します。ユーザーが明示的に `ALLOW` を選択した際は、監視タイマーは自動的に一時停止し設定を尊重します。

### 3.2. カーネルメモリ保護とインジェクション阻止（Freeze & Prompt）

プロセスへの不正なコード注入（DLL Injection、APC Injection、Process Doppelgänging）を防ぐため、カーネル ETW プロバイダー `Microsoft-Windows-Kernel-Process` を購読します：
1. **イベント検知:** スレッド生成やモジュール読み込みイベントをリアルタイムに監視。
2. **検知判定:** ホワイトリストに登録されたアプリケーションへの不正アクセスを検知すると、**Freeze & Prompt** アルゴリズムをトリガー。
3. **スレッド瞬時凍結:** `ntdll.dll` のネイティブシステムコール `NtSuspendProcess` を呼び出し、攻撃元プロセスの全実行スレッドを即時停止。
4. **アラートダイアログ（`PromptDialog`）:** 呼び出し元のパス、PID、標的プロセスの情報、および 60 秒のカウントダウンタイマーを最前面に表示。
5. **安全な解決:**
   - ユーザーが**［プロセスを強制終了］**を選択するか、60 秒が経過すると、`NtTerminateProcess` によりプロセスを強制終了。
   - ユーザーが**［無視］**を選択すると、`NtResumeProcess` により実行を再開。

### 3.3. コンパニオンコンポーネント自動検出（Companion Discovery）

現代の複雑なソフトウェア（VPN クライアント、ブラウザ、Discord、IDE など）は、メイン GUI、Windows サービス、ネットワークトンネル（`tun2socks`、`wireguard`、`openvpn`）、ヘルパー、アップデーター（`Update.exe`）など多数のバイナリで構成されています。

OmniEye はメイン `.exe` の選択時に：
* アプリケーションディレクトリ、サブフォルダ（`bin`、`tap`、`helper`、`proxy`）、Squirrel 親フォルダを再帰的にスキャン。
* 役割を自動判別（「ネットワークトンネル / VPN」、「バックグラウンドサービス」、「アップデーター」、「アンインストーラー」）。
* **`CompanionDiscoveryDialog`** を表示し、関連モジュール一式をワンクリックで一括ホワイトリスト登録。
* Windows 11 `SettingsExpander` カードにグループ化され、一括管理および一括削除が可能です。

### 3.4. ハードウェアバインド暗号化とデータベース堅牢化

* **透過的暗号化:** データベースファイル `C:\ProgramData\OmniEye\config.db` は、**SQLCipher AES-256-CBC** によりオンザフライ暗号化されます。SQLite ヘッダー（`SQLite format 3`）すら完全に暗号化されます。
* **DPAPI ハードウェアバインド:** 暗号化マスターキーは、**Windows DPAPI**（`DataProtectionScope.LocalMachine`）を用いて保護され、マシンの TPM およびハードウェア固有プロファイルにバインドされます。
* **NTFS アクセス権の厳格化:** `C:\ProgramData\OmniEye` に対し、`SYSTEM` と `Administrators` のみ完全制御権（`FullControl`）を持ち、一般ユーザーは読み取り専用に制限されます。
* **排他ファイルロック:** サービス実行中は `FileShare.None` および `PRAGMA locking_mode = EXCLUSIVE` により排他ロックを保持し、改ざんを完全に防ぎます。

### 3.5. Authenticode コード署名検証

* Win32 API `WinVerifyTrust`（`wintrust.dll`、GUID `WINTRUST_ACTION_GENERIC_VERIFY_V2`）を用いて検証を実施。
* 埋め込み Authenticode 署名および Windows セキュリティカタログ（`.cat`）署名の双方に対応。
* 発行者情報（CN、組織名、国コード）を抽出・記録。
* 本番運用モード（`DeveloperMode = false`）では、未署名または改ざんされたバイナリは**一切登録できません**。

### 3.6. Windows 11 ネイティブ Fluent UI と PerMonitorV2 高DPI対応

[OmniEyeTray](file:///d:/SPA_Full/OmniEye/OmniEyeTray) は [Microsoft Windows アプリ設計ガイドライン](https://learn.microsoft.com/ja-jp/windows/apps/design/guidelines-overview) に完全準拠しています：
* **Mica マテリアル:** DWM API を使用した半透明のネイティブ Mica 背景（`DWMSBT_MAINWINDOW`）。
* **Snap Layouts 対応 TitleBar:** 最大化ボタンにカーソルを合わせた際に Windows 11 標準のスナップレイアウトが展開。
* **サブピクセル描画:** `ClearType`、`UseLayoutRounding="True"` により、ダークテーマ上での文字ボケを完全排除。
* **PerMonitorV2 高DPI対応:** アプリケーションマニフェストおよび `SetProcessDpiAwarenessContext` による初期化により、1080p（100%）と 4K（150%〜200%）モニター間をドラッグ移動しても文字やベクターアイコンが一切ぼやけません。
* **Windows 11 設定カード:** 明確な区切り線、丸みを帯びた角（`CornerRadius="8"`）、滑らかなマウスホバー状態（`IsMouseOver`）、ダークスクロールバー。

### 3.7. ネイティブ Zapret DPI 回避エンジン

DPI（ディープパケットインスペクション）環境下でも Discord 音声通信や YouTube などの重要なネットワーク通信を安定して維持するため、分離されたネイティブモジュール `OmniEye.DpiBypass` が組み込まれています：
* **カーネルレベルのパケット傍受:** L3/L4 で動作するネイティブドライバー `WinDivert64.sys` と `winws.exe` プロセスを活用。
* **Discord WebRTC 音声チャンネルの非同期化:** 特化した UDP フィルタリングと偽装ペイロード置換（`--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=ACTIVE_DISCORD_UDP.bin`）により、音声通話の安定性を回復。
* **HTTPS / TLS ClientHello の非同期化:** `list-general.txt` および `list-google.txt` に対する TCP パケット分割（multisplit）とシーケンス重複（seqovl）。
* **22 種類の Flowseal プリセット:** GUI 上にプリセット選択ドロップダウン（`General`, `ALT1-13`, `SIMPLE FAKE`, `FAKE TLS AUTO`, `EXP`）を備え、任意のプロバイダーに合わせた最適戦略へ瞬時に切り替え可能。
* **Windows JobObject による安全なライフサイクル管理:** `winws.exe` は `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` を備えた Win32 Job Object にバインド。アプリ終了時や予期せぬクラッシュ時でも、ドライバーとプロセスが確実に即時クリーンアップされます。

### 3.8. カスタムドメインリストエディター (Custom Domain Lists Editor)

DPI 回避ページ内に統合されたインタラクティブなドメインリストエディターにより、GUI 上から直接ホストリストルールを管理できます：
* **ファイル直接編集不要のリスト管理:** セグメント化されたタブから `list-general.txt`（一般リスト）、`list-google.txt`（YouTube & Google 関連）、`list-exclude.txt`（除外リスト）を 1 クリックで切り替え。
* **デュアル表示モード（カード表示 vs メモ帳テキスト表示）:**
  * **「アイテム」モード:** 個別削除ボタン（`✕`）付きの視覚的カード、迅速なドメイン追加バー、部分一致検索フィルター。
  * **「メモ帳」モード:** 内蔵の等幅フルテキストエディター（Consolas、ダークテーマ、スクロールバー完備）。数十〜数百件のドメインの一括貼り付け、コメント行（`#`, `;`）の自由な記述、ダイレクト編集に対応。
* **Windows 標準「メモ帳」との連携:** 「Windows メモ帳で開く」ボタンにより、対象リストファイルを OS ネイティブの `notepad.exe` で直接開いて編集・同期可能。
* **高機能なドメイン正規化 & 検証:** 入力された URL からプロトコル（`http://`, `https://`）、パス、ポート、クエリパラメータを自動除去し、FQDN 書式を検証。Zapret の `^` や `*.` ワイルドカードにも完全対応。
* **瞬時のホットリロード (Hot-Reload):** 変更保存時、稼働中の `winws.exe` プロセスが 200ms 未満で自動再起動され、GUI の状態を維持したまま新ルールが即時適用。
* **インポート、エクスポート & コミュニティ同期:** テキストファイルへの書き出し、重複自動排除付きの一括インポート、オープンリポジトリからの最新ルール取得を 1 クリックで実行。
* **リアルタイム検索 & 動的カウントバッジ:** 部分一致による瞬時絞り込み検索と、登録された有効ルール総数をリアルタイム表示。

### 3.9. 安全な DNS マネージャーと Windows 11 DoH 連携

`SystemDnsManager` サブシステムがホストの DNS 設定を自動化します：
* **自動アダプター設定:** 回避起動時、アクティブな物理アダプター（Ethernet、Wi-Fi）に検閲のない安全な DNS（Cloudflare `1.1.1.1` / `1.0.0.1`, Google, Quad9, AdGuard）を自動構成。
* **Windows 11 ネイティブ DoH 暗号化:** `netsh dns add encryption` を通じてテンプレートを登録し、自動アップグレード（`autoupgrade=yes udpfallback=yes`）による DNS-over-HTTPS を有効化。
* **リアルタイム DoH モニター:** 応答速度（Ping）の監視と、一覧テーブルからの 1 クリックプロバイダー切り替え。
* **確実な設定復元（Safe Rollback）:** 変更前の元設定（DHCP または固定 DNS）をバックアップし、停止時やアプリ終了時に元の状態へ確実にロールバック。

### 3.10. リアルタイムネットワークソケットモニター

インタラクティブなネットワークモニターにより、ホストの全ネットワーク通信を可視化します：
* **ソケットの常時監視:** `GetExtendedTcpTable` / `GetExtendedUdpTable` による TCP/UDP 通信のリアルタイム一覧表示。
* **プロセス属性の紐付け:** ソケットとプロセス ID（PID）、実行ファイルパス、ゼロトラストポリシー適用状態の自動関連付け。
* **1 クリック許可:** 検出された通信から直接ホワイトリストへ追加し、コンパニオンコンポーネントを自動検出。

---

## 4. プロセス間通信（IPC）プロトコル仕様

特権サービス（`OmniEyeSvc`）とトレイ GUI（`OmniEyeTray`）間の通信は、セキュリティ記述子 `PipeSecurity` で保護された名前付きパイプ `\\.\pipe\OmniEyePipe` を介して行われます：
- `LocalSystem` & `Administrators`: フルコントロール（`FullControl`）。
- `Users`: メッセージの読み書き（`ReadWrite`）。

### IPC メッセージエンベロープ仕様：

| メッセージタイプ (`Type`) | 方向 | 役割 |
|:---|:---:|:---|
| `status.request` | Tray ➔ Svc | サービス稼働状態、稼働時間、動作フラグの照会 |
| `status.response` | Svc ➔ Tray | 応答：稼働フラグ、DevMode、ファイアウォール状態、遮断カウンタ |
| `whitelist.get.request` | Tray ➔ Svc | 登録済みホワイトリスト全件の取得要求 |
| `whitelist.get.response` | Svc ➔ Tray | `WhitelistEntry` オブジェクト一覧（パス、署名者、グループ、日時） |
| `whitelist.add.request` | Tray ➔ Svc | アプリケーションのホワイトリスト追加とファイアウォールルール生成 |
| `whitelist.add.response` | Svc ➔ Tray | 署名検証結果およびルール追加ステータス |
| `whitelist.remove.request` | Tray ➔ Svc | エントリ/グループの削除およびルールの失効要求 |
| `whitelist.remove.response`| Svc ➔ Tray | 削除完了の応答 |
| `firewall.set_policy.request` | Tray ➔ Svc | 送信ポリシーの動的切り替え（`BlockOutbound`: true/false） |
| `firewall.set_policy.response`| Svc ➔ Tray | ポリシー切り替え結果および適用状態の確認応答 |
| `injection.prompt.notification` | Svc ➔ Tray | メモリインジェクション検知時のブロードキャスト通知 |
| `injection.prompt.action` | Tray ➔ Svc | ユーザーの対処決定（`"kill"` または `"ignore"`） |

---

## 5. 動作モード（開発モード vs 厳格ゼロトラスト）

サービス設定は `OmniEyeSvc\appsettings.json` にて定義されます：

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

### 動作モード比較表：

| 機能 | `DeveloperMode: true`（開発・テストモード） | `DeveloperMode: false`（本番ゼロトラスト） |
|:---|:---|:---|
| **終了時の挙動** | ファイアウォールを自動で `ALLOW` に復元し、`OmniEye-*` ルールを削除 | ファイアウォールは遮断状態を維持し、通信の隔離を継続 |
| **自己修復監視** | 一時停止（エンジニアによる手動のネットワーク検証を許容） | 有効（改ざんされた設定を 3000ms ごとに自動復旧） |
| **未署名ファイル** | 確認ダイアログによるユーザー承認の上で追加可能 | **厳格に拒否**: 有効な署名のないファイルは一切追加不可 |
| **サービス停止** | 正常停止が可能で、ファイルロックを解放 | サービスは偶発的または強制的な終了から保護 |

---

## 6. クイックスタートとビルド手順

### 前提要件：
* Windows 10（ビルド 1809 以降）または Windows 11（全エディション、x64）。
* .NET 10.0 SDK。
* ローカル管理者権限（ファイアウォールおよびカーネル ETW サービスの制御に必要）。

### 1. ソリューション全体のビルド：
```powershell
dotnet build OmniEye.slnx -c Release
```

### 2. デバッグモードでの実行：
2 つの独立した PowerShell ウィンドウを起動します：

* **ウィンドウ 1（管理者として実行 — バックグラウンドサービス）：**
  ```powershell
  dotnet run --project OmniEyeSvc\OmniEyeSvc.csproj -c Release
  ```

* **ウィンドウ 2（一般ユーザー — トレイ GUI）：**
  ```powershell
  dotnet run --project OmniEyeTray\OmniEyeTray.csproj -c Release
  ```

---

## 7. Windows サービス展開手順

本番運用では、サービスを Release ビルドし、Windows サービスコントロールマネージャー（SCM）に登録します：

### 1. リリースバイナリの発行：
```powershell
dotnet publish OmniEyeSvc\OmniEyeSvc.csproj -c Release -o publish\OmniEyeSvc
dotnet publish OmniEyeTray\OmniEyeTray.csproj -c Release -o publish\OmniEyeTray
```

### 2. サービスの登録（管理者権限のコマンドプロンプトで `sc.exe` を実行）：
```cmd
sc.exe create OmniEyeSvc binPath= "D:\SPA_Full\OmniEye\publish\OmniEyeSvc\OmniEyeSvc.exe" start= auto DisplayName= "OmniEye Zero-Trust Service"
sc.exe description OmniEyeSvc "データ流出防止エンジンおよびゼロトラストネットワークエンフォーサー。"
sc.exe start OmniEyeSvc
```

### 3. サービスの管理：
```cmd
sc.exe stop OmniEyeSvc
sc.exe delete OmniEyeSvc
```

### 4. トレイ GUI のスタートアップ登録：
`publish\OmniEyeTray\OmniEyeTray.exe` のショートカットを作成し、Windows のスタートアップフォルダ（`Win + R` ➔ `shell:startup`）に配置します。

---

## 8. 自動検証テストスイート

[OmniEye.Tests](file:///d:/SPA_Full/OmniEye/OmniEye.Tests) プロジェクトには、外部依存関係なしにすべての保護メカニズムを検証する統合テストが含まれています：

```powershell
dotnet run --project OmniEye.Tests\OmniEye.Tests.csproj
```

### テスト実行結果：
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

## 9. よくある質問（FAQ）

#### Q: OmniEye サービスが予期せず強制終了された場合、インターネット通信はどうなりますか？
> **A:** `DeveloperMode: true` の場合、サービス終了時に自動的にポリシーが `DefaultOutboundAction = ALLOW` に復元されます。本番モード（`DeveloperMode: false`）の場合、情報流出を防ぐためファイアウォールは遮断状態を維持し、ホワイトリスト登録済みアプリおよびシステム必須通信のみが接続可能です。管理者権限の PowerShell から手動で標準状態に戻すことも可能です：  
> `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`。

#### Q: DNS や DHCP がシステム必須例外に指定されている理由は何ですか？
> **A:** DHCP（UDP ポート 67/68）が遮断されるとルーターからローカル IP アドレスを取得できず、DNS（UDP/TCP ポート 53）が遮断されると信頼されたアプリケーションの名前解決が一切機能しなくなるためです。高度なセキュリティ環境では、DNS ポートの通信先を企業内の特定 DNS サーバー IP に限定することも可能です。

#### Q: ブラウザや Discord などの自動更新時、OmniEye はどのように動作しますか？
> **A:** **Companion Discovery** 機能により、更新ヘルパープログラム（`Update.exe`）が事前に同じ信頼グループとして登録されます。同じ正規発行元証明書で署名された新バージョンがインストールされても、ファイアウォールルールは中断することなく機能し続けます。

#### Q: ゲームやストリーミング時のネットワーク遅延（Ping）に影響はありますか？
> **A:** ありません。パケットフィルタリングは Windows NDIS カーネルドライバー（Windows Defender ファイアウォール）内でハードウェアネイティブの速度で処理されます。遅延の原因となるプロキシを挟まないため、通信オーバーヘッドはゼロです。

---

<p align="center">
  <sub>プライバシーの保護と最高水準の Windows エンドポイントセキュリティのために設計されています。</sub>
</p>
