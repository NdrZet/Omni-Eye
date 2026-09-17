; Inno Setup Script for OmniEye Zero-Trust Endpoint Protection & DPI Bypass
; Generates a single-file installer: OmniEye-Setup-win-x64.exe

#define MyAppName "OmniEye"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "NdrZet"
#define MyAppURL "https://github.com/NdrZet/Omni-Eye"
#define MyAppExeName "OmniEyeTray.exe"

[Setup]
AppId={{E6F7A2C9-4871-4A59-8637-2E89F0B309DC}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
OutputDir=..\publish
OutputBaseFilename=OmniEye-Setup-win-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
UsedUserAreasWarning=no
CloseApplications=yes
RestartApplications=no
UninstallDisplayName={#MyAppName} - Zero-Trust Endpoint Protection
UninstallDisplayIcon={app}\Tray\{#MyAppExeName}
SetupIconFile=..\OmniEyeTray\Assets\app.ico

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "uk"; MessagesFile: "compiler:Languages\Ukrainian.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "ja"; MessagesFile: "compiler:Languages\Japanese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Запускать OmniEye Tray при входе в Windows"; Languages: ru
Name: "autostart"; Description: "Start OmniEye Tray on Windows boot"; Languages: en
Name: "autostart"; Description: "Запускати OmniEye Tray при вході у Windows"; Languages: uk
Name: "autostart"; Description: "OmniEye Tray beim Windows-Start ausführen"; Languages: de
Name: "autostart"; Description: "Windows起動時にOmniEye Trayを開始"; Languages: ja
Name: "startservice"; Description: "Установить и запустить системную службу OmniEyeSvc"; Languages: ru; Flags: checkedonce
Name: "startservice"; Description: "Install and start OmniEyeSvc Windows Service"; Languages: en; Flags: checkedonce
Name: "startservice"; Description: "Встановити та запустити системну службу OmniEyeSvc"; Languages: uk; Flags: checkedonce
Name: "startservice"; Description: "OmniEyeSvc Windows-Dienst installieren und starten"; Languages: de; Flags: checkedonce
Name: "startservice"; Description: "OmniEyeSvc Windowsサービスをインストールして開始"; Languages: ja; Flags: checkedonce

[Files]
; Сохранение пользовательских настроек и списков доменов при накатывании обновлений
Source: "..\publish\OmniEye\Service\appsettings.json"; DestDir: "{app}\Service"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "..\publish\OmniEye\Tray\Zapret\lists\*"; DestDir: "{app}\Tray\Zapret\lists"; Flags: onlyifdoesntexist uninsneveruninstall recursesubdirs createallsubdirs

; Обновляемые бинарники и исполняемые файлы
Source: "..\publish\OmniEye\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\OmniEye\Tray\*"; DestDir: "{app}\Tray"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\OmniEye\InstallService.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\OmniEye\UninstallService.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\OmniEye\StartOmniEye.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\OmniEye\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}\OmniEye"; Filename: "{app}\Tray\{#MyAppExeName}"
Name: "{autoprograms}\{#MyAppName}\Удалить OmniEye"; Filename: "{uninstallexe}"; Languages: ru
Name: "{autoprograms}\{#MyAppName}\Uninstall OmniEye"; Filename: "{uninstallexe}"; Languages: en
Name: "{autoprograms}\{#MyAppName}\Видалити OmniEye"; Filename: "{uninstallexe}"; Languages: uk
Name: "{autoprograms}\{#MyAppName}\OmniEye deinstallieren"; Filename: "{uninstallexe}"; Languages: de
Name: "{autoprograms}\{#MyAppName}\OmniEyeのアンインストール"; Filename: "{uninstallexe}"; Languages: ja
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\Tray\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OmniEyeTray"; ValueData: """{app}\Tray\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; 1. Регистрация и запуск системной службы (если выбрана задача startservice)
Filename: "{sys}\sc.exe"; Parameters: "create OmniEyeSvc binPath= ""{app}\Service\OmniEyeSvc.exe"" start= auto DisplayName= ""OmniEye Zero-Trust Service"""; Flags: runhidden; Tasks: startservice
Filename: "{sys}\sc.exe"; Parameters: "description OmniEyeSvc ""Высокопроизводительное ядро эндпоинт-защиты Zero-Trust и предотвращения эксфильтрации данных."""; Flags: runhidden; Tasks: startservice
Filename: "{sys}\sc.exe"; Parameters: "start OmniEyeSvc"; Flags: runhidden; Tasks: startservice

; 2. Запуск приложения Tray после завершения установки
Filename: "{app}\Tray\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Корректное завершение процессов и удаление службы при деинсталляции
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM OmniEyeTray.exe"; Flags: runhidden; RunOnceId: "KillTray"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM winws.exe"; Flags: runhidden; RunOnceId: "KillWinws"
Filename: "{sys}\sc.exe"; Parameters: "stop OmniEyeSvc"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete OmniEyeSvc"; Flags: runhidden; RunOnceId: "DelSvc"

[Code]
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  // Останавливаем старые запущенные экземпляры при обновлении
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop OmniEyeSvc', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM OmniEyeTray.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM winws.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop OmniEyeSvc', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM OmniEyeTray.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM winws.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
