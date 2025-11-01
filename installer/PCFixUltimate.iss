#define MyAppName "PCFixUltimate"
#define MyAppVersion "1.0.5"
#define MyAppPublisher "PCFix"
#define MyAppExeName "PCFixUltimate.exe"

[Setup]
AppId={{F9E1B1E5-6B0E-4C1C-AB12-9A1234ABCDEF}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={pf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputBaseFilename={#MyAppName}-Setup-{#MyAppVersion}
OutputDir=..\dist
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
; SetupIconFile disabled (icon file not found)

[Files]
Source: "..\dist\PCFixUltimate.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "إنشاء اختصار على سطح المكتب"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "تشغيل {#MyAppName} الآن"; Flags: nowait postinstall skipifsilent
