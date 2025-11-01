#define MyAppName "PCFixUltimate"
#define MyAppVersion "1.0.5"
#define MyAppExeName "PCFixUltimate.exe"

[Setup]
AppId={{A3D2D33B-CAF9-4D16-9C9C-7F0B3E9A1.0.5}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=.
OutputBaseFilename=PCFixUltimateSetup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
SetupIconFile=.\assets\pcfix.ico
DisableDirPage=no
DisableProgramGroupPage=yes

[Files]
Source: ".\dist\PCFixUltimate.exe"; DestDir: "{app}"; Flags: ignoreversion


[Icons]
Name: "{group}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"
Name: "{commondesktop}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"
