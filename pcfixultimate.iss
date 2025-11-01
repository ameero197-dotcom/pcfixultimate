[Setup]
AppName=PCFixUltimate
AppVersion=1.0.4
DefaultDirName={pf}\PCFixUltimate
DefaultGroupName=PCFixUltimate
OutputBaseFilename=PCFixUltimateSetup
OutputDir=docs                   ; << خليه يُخرج الـ Setup مباشرة داخل docs/
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
SetupIconFile=pcfix_icon.ico     ; << أيقونة ملف الـ Setup
UninstallDisplayIcon={app}\PCFixUltimate.exe

[Files]
; ملف البرنامج المبني عبر PyInstaller
Source: "dist\PCFixUltimate.exe"; DestDir: "{app}"; Flags: ignoreversion
; انسخ الأيقونة ضمن البرنامج (اختياري)
Source: "pcfix_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
; انسخ الشهادة للمستخدم (اختياري)
Source: "pcfix.cer"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"
Name: "{commondesktop}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
; (اختياري) تثبيت الشهادة كمُصدِّر موثوق (للشبكات الداخلية/التجارب)
Filename: "certutil.exe"; Parameters: "-addstore -f -user TrustedPublisher ""{app}\pcfix.cer"""; Flags: runhidden postinstall
; تشغيل البرنامج بعد التثبيت (اختياري)
; Filename: "{app}\PCFixUltimate.exe"; Flags: nowait postinstall skipifsilent
