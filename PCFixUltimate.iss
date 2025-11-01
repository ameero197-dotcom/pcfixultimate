[Setup]
AppName=PCFixUltimate
AppVersion=1.0.4
DefaultDirName={pf}\PCFixUltimate
DefaultGroupName=PCFixUltimate
OutputBaseFilename=PCFixUltimateSetup
OutputDir=C:\Users\xlx\Desktop\Pcfixapp\pcfixgptversion\dist
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
SetupIconFile=C:\Users\xlx\Desktop\Pcfixapp\pcfixgptversion\pcfix_icon.ico
UninstallDisplayIcon={app}\PCFixUltimate.exe

[Files]
Source: "dist\PCFixUltimate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Users\xlx\Desktop\Pcfixapp\pcfixgptversion\pcfix_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Users\xlx\Desktop\Pcfixapp\pcfixgptversion\keys\pcfix.cer"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"
Name: "{commondesktop}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"
