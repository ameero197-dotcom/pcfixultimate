param(
  [string]$ExePath = ".\dist\PCFixUltimate.exe",
  [string]$IconPath = ".\assets\pcfix.ico",
  [string]$PfxPath = "",
  [string]$PfxPassword = ""
)

$ErrorActionPreference = "Stop"
function Info([string]$m){ Write-Host $m -ForegroundColor Cyan }
function Warn([string]$m){ Write-Host $m -ForegroundColor Yellow }

if(-not (Test-Path $ExePath)){ throw "EXE not found: $ExePath" }

# ابحث عن ISCC (Inno Setup)
$ISCC = $null
try {
  $c = Get-Command ISCC.exe -ErrorAction Stop
  if($c -and $c.Source){ $ISCC = $c.Source }
} catch {}
if(-not $ISCC){
  $candidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
  ) | Where-Object { Test-Path $_ }
  if($candidates.Count -gt 0){ $ISCC = $candidates[0] }
}

$installerPath = $null
if($ISCC){
  Info "Building installer with Inno Setup..."
  $installerDir = ".\installer"
  if(-not (Test-Path $installerDir)){ New-Item -ItemType Directory -Path $installerDir | Out-Null }
  $issPath = Join-Path $installerDir "pcfix_autogen.iss"

  $iconLine = ""
  if($IconPath -and (Test-Path $IconPath)){ $iconLine = "SetupIconFile=$IconPath" }

  $iss = @"
#define MyAppName "PCFixUltimate"
#define MyAppExeName "PCFixUltimate.exe"

[Setup]
AppId={{2B9E5A3A-2F8E-4D6C-9E2C-3E0CF3F8B1A0}
AppName={#MyAppName}
AppVersion=autodetect
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=.
OutputBaseFilename=PCFixUltimateSetup
Compression=lzma
SolidCompression=yes
$iconLine

[Files]
Source: "$ExePath"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"
Name: "{commondesktop}\PCFixUltimate"; Filename: "{app}\PCFixUltimate.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"
"@

  Set-Content -Path $issPath -Value $iss -Encoding ASCII
  & "$ISCC" "$issPath" | Write-Host
  $cand = Get-ChildItem -Path . -Filter "PCFixUltimateSetup.exe" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if($cand){ $installerPath = $cand.FullName }
} else {
  Info "Inno Setup غير موجود — سنعمل ZIP بديل."
  $zipName = "PCFixUltimate.zip"
  if(Test-Path $zipName){ Remove-Item $zipName -Force }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory((Split-Path -Parent $ExePath), $zipName)
  $installerPath = (Resolve-Path $zipName).Path
}

# توقيع اختياري
if($PfxPath -and (Test-Path $PfxPath) -and $installerPath.ToLower().EndsWith(".exe")){
  if(Get-Command signtool.exe -ErrorAction SilentlyContinue){
    $ts="http://timestamp.digicert.com"
    $cmd = "signtool sign /f `"$PfxPath`" /p `"$PfxPassword`" /tr $ts /td sha256 /fd sha256 `"$installerPath`""
    Write-Host $cmd
    cmd /c $cmd | Write-Host
  } else {
    Warn "signtool.exe غير موجود — التجاوز عن التوقيع."
  }
}

Write-Host "DONE"
Write-Host "Installer/Archive: $installerPath"
