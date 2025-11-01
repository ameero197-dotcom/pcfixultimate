param(
  [Parameter(Mandatory=$true)][string]$Version,
  [string]$IconPath=".\\assets\\pcfix.ico",
  [string]$EntryScript="pcfixultimate.py",
  [string]$ExeName="PCFixUltimate.exe",
  [string]$ManifestPath=".\\docs\\manifest.json",
  [string]$PfxPath="",
  [string]$PfxPassword=""
)

$ErrorActionPreference="Stop"
function Fail([string]$m){ Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }
function Info([string]$m){ Write-Host $m -ForegroundColor Cyan }
function Warn([string]$m){ Write-Host $m -ForegroundColor Yellow }

if(-not (Test-Path $EntryScript)){ Fail "Entry script not found: $EntryScript" }

# pick pyinstaller
$pyiCmd=$null
if(Get-Command pyinstaller -ErrorAction SilentlyContinue){ $pyiCmd="pyinstaller" }
elseif(Get-Command python -ErrorAction SilentlyContinue){ $pyiCmd="python -m PyInstaller" }
elseif(Get-Command py -ErrorAction SilentlyContinue){ $pyiCmd="py -m PyInstaller" }
else{ Fail "PyInstaller not found. Install with: pip install pyinstaller" }

# icon
$iconArg=""
if($IconPath -and (Test-Path $IconPath)){ $iconArg="--icon `"$IconPath`"" } else { Warn "Icon not found at $IconPath - EXE will have no custom icon." }

# build
$buildCmd="$pyiCmd --clean --noconfirm --onefile --name PCFixUltimate $iconArg `"$EntryScript`""
Info "Running: $buildCmd"
cmd /c $buildCmd
if($LASTEXITCODE -ne 0){ Fail "PyInstaller build failed (exit $LASTEXITCODE)" }

# find exe
$exePath=Join-Path -Path ".\dist" -ChildPath $ExeName
if(-not (Test-Path $exePath)){
  $probe=Get-ChildItem -Recurse -Filter $ExeName -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if($probe){ $exePath=$probe.FullName }
}
if(-not (Test-Path $exePath)){ Fail "Built EXE not found." }
Info "Built: $exePath"

# sign (optional)
if($PfxPath -and (Test-Path $PfxPath)){
  if(Get-Command signtool.exe -ErrorAction SilentlyContinue){
    $ts="http://timestamp.digicert.com"
    $cmd="signtool sign /f `"$PfxPath`" /p `"$PfxPassword`" /tr $ts /td sha256 /fd sha256 `"$exePath`""
    Info $cmd
    cmd /c $cmd
    if($LASTEXITCODE -ne 0){ Warn "signtool failed to sign EXE" }
  } else { Warn "signtool.exe not found - skipping signing" }
} else { Info "No PFX provided - skipping signing" }

# sha256
$shaExe=(Get-FileHash -Algorithm SHA256 $exePath).Hash
Info "SHA256(EXE) = $shaExe"

# update manifest
if(Test-Path $ManifestPath){
  try{ $m=Get-Content $ManifestPath -Raw | ConvertFrom-Json } catch{ $m=@{} }
  $m.version=$Version
  $m.url=$ExeName
  $m.sha256=$shaExe
  if(-not $m.PSObject.Properties.Match("signature")){ $m | Add-Member -NotePropertyName "signature" -NotePropertyValue "" }
  $m.signature=""
  $m | ConvertTo-Json -Depth 10 | Set-Content $ManifestPath -Encoding UTF8
  Info "Manifest updated: $ManifestPath"
} else {
  Warn "Manifest not found at $ManifestPath - skipping"
}

Write-Host "DONE"
Write-Host "EXE: $exePath"
Write-Host "SHA256: $shaExe"
