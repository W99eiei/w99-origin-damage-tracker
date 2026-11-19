$ErrorActionPreference = 'Stop'
$project = $PSScriptRoot
$version = '1.1.0'
$packageName = "W99_Origin_Damage_Tracker_v$version"
$stage = Join-Path $project "build\package_$packageName"
$work = Join-Path $project "build\pyinstaller_$packageName"
$dist = Join-Path $project "dist\$packageName"
$zip = Join-Path $project "dist\$packageName.zip"

if (-not (Test-Path (Join-Path $project 'analise_engine\protocol_table.bin'))) {
    throw 'Missing analise_engine\protocol_table.bin.'
}
if (Test-Path -LiteralPath $dist) { throw "Output folder already exists: $dist" }
if (Test-Path -LiteralPath $zip) { throw "Output ZIP already exists: $zip" }

Push-Location $project
try {
& python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin `
    --name 'W99 Origin Damage Tracker' `
    --icon 'assets/7ds_dps_meter.ico' `
    --distpath $stage `
    --workpath $work `
    --add-data 'dps_live.html:.' `
    --add-data 'dps_overlay.html:.' `
    --add-data 'assets/characters:assets/characters' `
    --add-data 'assets/themes:assets/themes' `
    --add-data 'distribution_build.json:.' `
    --add-data 'analise_engine/protocolos_ids.json:analise_engine' `
    --add-data 'analise_engine/protocol_table.bin:analise_engine' `
    'dps_meter_exe.py'

if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }
$exe = Join-Path $stage 'W99 Origin Damage Tracker.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'PyInstaller did not produce the expected executable.' }
New-Item -ItemType Directory -Path $dist -Force | Out-Null
Copy-Item -LiteralPath $exe -Destination $dist
Copy-Item -LiteralPath (Join-Path $project 'README.md') -Destination (Join-Path $dist 'README.md')
Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip
Write-Output $zip
} finally {
    Pop-Location
}

