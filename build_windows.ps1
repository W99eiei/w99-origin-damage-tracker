$ErrorActionPreference = 'Stop'
$project = $PSScriptRoot
$dist = Join-Path $project 'dist'
$work = Join-Path $project 'build'

if (-not (Test-Path (Join-Path $project 'analise_engine\protocol_table.bin'))) {
    throw 'Missing analise_engine\protocol_table.bin.'
}
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin `
    --name 'W99 Origin Damage Tracker' `
    --distpath $dist `
    --workpath $work `
    --add-data 'dps_live.html:.' `
    --add-data 'dps_overlay.html:.' `
    --add-data 'distribution_build.json:.' `
    --add-data 'analise_engine/protocolos_ids.json:analise_engine' `
    --add-data 'analise_engine/protocol_table.bin:analise_engine' `
    'dps_meter_exe.py'

if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }
Copy-Item -LiteralPath (Join-Path $project 'README.md') -Destination (Join-Path $dist 'README.md') -Force
Write-Output (Join-Path $dist 'W99 Origin Damage Tracker.exe')

