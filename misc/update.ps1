Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$baseDir = Split-Path -Parent $PSScriptRoot
$configSchema = Join-Path $baseDir "docs/config.schema.json"
$policiesSchemaDir = Join-Path $baseDir "policies/schema"

New-Item -ItemType Directory -Force -Path $policiesSchemaDir | Out-Null

Write-Host "+ cargo run -q -p coauth-config --bin schema"
$configJson = & cargo run -q -p coauth-config --bin schema
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$configJson | Set-Content -Path $configSchema -Encoding utf8NoBOM

$oldOutDir = $env:OUT_DIR
$env:OUT_DIR = $policiesSchemaDir
try {
    Write-Host "+ cargo run -q -p coauth-backend --bin policy_schema"
    & cargo run -q -p coauth-backend --bin policy_schema
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    if ($null -eq $oldOutDir) {
        Remove-Item Env:OUT_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:OUT_DIR = $oldOutDir
    }
}
