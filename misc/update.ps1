Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$baseDir = Split-Path -Parent $PSScriptRoot
$configSchema = Join-Path $baseDir "docs/config.schema.json"
$templatesDir = Join-Path $baseDir "templates"
$translationsFile = Join-Path $baseDir "translations/en.json"
$policiesSchemaDir = Join-Path $baseDir "policies/schema"

New-Item -ItemType Directory -Force -Path $policiesSchemaDir | Out-Null

function Normalize-TranslationContexts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content -Raw -Path $Path
    $normalized = [regex]::Replace(
        $content,
        '"context"\s*:\s*"([^"]*)"',
        {
            param($match)
            $value = $match.Groups[1].Value -replace '\\\\', '/'
            '"context": "' + $value + '"'
        }
    )

    if ($normalized -ne $content) {
        $encoding = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($Path, $normalized, $encoding)
    }
}

Write-Host "+ cargo run -q -p coauth-config --bin schema"
$configJson = & cargo run -q -p coauth-config --bin schema
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$configJson | Set-Content -Path $configSchema -Encoding utf8NoBOM

Write-Host "+ cargo run -q -p coauth-i18n-scan -- --update $templatesDir $translationsFile"
& cargo run -q -p coauth-i18n-scan -- --update $templatesDir $translationsFile
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
Normalize-TranslationContexts -Path $translationsFile

$oldOutDir = $env:OUT_DIR
$env:OUT_DIR = $policiesSchemaDir
try {
    Write-Host "+ cargo run -q -p coauth-policy --bin schema"
    & cargo run -q -p coauth-policy --bin schema
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
