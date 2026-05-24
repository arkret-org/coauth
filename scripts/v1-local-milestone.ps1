[CmdletBinding()]
param(
    [string]$Version = "v1.0.0",
    [string]$ArtifactDir = "target/release-artifacts",
    [switch]$RunBuilds
)

$ErrorActionPreference = "Stop"

function Get-CommandPath {
    param([string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        return $null
    }

    return $cmd.Source
}

function Add-Result {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [string]$Name,
        [string]$Status,
        [string]$Details
    )

    $Results.Add([ordered]@{
        name    = $Name
        status  = $Status
        details = $Details
    })
}

function Invoke-LocalBookBuild {
    param(
        [string]$RepoRoot,
        [string]$ArtifactRoot,
        [string]$ConfigFile,
        [string]$Name,
        [System.Collections.Generic.List[object]]$Results
    )

    $mdbook = Get-CommandPath "mdbook"
    if ($null -eq $mdbook) {
        Add-Result $Results $Name "skipped" "mdbook was not found on PATH"
        return
    }

    $sourceRoot = Join-Path $ArtifactRoot "mdbook-$Name-source"
    New-Item -ItemType Directory -Force $sourceRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot "docs") -Destination $sourceRoot -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $RepoRoot $ConfigFile) -Destination (Join-Path $sourceRoot "book.toml") -Force

    & $mdbook build $sourceRoot
    Add-Result $Results $Name "passed" "built with $ConfigFile under $sourceRoot"
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
Set-Location $repoRoot

$artifactRoot = Join-Path $repoRoot $ArtifactDir
New-Item -ItemType Directory -Force $artifactRoot | Out-Null

$head = (& git rev-parse HEAD).Trim()
$short = (& git rev-parse --short=12 HEAD).Trim()
$status = @(& git status --short)
$recordPath = Join-Path $artifactRoot "coauth-$Version-local-milestone.json"
$buildResults = [System.Collections.Generic.List[object]]::new()

if ($RunBuilds) {
    Invoke-LocalBookBuild $repoRoot $artifactRoot "book.toml" "book-en" $buildResults
    Invoke-LocalBookBuild $repoRoot $artifactRoot "book-zh.toml" "book-zh" $buildResults

    $docker = Get-CommandPath "docker"
    if ($null -eq $docker) {
        Add-Result $buildResults "image-oci-archive" "skipped" "docker was not found on PATH"
    } else {
        $imageTar = Join-Path $artifactRoot "coauth-$Version-$short.oci.tar"
        & $docker buildx build `
            --output "type=oci,dest=$imageTar" `
            --build-arg "VERGEN_GIT_DESCRIBE=$Version-local+$short" `
            .
        Add-Result $buildResults "image-oci-archive" "passed" "wrote $imageTar"
    }
} else {
    Add-Result $buildResults "book-en" "not-run" "run with -RunBuilds to attempt mdbook build"
    Add-Result $buildResults "book-zh" "not-run" "run with -RunBuilds to attempt mdbook build"
    Add-Result $buildResults "image-oci-archive" "not-run" "run with -RunBuilds to attempt local docker buildx archive"
}

$record = [ordered]@{
    schema             = "cx.coauth.local_milestone.v1"
    version            = $Version
    commit             = $head
    short_commit       = $short
    generated_at_utc   = (Get-Date).ToUniversalTime().ToString("o")
    scope              = "local-only"
    guardrails         = @(
        "do not git tag",
        "do not git push",
        "do not docker push",
        "do not publish GitHub releases",
        "do not publish crates"
    )
    tools              = [ordered]@{
        mdbook = Get-CommandPath "mdbook"
        docker = Get-CommandPath "docker"
        syft   = Get-CommandPath "syft"
        cosign = Get-CommandPath "cosign"
    }
    working_tree_short = $status
    build_results      = $buildResults
    next_commands      = [ordered]@{
        english_book = "mdbook build"
        chinese_book = "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/v1-local-milestone.ps1 -RunBuilds"
        image_archive = "docker buildx build --output type=oci,dest=$ArtifactDir/coauth-$Version-$short.oci.tar --build-arg VERGEN_GIT_DESCRIBE=$Version-local+$short ."
        sbom_and_provenance = "see docs/en/development/releasing.md"
    }
}

$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding UTF8
Write-Output $recordPath
