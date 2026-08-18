[CmdletBinding()]
param(
    [string]$OutputDirectory = "dist"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Extension = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Extension = ".exe" },
    @{ GOOS = "linux"; GOARCH = "amd64"; Extension = "" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Extension = "" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Extension = "" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Extension = "" }
)

$savedCGO = $env:CGO_ENABLED
$savedOS = $env:GOOS
$savedArch = $env:GOARCH
try {
    foreach ($target in $targets) {
        $env:CGO_ENABLED = "0"
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $binary = Join-Path $outputPath ("drg-{0}-{1}{2}" -f $target.GOOS, $target.GOARCH, $target.Extension)
        Write-Host "Building $($target.GOOS)/$($target.GOARCH): $binary"
        & go build -trimpath '-ldflags=-s -w' -o $binary ./cmd/drg
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($target.GOOS)/$($target.GOARCH)"
        }
    }
}
finally {
    $env:CGO_ENABLED = $savedCGO
    $env:GOOS = $savedOS
    $env:GOARCH = $savedArch
}

Write-Host "Release binaries are ready in $outputPath"
