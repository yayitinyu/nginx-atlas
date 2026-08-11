param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location (Join-Path $projectRoot "web")
try {
    npm ci
    npm run build
} finally {
    Pop-Location
}

Push-Location $projectRoot
try {
    New-Item -ItemType Directory -Force -Path (Join-Path $projectRoot "bin") | Out-Null
    go test ./...
    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o (Join-Path $projectRoot "bin\nginx-atlas.exe") ./cmd/atlas
} finally {
    Pop-Location
}

Write-Host "Built bin\nginx-atlas.exe ($Version)"
