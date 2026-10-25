param(
    [string]$Target = "build",
    [string]$Version = "v2.0.0"
)

$ErrorActionPreference = "Stop"
$env:CGO_ENABLED = "0"

$commit = "dev"
try {
    $commit = (git rev-parse --short HEAD 2>$null)
} catch {}

$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ldflags = "-s -w -X main.Version=$Version -X main.GitCommit=$commit -X main.BuildDate=$buildDate"

if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

switch ($Target) {
    "build" {
        Write-Host "Building wg-dashboard for current OS..." -ForegroundColor Cyan
        go build -trimpath -ldflags $ldflags -o bin/wg-dashboard.exe .
        Write-Host "Build success: bin/wg-dashboard.exe" -ForegroundColor Green
    }
    "linux-amd64" {
        Write-Host "Cross-compiling wg-dashboard for Linux amd64..." -ForegroundColor Cyan
        $env:GOOS = "linux"
        $env:GOARCH = "amd64"
        go build -trimpath -ldflags $ldflags -o bin/wg-dashboard-linux-amd64 .
        Write-Host "Build success: bin/wg-dashboard-linux-amd64" -ForegroundColor Green
    }
    "linux-arm64" {
        Write-Host "Cross-compiling wg-dashboard for Linux arm64..." -ForegroundColor Cyan
        $env:GOOS = "linux"
        $env:GOARCH = "arm64"
        go build -trimpath -ldflags $ldflags -o bin/wg-dashboard-linux-arm64 .
        Write-Host "Build success: bin/wg-dashboard-linux-arm64" -ForegroundColor Green
    }
    "test" {
        Write-Host "Running test suite..." -ForegroundColor Cyan
        go test -v ./...
    }
    "bench" {
        Write-Host "Running benchmarks..." -ForegroundColor Cyan
        go test -bench=. -benchmem ./...
    }
    "clean" {
        Write-Host "Cleaning bin and sandbox directories..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force bin, .sandbox_data -ErrorAction SilentlyContinue
    }
    Default {
        Write-Host "Unknown target: $Target. Usage: .\build.ps1 -Target [build|linux-amd64|linux-arm64|test|bench|clean]" -ForegroundColor Red
    }
}
