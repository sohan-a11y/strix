# Strix Agentic - one-command setup
# Usage:
#   powershell -ExecutionPolicy Bypass -File setup.ps1                  # bind to OpenCode (project config)
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -SeedTestSite    # also start the local Juice Shop test site
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -SkipPull        # skip sandbox image pull
param(
  [switch]$SeedTestSite,
  [switch]$SkipPull,
  [int]$TestSitePort = 4321
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$env:PYTHONUTF8 = "1"

function Info($m) { Write-Host "[*] $m" }
function Good($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

# -------------------------------------------------- 1) Python environment
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  Info "Creating .venv..."
  if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv venv
    uv pip install --python $venvPy -e . mcp
  } else {
    py -3 -m venv .venv
    & $venvPy -m pip install -e . mcp
  }
} else {
  Info "Refreshing .venv packages (idempotent)..."
  if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv pip install --python $venvPy -e . mcp
  } else {
    & $venvPy -m pip install -e . mcp
  }
}
Good "Python environment ready: $venvPy"

# -------------------------------------------------- 2) Docker daemon
docker info *> $null
if ($LASTEXITCODE -ne 0) {
  Info "Docker daemon not running; starting Docker Desktop..."
  $dd = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\Docker Desktop.exe"
  if (-not (Test-Path $dd)) { $dd = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe" }
  if (-not (Test-Path $dd)) { Warn "Docker Desktop not found - start it manually and re-run setup.ps1"; exit 1 }
  Start-Process $dd
  $up = $false
  foreach ($i in 1..60) { docker info *> $null; if ($LASTEXITCODE -eq 0) { $up = $true; break }; Start-Sleep 5 }
  if (-not $up) { Warn "Docker did not come up within 5 minutes - start it manually and re-run"; exit 1 }
}
Good "Docker daemon running"

# -------------------------------------------------- 3) Sandbox image
$sandboxImage = & $venvPy -c "from strix.config.settings import load_settings; print(load_settings().runtime.image)"
$present = (docker images --format "{{.Repository}}:{{.Tag}}" | Select-String -SimpleMatch $sandboxImage) -ne $null
if (-not $present) {
  if ($SkipPull) {
    Warn "Sandbox image $sandboxImage missing; skipping pull as requested (first scan will pull it)"
  } else {
    Info "Pulling sandbox image $sandboxImage (~2GB, one-time)..."
    docker pull $sandboxImage
  }
}
if ($present) { Good "Sandbox image present: $sandboxImage" }

# -------------------------------------------------- 4) Register MCP server with OpenCode
& $venvPy (Join-Path $root "mcp\install_mcp.py")
Good "OpenCode config updated (opencode.json in repo root)"

# -------------------------------------------------- 5) Optional: local test site
if ($SeedTestSite) {
  Info "Seeding local test site (OWASP Juice Shop on port $TestSitePort)..."
  if (-not (docker images -q bkimminich/juice-shop:latest)) { docker pull bkimminich/juice-shop:latest }
  if (-not (docker ps -a --filter "name=runscan-test-shop" -q)) {
    docker run -d --name runscan-test-shop -p "${TestSitePort}:3000" bkimminich/juice-shop:latest *> $null
  } else {
    docker start runscan-test-shop | Out-Null
  }
  Info "Waiting for the app to boot..."
  $siteOk = $false
  foreach ($i in 1..40) {
    try {
      $resp = Invoke-WebRequest -Uri "http://localhost:$TestSitePort" -UseBasicParsing -TimeoutSec 3
      if ($resp.StatusCode -eq 200) { $siteOk = $true; break }
    } catch { Start-Sleep 3 }
  }
  if ($siteOk) { Good "Test site ready: http://localhost:$TestSitePort" }
  else { Warn "Test site did not answer on http://localhost:$TestSitePort - check: docker logs runscan-test-shop" }
} else {
  Info "Tip: -SeedTestSite spins up a legal local pentest target (OWASP Juice Shop)."
}

# -------------------------------------------------- Done
Write-Host ""
Good "Setup complete."
Write-Host ""
Write-Host "  1) Open this folder in OpenCode"
Write-Host "  2) Type:  /runscan <target-url>" -ForegroundColor Cyan
$useTarget = "use your own site (must be authorized), or the seeded test site"
if ($SeedTestSite) { $useTarget = "http://localhost:$TestSitePort" }
Write-Host "     example: /runscan $useTarget"
Write-Host ""
Write-Host "  No API keys: the pentest brain is the model you selected in OpenCode;"
Write-Host "  the muscle (nmap/sqlmap/chromium/...) runs in the strix sandbox container."
