#Requires -Version 7.0
<#
.SYNOPSIS
    Run a Strix pentest headlessly through a coding agent (no Strix LLM key).

.DESCRIPTION
    Drives the `pentest` OpenCode agent over the Strix MCP server. The model is
    whatever OpenCode is configured with; Strix itself never calls an LLM API.
    The agent runs the same engine tools as an interactive /runscan and writes
    the usual strix_runs/<run>/ artifacts.

.PARAMETER Target
    Exact authorized target (URL, host, or repository path). Nothing else is
    in scope for the run.

.PARAMETER Mode
    quick | standard | deep. Defaults to $env:STRIX_MCP_SCAN_MODE, then deep.

.PARAMETER Model
    Optional provider/model override for the host agent (not for Strix).

.PARAMETER RunsDir
    Override the artifact root. Default: <repo>/strix_runs.

.PARAMETER Json
    Ask OpenCode for JSON event output instead of the default transcript.

.EXAMPLE
    ./scripts/runscan-agent.ps1 -Target https://staging.example.com -Mode standard

.EXAMPLE
    ./scripts/runscan-agent.ps1 -Target https://example.com -Mode quick -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,

    [Parameter(Position = 1)]
    [ValidateSet('quick', 'standard', 'deep')]
    [string]$Mode,

    [string]$Model,
    [string]$RunsDir,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

if (-not $Mode) {
    $Mode = if ($env:STRIX_MCP_SCAN_MODE) { $env:STRIX_MCP_SCAN_MODE } else { 'deep' }
}
if ($Mode -notin @('quick', 'standard', 'deep')) {
    throw "Mode must be quick, standard or deep (got '$Mode')."
}

# --- preflight ---------------------------------------------------------------
$opencode = Get-Command opencode -ErrorAction SilentlyContinue
if (-not $opencode) {
    throw 'opencode is not on PATH. Install it from https://opencode.ai and re-run.'
}

$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    throw "Python venv missing at $python. Run setup.ps1 first."
}
$server = Join-Path $repo 'mcp\server.py'
if (-not (Test-Path $server)) {
    throw "MCP server missing at $server."
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Warning 'docker is not on PATH; the agent will fail its sandbox health check.'
}
else {
    try {
        $null = docker version --format '{{.Server.Version}}' 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'Docker daemon is not responding. Start Docker Desktop before the run.'
        }
    }
    catch {
        Write-Warning 'Could not query Docker. Start Docker Desktop before the run.'
    }
}

# --- environment -------------------------------------------------------------
$env:STRIX_MCP_SCAN_MODE = $Mode
if ($RunsDir) {
    $env:STRIX_MCP_RUNS_DIR = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $RunsDir)).Path
}

$title = 'runscan-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$prompt = @"
Run the /runscan workflow for exactly this target: $Target
Scan mode: $Mode

Follow your system prompt. Start with strix_sandbox_health; if Docker or the
sandbox image is unavailable, report the exact fix and stop. Restate scope,
read or derive the threat model, and keep a short todo plan. Recon and map the
surface before attacking it, create throwaway accounts if auth is required,
record coverage as you assess each surface, and file only confirmed findings
with real captured evidence. Reconcile needs_follow_up coverage rows, then
call strix_finish_report exactly once.

Do not test anything outside $Target. If the target is unreachable, diagnose
once and stop. Finish with: findings by severity, one line each, the report
path, and the honest coverage gaps.
"@

$cliArgs = @('run', '--agent', 'pentest', '--auto', '--title', $title)
if ($Model) { $cliArgs += @('--model', $Model) }
if ($Json) { $cliArgs += @('--format', 'json') }
$cliArgs += $prompt

Write-Host "Strix agentic scan"
Write-Host "  target : $Target"
Write-Host "  mode   : $Mode"
Write-Host "  runs   : $(if ($RunsDir) { $env:STRIX_MCP_RUNS_DIR } else { Join-Path $repo 'strix_runs' })"
Write-Host "  session: $title"
Write-Host ''

Push-Location $repo
try {
    & opencode @cliArgs
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}

$runsRoot = if ($env:STRIX_MCP_RUNS_DIR) { $env:STRIX_MCP_RUNS_DIR } else { Join-Path $repo 'strix_runs' }
if (Test-Path $runsRoot) {
    $latest = Get-ChildItem $runsRoot -Directory -Filter 'runscan-*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host ''
        Write-Host "Latest run: $($latest.FullName)"
        $report = Join-Path $latest.FullName 'penetration_test_report.md'
        if (Test-Path $report) { Write-Host "Report:     $report" }
    }
}

exit $code
