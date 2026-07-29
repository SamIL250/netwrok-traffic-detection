# Network Traffic Monitor - Windows service runner
param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "status", "restart", "init-db", "logs")]
    [string]$Command = "start"
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$RunDir = Join-Path $RootDir ".run"
$env:PYTHONPATH = Join-Path $RootDir "src"

$ApiPidFile = Join-Path $RunDir "api.pid"
$DashboardPidFile = Join-Path $RunDir "dashboard.pid"
$AgentPidFile = Join-Path $RunDir "agent.pid"
$ApiLog = Join-Path $RunDir "api.log"
$DashboardLog = Join-Path $RunDir "dashboard.log"
$AgentLog = Join-Path $RunDir "agent.log"

$Python = Join-Path $RootDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $Python) {
        Write-Error "Python not found. Create the venv first: py -m venv .venv"
    }
}

Set-Location $RootDir
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

function Test-ProcessRunning {
    param([string]$PidFile)
    if (-not (Test-Path $PidFile)) { return $false }
    $processId = Get-Content $PidFile -ErrorAction SilentlyContinue
    if (-not $processId) { return $false }
    return $null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue)
}

function Start-BackgroundProcess {
    param(
        [string]$Name,
        [string]$PidFile,
        [string]$LogFile,
        [string[]]$Arguments
    )

    if (Test-ProcessRunning $PidFile) {
        $existingPid = Get-Content $PidFile
        Write-Host "$Name already running (PID $existingPid)"
        return
    }

    Write-Host "Starting $Name..."
    $process = Start-Process `
        -FilePath $Python `
        -ArgumentList $Arguments `
        -WorkingDirectory $RootDir `
        -WindowStyle Hidden `
        -RedirectStandardOutput $LogFile `
        -RedirectStandardError $LogFile `
        -PassThru

    $process.Id | Set-Content $PidFile
    Write-Host "$Name started (PID $($process.Id), log: $LogFile)"
}

function Stop-BackgroundProcess {
    param(
        [string]$Name,
        [string]$PidFile
    )

    if (-not (Test-Path $PidFile)) {
        Write-Host "$Name is not running."
        return
    }

    $processId = Get-Content $PidFile -ErrorAction SilentlyContinue
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "Stopping $Name (PID $processId)..."
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "$Name was not running (stale PID file)."
    }

    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

function Wait-ForApi {
    Write-Host "Waiting for API to become ready..."
    for ($i = 1; $i -le 30; $i++) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                Write-Host "API is ready."
                return
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    Write-Error "API did not become ready in time. Check $ApiLog"
}

function Start-Services {
    if (-not (Test-Path (Join-Path $RootDir ".env"))) {
        Write-Error "Missing .env file. Copy .env.example to .env and configure it first."
    }

    Start-BackgroundProcess "API" $ApiPidFile $ApiLog @(
        "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"
    )
    Wait-ForApi
    Start-BackgroundProcess "Dashboard" $DashboardPidFile $DashboardLog @(
        "-m", "streamlit", "run", "dashboard/app.py", "--server.port", "8501", "--server.headless", "true"
    )
    Start-BackgroundProcess "Agent" $AgentPidFile $AgentLog @(
        "agent/capture.py", "--daemon"
    )

    Write-Host ""
    Write-Host "All services started."
    Write-Host "  Dashboard: http://localhost:8501"
    Write-Host "  API:       http://127.0.0.1:8000"
    Write-Host "  Logs:      $RunDir\"
    Write-Host ""
    Write-Host "Stop everything with: .\start.ps1 stop"
}

function Stop-Services {
    Stop-BackgroundProcess "Agent" $AgentPidFile
    Stop-BackgroundProcess "Dashboard" $DashboardPidFile
    Stop-BackgroundProcess "API" $ApiPidFile
    Write-Host "All services stopped."
}

function Show-Status {
    $running = 0
    foreach ($entry in @(
            @{ Name = "API"; PidFile = $ApiPidFile },
            @{ Name = "Dashboard"; PidFile = $DashboardPidFile },
            @{ Name = "Agent"; PidFile = $AgentPidFile }
        )) {
        if (Test-ProcessRunning $entry.PidFile) {
            $pid = Get-Content $entry.PidFile
            Write-Host "$($entry.Name): running (PID $pid)"
            $running++
        } else {
            Write-Host "$($entry.Name): stopped"
            Remove-Item $entry.PidFile -Force -ErrorAction SilentlyContinue
        }
    }

    if ($running -gt 0) {
        Write-Host ""
        Write-Host "Dashboard: http://localhost:8501"
        Write-Host "API:       http://127.0.0.1:8000"
    }
}

switch ($Command) {
    "start" { Start-Services }
    "stop" { Stop-Services }
    "status" { Show-Status }
    "restart" { Stop-Services; Start-Sleep -Seconds 1; Start-Services }
    "init-db" { & $Python (Join-Path $RootDir "scripts\init_db.py") }
    "logs" { Get-Content $ApiLog, $DashboardLog, $AgentLog -Wait -ErrorAction SilentlyContinue }
}
