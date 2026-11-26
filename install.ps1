# Decision OS one-line installer for Windows (PowerShell 5.1 or 7).
#
#   irm https://raw.githubusercontent.com/Aliipou/decision-os-min/main/install.ps1 | iex
#
# Installs the `decision-os` command with uv (installing uv first if needed; uv
# also provides Python when none is installed), then runs `decision-os install`,
# which wraps every MCP server of every detected app (Claude Desktop, Claude
# Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex, LM Studio, ...).
#
# Options: set $env:DECISION_OS_ARGS = "--observe" (or "--profile strict") first.
# Undo everything with:  decision-os uninstall

$ErrorActionPreference = "Stop"
$Ref = if ($env:DECISION_OS_REF) { $env:DECISION_OS_REF } else { "main" }
$Src = if ($env:DECISION_OS_SRC) { $env:DECISION_OS_SRC } else {
    "https://github.com/Aliipou/decision-os-min/archive/refs/heads/$Ref.zip"
}

function Find-Uv {
    $cmd = Get-Command uv -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @("$env:USERPROFILE\.local\bin\uv.exe", "$env:USERPROFILE\.cargo\bin\uv.exe")) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

$uv = Find-Uv
if (-not $uv) {
    Write-Host "Decision OS needs uv (a Python package manager from Astral). Installing it now..."
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    $uv = Find-Uv
    if (-not $uv) { throw "uv was installed but not found; open a new terminal and run this again." }
}

Write-Host "Installing Decision OS from $Src"
& $uv tool install --force "decision-os-min @ $Src"
if ($LASTEXITCODE -ne 0) { throw "uv tool install failed" }

$bin = (& $uv tool dir --bin).Trim()
$cli = Join-Path $bin "decision-os.exe"
if (-not (Test-Path $cli)) { throw "decision-os was installed but $cli is missing" }

Write-Host ""
$extra = if ($env:DECISION_OS_ARGS) { $env:DECISION_OS_ARGS -split " " } else { @() }
& $cli install @extra

if (-not (($env:Path -split ";") -contains $bin)) {
    Write-Host ""
    Write-Host "Tip: run 'uv tool update-shell' so the decision-os command works in new terminals."
}
