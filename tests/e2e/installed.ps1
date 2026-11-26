# End-to-end check of the Windows one-click install, in a throwaway profile.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\installed.ps1 -Src <wheel|zip URL>
#
# Runs Install-DecisionOS.cmd (the double-click path) with USERPROFILE, APPDATA
# and LOCALAPPDATA pointed at a temp folder, so no real config, uv install or
# PATH entry is touched. Then launches Claude Desktop, Cursor and VS Code
# servers exactly as their configs say (one of them through a .cmd shim, the
# way npx.cmd is), checks enforcement, approvals, the audit chain, and a
# byte-exact uninstall.
param([Parameter(Mandatory = $true)][string]$Src, [switch]$RealNpx)
$ErrorActionPreference = "Continue"

$E2E = $PSScriptRoot
$Repo = (Resolve-Path "$E2E\..\..").Path
$Py = (Get-Command python).Source
$UserPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")

$Root = Join-Path ([IO.Path]::GetTempPath()) ("dos-e2e-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $Root | Out-Null
$env:USERPROFILE = $Root
$env:HOME = $Root
$env:APPDATA = "$Root\AppData\Roaming"
$env:LOCALAPPDATA = "$Root\AppData\Local"
$env:UV_INSTALL_DIR = "$Root\.local\bin"   # uv's own installer: keep it in the sandbox
$env:UV_NO_MODIFY_PATH = "1"               # and never edit the real user PATH
# uv may resolve home through the Windows known-folder API, not USERPROFILE: pin every dir.
$env:UV_TOOL_DIR = "$Root\uv\tools"
$env:UV_TOOL_BIN_DIR = "$Root\.local\bin"
$env:UV_CACHE_DIR = "$Root\uv\cache"
$env:UV_PYTHON_INSTALL_DIR = "$Root\uv\python"
$env:DECISION_OS_SRC = $Src
$env:E2E_SERVER_LOG = "$Root\server.log"
$env:DOS_PROBE = "$Root\injected.txt"
Remove-Item Env:DECISION_OS_HOME, Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue

$script:fails = 0
function Check([string]$name, [string]$want, [string]$text) {
    if ($text -and $text.Contains($want)) { Write-Host "  pass  $name" }
    else { Write-Host "  FAIL  $name (wanted: $want)"; $script:fails++ }
}
function Assert([string]$name, [bool]$ok) {
    if ($ok) { Write-Host "  pass  $name" } else { Write-Host "  FAIL  $name"; $script:fails++ }
}
function Write-Json([string]$path, $obj) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllText($path, ($obj | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
}
function J([string]$s) { return (ConvertTo-Json $s) }  # a JSON string literal
function Invoke-Mcp([string]$cfg, [string]$key, [string]$calls) {
    # Calls are JSON text: Windows PowerShell 5.1 mangles nested arrays in ConvertTo-Json.
    $f = "$Root\calls-" + [Guid]::NewGuid().ToString("N") + ".json"
    [IO.File]::WriteAllText($f, $calls, (New-Object Text.UTF8Encoding $false))
    Push-Location $Repo  # the source tree must not be what makes it work
    $out = & $Py "$E2E\mcp_client.py" $cfg $key "@$f" 2>$null | Out-String
    Pop-Location
    return $out
}

# --- seed the three apps, the way they store their configs on Windows
New-Item -ItemType Directory -Force "$Root\.ssh", "$Root\work", "$Root\bin" | Out-Null
Set-Content "$Root\.ssh\id_rsa" "PRIVATE KEY"
Set-Content "$Root\work\notes.txt" "hello from notes"
# an npx-style launcher: a bare name that only resolves to a .cmd through PATHEXT
Set-Content "$Root\bin\mcp-e2e.cmd" "@echo off`r`n`"$Py`" `"$E2E\mcp_server.py`" %*" -Encoding ASCII
$env:PATH = "$Root\bin;$env:PATH"

$Desktop = "$env:APPDATA\Claude\claude_desktop_config.json"
$Cursor = "$Root\.cursor\mcp.json"
$VSCode = "$env:APPDATA\Code\User\mcp.json"
Write-Json $Desktop @{ mcpServers = @{ files = @{ command = $Py; args = @("$E2E\mcp_server.py") } }; globalShortcut = "Ctrl+Space" }
Write-Json $Cursor @{ mcpServers = @{ shim = @{ command = "mcp-e2e"; args = @() } } }
$vs = @{ servers = @{ tools = @{ type = "stdio"; command = $Py; args = @("$E2E\mcp_server.py") } } }
if ($RealNpx) {
    $vs.servers.fs = @{ type = "stdio"; command = "npx"; args = @("-y", "@modelcontextprotocol/server-filesystem", "$Root\work") }
}
Write-Json $VSCode $vs
$Configs = @($Desktop, $Cursor, $VSCode)
$Before = $Configs | ForEach-Object { (Get-FileHash $_).Hash }

Write-Host "== Install-DecisionOS.cmd (sandbox $Root)"
$installOut = cmd /c "echo.| `"$Repo\Install-DecisionOS.cmd`"" 2>&1 | Out-String
Write-Host $installOut
Check "installer reports 3 apps" "across 3 app(s)" $installOut
$Cli = "$Root\.local\bin\decision-os.exe"
Assert "decision-os.exe installed inside the sandbox" (Test-Path $Cli)
$doctor = & $Cli doctor 2>&1 | Out-String
Write-Host $doctor
Assert "doctor passes" (-not $doctor.Contains("FAIL"))

function Send-Approve([string]$answers) {
    # Feed `decision-os approve` real lines; PowerShell 5.1 pipes to native programs unreliably.
    & $Py -c "import subprocess,sys; subprocess.run([sys.argv[1], 'approve'], input=sys.argv[2].replace('/', chr(10)) + chr(10), text=True, capture_output=True)" $Cli $answers
}

# Start the dashboard ourselves without a browser, so an approval never opens a real tab.
$ui = Start-Process -FilePath $Cli -ArgumentList "ui", "--no-browser" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

Write-Host "== Claude Desktop"
$out = Invoke-Mcp $Desktop "mcpServers.files" ('[' +
    '["read_file", {"path": ' + (J "$Root\work\notes.txt") + '}],' +
    '["read_file", {"path": ' + (J "~\.ssh\id_rsa") + '}],' +
    '["run_command", {"command": "format C:"}],' +
    '["write_file", {"path": ' + (J "$Root\work\t.txt") + ', "content": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]]')
Write-Host $out
Check "launched through the gateway" "'mcp-proxy', '--client', 'claude-desktop'" $out
Check "read-only call runs" "-> OK: hello from notes" $out
Check "credential path blocked" "protected credentials path" $out
Check "format C: blocked" "Decision OS blocked ``files/run_command``" $out
Check "secret in arguments blocked" "contains a GitHub token" $out

Write-Host "== Cursor, through an npx-style .cmd shim"
$out = Invoke-Mcp $Cursor "mcpServers.shim" ('[["read_file", {"path": ' + (J "$Root\work\notes.txt") + '}]]')
Write-Host $out
Check "launched through the gateway" "'mcp-proxy', '--client', 'cursor'" $out
Check ".cmd upstream resolved and answers" "-> OK: hello from notes" $out

Write-Host "== VS Code"
$out = Invoke-Mcp $VSCode "servers.tools" '[["run_command", {"command": "rm -rf ~"}]]'
Write-Host $out
Check "launched through the gateway" "'mcp-proxy', '--client', 'vscode'" $out
Check "VS Code governed too" "recursive delete" $out
if ($RealNpx) {
    $out = Invoke-Mcp $VSCode "servers.fs" '[["list_allowed_directories", {}]]'
    Write-Host $out
    Check "real npx server lists tools through the proxy" "read_text_file" $out
}

Write-Host "== approvals (and a tool name crafted to inject PowerShell into the notification)"
$calls = "$Root\approve-a.json"
[IO.File]::WriteAllText($calls, '[["write_file", {"path": "' + "$Root\work\a.txt".Replace("\", "\\") + '", "content": "approved"}]]')
$p = Start-Process -FilePath $Py -ArgumentList "`"$E2E\mcp_client.py`"", "`"$Desktop`"", "mcpServers.files", "`"@$calls`"" -PassThru -WindowStyle Hidden -WorkingDirectory $Repo -RedirectStandardOutput "$calls.out" -RedirectStandardError "$calls.err"
Start-Sleep -Seconds 6
Send-Approve "a"
$p.WaitForExit(60000) | Out-Null
Get-Content "$calls.out", "$calls.err" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
Check "approved write runs" "approved" ((Get-Content "$Root\work\a.txt" -ErrorAction SilentlyContinue) -join "")

$calls = "$Root\approve-d.json"
[IO.File]::WriteAllText($calls, '[["probe$(Set-Content -Path $env:DOS_PROBE -Value pwned)", {"x": 1}], ["write_file", {"path": "' + "$Root\work\b.txt".Replace("\", "\\") + '", "content": "no"}]]')
$p = Start-Process -FilePath $Py -ArgumentList "`"$E2E\mcp_client.py`"", "`"$Desktop`"", "mcpServers.files", "`"@$calls`"" -PassThru -WindowStyle Hidden -WorkingDirectory $Repo -RedirectStandardOutput "$calls.out" -RedirectStandardError "$calls.err"
Start-Sleep -Seconds 6
Send-Approve "d/d"
Start-Sleep -Seconds 4
Send-Approve "d"
$p.WaitForExit(60000) | Out-Null
Start-Sleep -Seconds 3
Get-Content "$calls.out", "$calls.err" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
Assert "denied write left no file" (-not (Test-Path "$Root\work\b.txt"))
Assert "tool name cannot run PowerShell via the notification" (-not (Test-Path $env:DOS_PROBE))

Write-Host "== only allowed calls reached the servers"
$log = Get-Content $env:E2E_SERVER_LOG -ErrorAction SilentlyContinue
$log | ForEach-Object { Write-Host "  $_" }
Assert "exactly 3 executions (2 reads, 1 approved write)" (@($log | Where-Object { $_ -like "EXECUTED*" }).Count -eq 3)
Check "audit chain verifies" "chain verified" (& $Cli audit --verify 2>&1 | Out-String)

Stop-Process -Id $ui.Id -Force -ErrorAction SilentlyContinue
Write-Host "== uninstall"
& $Cli uninstall 2>&1 | Out-String | Write-Host
$After = $Configs | ForEach-Object { (Get-FileHash $_).Hash }
Assert "all 3 configs restored byte for byte" ((Compare-Object $Before $After) -eq $null)
Assert "real user PATH untouched" ([Environment]::GetEnvironmentVariable("Path", "User") -eq $UserPathBefore)

Write-Host ""
if ($script:fails -eq 0) { Write-Host "all Windows end-to-end checks passed"; exit 0 }
Write-Host "$($script:fails) Windows end-to-end check(s) failed"; exit 1
