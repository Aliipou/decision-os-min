@echo off
rem Double-click to install Decision OS on Windows.
rem Uses install.ps1 next to this file when present, otherwise downloads it.
setlocal
set "HERE=%~dp0"
if exist "%HERE%install.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%install.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Aliipou/decision-os-min/main/install.ps1 | iex"
)
echo.
echo Restart Claude Desktop, Cursor or your other AI apps to finish. Run "decision-os ui" to see approvals.
pause
