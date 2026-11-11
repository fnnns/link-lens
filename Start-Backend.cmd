@echo off
setlocal
cd /d "%~dp0"
set "LINK_LENS_NODE=node"
where node >nul 2>nul
if not errorlevel 1 goto launch
set "LINK_LENS_NODE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
if exist "%LINK_LENS_NODE%" goto launch
echo Node.js 22 or later is required. See README.md.
pause
exit /b 1
:launch
"%LINK_LENS_NODE%" backend\server.mjs
pause
