@echo off
rem Sign the Release binaries. Usage: sign.cmd <certificate thumbprint or subject name> [timestamp url]
setlocal
if "%~1"=="" (echo Usage: sign.cmd ^<thumbprint^|subject^> [timestamp url] & exit /b 1)
set TS=%2
if "%TS%"=="" set TS=http://time.certum.pl
for /f "delims=" %%i in ('dir /b /s /o-n "%ProgramFiles(x86)%\Windows Kits\10\bin\signtool.exe" ^| findstr /i "\x64\\"') do set SIGNTOOL=%%i
if not defined SIGNTOOL (echo signtool not found & exit /b 1)
set SEL=/sha1 %1
echo %1| findstr /r /c:"^[0-9A-Fa-f]*$" >nul || set SEL=/n "%~1"
for %%f in (x86\Release\OpenPGPCsp32.dll x64\Release\OpenPGPCsp64.dll ARM64\Release\OpenPGPCspARM64.dll x86\Release\OpenPGPSmartCardManager.exe x64\Release\OpenPGPSmartCardManager.exe ARM64\Release\OpenPGPSmartCardManager.exe) do (
  "%SIGNTOOL%" sign %SEL% /d "OpenPGP CSP" /tr %TS% /td sha256 /fd sha256 "%~dp0%%f" || exit /b 1
)
