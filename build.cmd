@echo off
rem Build all projects for every platform with the latest installed Visual Studio.
rem Usage: build.cmd [Release|Debug] [Win32|x64|ARM64 ...]
setlocal
set CFG=%1
if "%CFG%"=="" set CFG=Release
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set MSBUILD=%%i
if not defined MSBUILD (echo MSBuild not found & exit /b 1)
set PLATFORMS=%2 %3 %4
if "%2"=="" set PLATFORMS=Win32 x64 ARM64
for %%p in (%PLATFORMS%) do (
  "%MSBUILD%" "%~dp0OpenPGPCsp\OpenPGPCsp.vcxproj" /p:Configuration=%CFG% /p:Platform=%%p /p:SolutionDir="%~dp0\" /m /nologo /v:m || exit /b 1
  "%MSBUILD%" "%~dp0SmartCardManager\SmartCardManager.vcxproj" /p:Configuration=%CFG% /p:Platform=%%p /p:SolutionDir="%~dp0\" /m /nologo /v:m || exit /b 1
)
