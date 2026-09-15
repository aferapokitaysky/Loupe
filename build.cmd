@echo off
setlocal enabledelayedexpansion

rem Builds the whole project in the right order.
rem
rem Why a script instead of "dotnet build NetSniffer.sln": the dotnet CLI cannot evaluate
rem Visual C++ project files, so it fails on NetSniffer.Native.vcxproj with
rem   error MSB4278: $(VCTargetsPath)\Microsoft.Cpp.Default.props does not exist
rem The native DLL needs real MSBuild; everything managed builds fine with dotnet.
rem
rem Usage:  build.cmd [Debug|Release]      (default: Release)

set CONFIG=%~1
if "%CONFIG%"=="" set CONFIG=Release

set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
    echo [!] vswhere.exe not found - install Visual Studio 2022 or the Build Tools.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set MSBUILD=%%i
if not defined MSBUILD (
    echo [!] MSBuild.exe not found - install the "Desktop development with C++" workload.
    exit /b 1
)

echo.
echo === 1/3  Native capture engine ^(%CONFIG^%^|x64^) ===
"%MSBUILD%" "%~dp0native\NetSniffer.Native\NetSniffer.Native.vcxproj" /p:Configuration=%CONFIG% /p:Platform=x64 /v:minimal /nologo
if errorlevel 1 (
    echo.
    echo [!] Native build failed. The Npcap SDK is needed to compile it:
    echo     https://npcap.com/#download  ^(extract to third_party\npcap-sdk\ or set NPCAP_SDK_DIR^)
    exit /b 1
)

echo.
echo === 2/3  Managed projects ^(%CONFIG^%^) ===
dotnet build "%~dp0src\NetSniffer.App\NetSniffer.App.csproj" -c %CONFIG% --nologo
if errorlevel 1 exit /b 1

echo.
echo === 3/3  Tests ===
dotnet run --project "%~dp0tests\NetSniffer.Tests" -c %CONFIG% --nologo
if errorlevel 1 (
    echo [!] Tests failed.
    exit /b 1
)

echo.
echo Done. App: src\NetSniffer.App\bin\%CONFIG%\net8.0-windows\NetSniffer.exe
endlocal
