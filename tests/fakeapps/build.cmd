@echo off
rem Build all fake apps for the Portappix compatibility suite.
rem
rem Usage (from a Delphi command prompt with dcc32/dcc64/brcc32 on PATH):
rem     tests\fakeapps\build.cmd          build Win32 (default)
rem     tests\fakeapps\build.cmd 64       build Win64
rem     tests\fakeapps\build.cmd all      build Win32 and Win64
rem
rem Output lands in tests\fakeapps\out\<AppName>\ (Win32) or
rem tests\fakeapps\out64\<AppName>\ (Win64). Never commit the output.
setlocal enabledelayedexpansion

set BITNESS=%1
if "%BITNESS%"=="" set BITNESS=32
if /i "%BITNESS%"=="all" (
    call "%~f0" 32 || exit /b 1
    call "%~f0" 64 || exit /b 1
    exit /b 0
)
if "%BITNESS%"=="64" (
    set COMPILER=dcc64.exe
    set OUTDIR=out64
) else if "%BITNESS%"=="32" (
    set COMPILER=dcc32.exe
    set OUTDIR=out
) else (
    echo Unknown bitness "%BITNESS%" ^(use 32, 64 or all^)
    exit /b 1
)

where %COMPILER% >nul 2>&1
if errorlevel 1 (
    echo ERROR: %COMPILER% not found on PATH. Open a Delphi command prompt first.
    exit /b 1
)

cd /d "%~dp0"
if not exist %OUTDIR% mkdir %OUTDIR%

set FAILED=0
for /d %%D in ("src\*") do call :build_one %%~nxD || set FAILED=1

if %FAILED% neq 0 (
    echo Fake app build: FAILED
    exit /b 1
)
echo Fake app build: OK ^(%OUTDIR%^)
exit /b 0

:build_one
set NAME=%1
echo Building %NAME% ...
if exist "src\%NAME%\%NAME%.rc" (
    brcc32 "src\%NAME%\%NAME%.rc" -fo"src\%NAME%\%NAME%.res" 1>nul || exit /b 1
)
if not exist "%OUTDIR%\%NAME%" mkdir "%OUTDIR%\%NAME%"
if not exist "out\dcu" mkdir "out\dcu"
%COMPILER% -B -Q -E"%OUTDIR%\%NAME%" -N"out\dcu" "src\%NAME%\%NAME%.dpr" 1>nul || exit /b 1
exit /b 0
