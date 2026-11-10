@echo off
rem Build the Portappix launcher (Win32 / Win64).
rem
rem Steps:
rem   1. python scripts\convert_icons.py   -> DIB-compressed icons in
rem                                            portappix_icons\dib\
rem      (the artwork ships as PNG-compressed .ico files, which the resource
rem       compiler cannot embed; see scripts\convert_icons.py)
rem   2. brcc32 src\PortappixIcons.rc      -> src\PortappixIcons.res
rem      (application icon + the five notification-area icons)
rem   3. dcc32 / dcc64 src\Launcher.dpr    -> the launcher executable
rem
rem Usage (from a Delphi command prompt with dcc32/dcc64/brcc32 on PATH):
rem     scripts\build_launcher.cmd          build Win32  -> bin\Launcher.exe
rem     scripts\build_launcher.cmd 64       build Win64  -> bin\Launcher.exe
rem     scripts\build_launcher.cmd all      build both
rem
rem The script only produces build output; it never commits anything.
setlocal enabledelayedexpansion

set BITNESS=%1
if "%BITNESS%"=="" set BITNESS=32
if /i "%BITNESS%"=="all" (
    call "%~f0" 32 || exit /b 1
    call "%~f0" 64 || exit /b 1
    exit /b 0
)
if /i "%BITNESS%"=="64" (
    set COMPILER=dcc64.exe
) else if /i "%BITNESS%"=="32" (
    set COMPILER=dcc32.exe
) else (
    echo Unknown bitness "%BITNESS%" ^(use 32, 64 or all^)
    exit /b 1
)

cd /d "%~dp0.."

rem --- 1. icons -------------------------------------------------------------
set PYTHON=python
where python >nul 2>&1
if errorlevel 1 (
    set PYTHON=py -3
    where py >nul 2>&1
    if errorlevel 1 (
        echo ERROR: python is required to convert the icon artwork ^(step 1^).
        exit /b 1
    )
)
echo Converting icon artwork ...
%PYTHON% scripts\convert_icons.py >nul || (
    echo Icon conversion FAILED
    exit /b 1
)

rem --- 2. resource ----------------------------------------------------------
where brcc32.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: brcc32.exe not found on PATH. Open a Delphi command prompt first.
    exit /b 1
)
echo Compiling icon resource ...
brcc32 src\PortappixIcons.rc -fo src\PortappixIcons.res >nul || (
    echo Resource compilation FAILED
    exit /b 1
)

rem --- 3. executable --------------------------------------------------------
where %COMPILER% >nul 2>&1
if errorlevel 1 (
    echo ERROR: %COMPILER% not found on PATH. Open a Delphi command prompt first.
    exit /b 1
)
if not exist bin mkdir bin
echo Building Launcher (%BITNESS%-bit) ...
%COMPILER% -B -Ebin -N0bin -Usrc src\Launcher.dpr >nul || (
    echo Launcher build FAILED
    exit /b 1
)

echo Launcher build: OK (bin\Launcher.exe, %BITNESS%-bit)
exit /b 0
