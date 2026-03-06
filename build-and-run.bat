@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================
echo   DPI Engine - Build and Run Script
echo ============================================
echo.

REM Step 1: Check Java
echo [1/4] Checking Java...
java --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Java not found. Install JDK from https://adoptium.net
    pause
    exit /b 1
)
java --version
echo Java found!
echo.

REM Step 2: Check javac
echo [2/4] Checking Java compiler (javac)...
javac --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: javac not found. Install JDK (not JRE) from https://adoptium.net
    pause
    exit /b 1
)
javac --version
echo Compiler found!
echo.

REM Step 3: Compile
echo [3/4] Compiling source code...
if not exist "out" mkdir out

REM Save file list to TEMP to avoid spaces-in-path issue
dir /s /b "src\*.java" > "%TEMP%\dpi_sources.txt"

REM Compile (no --release flag to avoid version issues)
javac -d out "@%TEMP%\dpi_sources.txt"

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed.
    del "%TEMP%\dpi_sources.txt" 2>nul
    pause
    exit /b 1
)
del "%TEMP%\dpi_sources.txt" 2>nul
echo Compilation successful!
echo.

REM Step 4: Run
echo [4/4] Running...
echo.
if exist "test_dpi.pcap" (
    java -cp out com.dpi.Main test_dpi.pcap output.pcap %*
    echo.
    echo Done! Output written to output.pcap
) else (
    echo No test_dpi.pcap found.
    echo Usage: java -cp out com.dpi.Main yourfile.pcap output.pcap
)

echo.
pause
