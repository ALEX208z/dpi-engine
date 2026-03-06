@echo off
REM ── Quick run script (after build-and-run.bat has been run once) ──────────

if "%1"=="" (
    echo Usage: run.bat yourfile.pcap [options]
    echo.
    echo Examples:
    echo   run.bat test_dpi.pcap
    echo   run.bat test_dpi.pcap --block-app YouTube
    echo   run.bat test_dpi.pcap --block-app YouTube --block-app TikTok
    echo   run.bat test_dpi.pcap --block-ip 192.168.1.50
    echo   run.bat test_dpi.pcap --block-domain facebook
    echo.
    pause
    exit /b
)

java -cp out com.dpi.Main %*
pause
