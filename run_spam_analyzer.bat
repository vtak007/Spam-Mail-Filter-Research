@echo off
setlocal

set PROFILE=C:\Users\Perdi\AppData\Roaming\Thunderbird\Profiles\7cbaki9u.default-release
set ACCOUNT=ImapMail\outlook.office365.com
set PROJECT=D:\Dropbox\Computing1\BatchFiles_Scripts\Claude Projects\Spam Mail Filter Research

echo ============================================================
echo  Spam Origin Analyzer - Automated Run
echo ============================================================
echo.

echo [1/4] Checking if Thunderbird is running...
tasklist /fi "imagename eq thunderbird.exe" 2>nul | find /i "thunderbird.exe" >nul
if not errorlevel 1 (
    echo.
    echo ERROR: Thunderbird is currently running.
    echo Please close Thunderbird completely and run this script again.
    echo.
    pause
    exit /b 1
)
echo       OK - Thunderbird is not running.
echo.

echo [2/4] Copying Junk mailbox from Thunderbird profile...
copy /y "%PROFILE%\%ACCOUNT%\Junk" "%PROJECT%\Junk" >nul
if errorlevel 1 (
    echo.
    echo ERROR: Failed to copy Junk file from:
    echo   %PROFILE%\%ACCOUNT%\Junk
    echo.
    pause
    exit /b 1
)
echo       OK - Junk file copied.
echo.

echo [3/4] Running spam analyzer...
echo.
cd /d "%PROJECT%"
python spam_analyzer.py
if errorlevel 1 (
    echo.
    echo ERROR: spam_analyzer.py failed. See output above.
    echo.
    pause
    exit /b 1
)
echo.

echo [4/4] Installing msgFilterRules.dat to Thunderbird profile...
copy /y "%PROJECT%\msgFilterRules.dat" "%PROFILE%\%ACCOUNT%\msgFilterRules.dat" >nul
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install msgFilterRules.dat to:
    echo   %PROFILE%\%ACCOUNT%\msgFilterRules.dat
    echo.
    pause
    exit /b 1
)
echo       OK - msgFilterRules.dat installed.
echo.

echo ============================================================
echo  Done. Start Thunderbird and verify via:
echo  Tools ^> Message Filters
echo ============================================================
echo.
pause
