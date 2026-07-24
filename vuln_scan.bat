@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: ULTIMATE VULNERABILITY SCANNER
:: PORTS: 80, 443, 8443
:: SIRF VULNERABLE CHEEZEIN CAPTURE KAREGA
:: SAFE IPs KA FOLDER DELETE HO JAYEGA
:: ============================================================

set "OUTPUT_DIR=Vuln_Results"
set "CSV_FILE=%OUTPUT_DIR%\Vulnerabilities.csv"
set "TIMEOUT=10"
set "USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
echo IP,Port,Vulnerability,Risk > "%CSV_FILE%"

:: ============================================================
:: 🔴 YAHAN APNE IP ADDRESS DAALO
:: ============================================================
set "IP_LIST_80=205.145.93.204 205.145.93.205"
set "IP_LIST_443=205.145.93.228 205.145.93.230"
set "IP_LIST_8443=205.145.93.228 205.145.93.230"

:: ============================================================
:: SCAN START
:: ============================================================
echo.
echo ============================================
echo ULTIMATE VULNERABILITY SCANNER
echo ============================================
echo.

echo [*] Scanning Port 80...
for %%i in (%IP_LIST_80%) do call :ScanIP %%i 80

echo.
echo [*] Scanning Port 443...
for %%i in (%IP_LIST_443%) do call :ScanIP %%i 443

echo.
echo [*] Scanning Port 8443...
for %%i in (%IP_LIST_8443%) do call :ScanIP %%i 8443

echo.
echo ============================================
echo SCAN COMPLETE
echo ============================================
echo Vulnerabilities saved in: %CSV_FILE%
pause
exit /b

:: ============================================================
:: FUNCTION: SCAN IP:PORT
:: ============================================================
:ScanIP
set "IP=%1"
set "PORT=%2"

if "%PORT%"=="80" (set "PROTO=http") else (set "PROTO=https")

set "OUTDIR=%OUTPUT_DIR%\%IP%_%PORT%"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

set "URL=%PROTO%://%IP%:%PORT%/"

echo [%PORT%] Checking %IP%...

curl -k -s -L -m %TIMEOUT% -A "%USER_AGENT%" -D "%OUTDIR%\headers.txt" -o nul "%URL%"
if errorlevel 1 (
    rd /s /q "%OUTDIR%" 2>nul
    exit /b
)

set "VULN=0"

:: ============================================================
:: 1. MISSING SECURITY HEADERS
:: ============================================================
findstr /i "content-security-policy:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Missing CSP Header,Medium
    echo %IP%,%PORT%,Missing CSP Header,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "x-frame-options:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Missing X-Frame-Options,Medium
    echo %IP%,%PORT%,Missing X-Frame-Options,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "x-content-type-options:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Missing X-Content-Type-Options,Medium
    echo %IP%,%PORT%,Missing X-Content-Type-Options,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "strict-transport-security:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Missing HSTS,Medium
    echo %IP%,%PORT%,Missing HSTS,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "referrer-policy:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Missing Referrer-Policy,Low
    echo %IP%,%PORT%,Missing Referrer-Policy,Low >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "permissions-policy:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Missing Permissions-Policy,Low
    echo %IP%,%PORT%,Missing Permissions-Policy,Low >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 2. COOKIE SECURITY FLAGS
:: ============================================================
set "HTTPONLY=OK"
set "SECURE=OK"
for /f "delims=" %%a in ('findstr /i "set-cookie:" "%OUTDIR%\headers.txt"') do (
    set "line=%%a"
    echo !line! | findstr /i "HttpOnly" >nul || set "HTTPONLY=MISSING"
    echo !line! | findstr /i "Secure" >nul || set "SECURE=MISSING"
)

if "!HTTPONLY!"=="MISSING" (
    echo %IP%,%PORT%,Cookie Missing HttpOnly,Medium
    echo %IP%,%PORT%,Cookie Missing HttpOnly,Medium >> "%CSV_FILE%"
    set "VULN=1"
)
if "!SECURE!"=="MISSING" (
    echo %IP%,%PORT%,Cookie Missing Secure,Medium
    echo %IP%,%PORT%,Cookie Missing Secure,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 3. TRACE METHOD ENABLED
:: ============================================================
curl -k -s -m %TIMEOUT% -X OPTIONS -A "%USER_AGENT%" -i "%URL%" > "%OUTDIR%\methods.txt"
findstr /i "TRACE" "%OUTDIR%\methods.txt" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,TRACE Method Enabled,High
    echo %IP%,%PORT%,TRACE Method Enabled,High >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 4. PUT / DELETE METHODS
:: ============================================================
curl -k -s -m %TIMEOUT% -X PUT -A "%USER_AGENT%" "%URL%" 2>&1 | findstr /i "405\|200" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,PUT Method Allowed,High
    echo %IP%,%PORT%,PUT Method Allowed,High >> "%CSV_FILE%"
    set "VULN=1"
)

curl -k -s -m %TIMEOUT% -X DELETE -A "%USER_AGENT%" "%URL%" 2>&1 | findstr /i "405\|200" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,DELETE Method Allowed,High
    echo %IP%,%PORT%,DELETE Method Allowed,High >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 5. DIRECTORY LISTING
:: ============================================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%" | findstr /i "Directory listing for\|Index of /" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Directory Listing Enabled,High
    echo %IP%,%PORT%,Directory Listing Enabled,High >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 6. WEAK TLS (443 & 8443)
:: ============================================================
if "%PORT%"=="443" (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.0 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Weak TLS v1.0 Supported,High
        echo %IP%,%PORT%,Weak TLS v1.0 Supported,High >> "%CSV_FILE%"
        set "VULN=1"
    )
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.1 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Weak TLS v1.1 Supported,High
        echo %IP%,%PORT%,Weak TLS v1.1 Supported,High >> "%CSV_FILE%"
        set "VULN=1"
    )
)

if "%PORT%"=="8443" (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.0 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Weak TLS v1.0 Supported,High
        echo %IP%,%PORT%,Weak TLS v1.0 Supported,High >> "%CSV_FILE%"
        set "VULN=1"
    )
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.1 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Weak TLS v1.1 Supported,High
        echo %IP%,%PORT%,Weak TLS v1.1 Supported,High >> "%CSV_FILE%"
        set "VULN=1"
    )
)

:: ============================================================
:: 7. CORS WILDCARD MISCONFIGURATION
:: ============================================================
curl -k -s -m %TIMEOUT% -H "Origin: https://evil.com" -I "%URL%" 2>&1 | findstr /i "Access-Control-Allow-Origin: \*" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,CORS Wildcard (*),High
    echo %IP%,%PORT%,CORS Wildcard (*),High >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 8. HOST HEADER INJECTION
:: ============================================================
curl -k -s -m %TIMEOUT% -H "Host: evil.com" -I "%URL%" 2>&1 | findstr /i "200 OK" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Host Header Injection,High
    echo %IP%,%PORT%,Host Header Injection,High >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 9. SENSITIVE FILES
:: ============================================================
for %%f in (.env config.php web.config .htaccess backup.sql) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -I "%URL%%%f" 2>&1 | findstr /i "200 OK" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Sensitive File (%%f),High
        echo %IP%,%PORT%,Sensitive File (%%f),High >> "%CSV_FILE%"
        set "VULN=1"
    )
)

:: ============================================================
:: 10. GIT / SVN EXPOSURE
:: ============================================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%.git/config" | findstr /i "repositoryformatversion" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Git Exposed (.git/config),High
    echo %IP%,%PORT%,Git Exposed (.git/config),High >> "%CSV_FILE%"
    set "VULN=1"
)

curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%.svn/entries" | findstr /i "dir" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,SVN Exposed (.svn/entries),High
    echo %IP%,%PORT%,SVN Exposed (.svn/entries),High >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 11. SERVER STATUS / PHP INFO
:: ============================================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%server-status" | findstr /i "Apache\|nginx" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Server Status Exposed,Medium
    echo %IP%,%PORT%,Server Status Exposed,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%phpinfo.php" | findstr /i "PHP Version" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,PHP Info Exposed,Medium
    echo %IP%,%PORT%,PHP Info Exposed,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 12. AWS METADATA (SSRF)
:: ============================================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "http://169.254.169.254/latest/meta-data/" | findstr /i "instance-id" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,AWS Metadata Accessible (SSRF),Critical
    echo %IP%,%PORT%,AWS Metadata Accessible (SSRF),Critical >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 13. ADMIN PANELS
:: ============================================================
for %%p in (admin login dashboard) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%%%p/" -o nul 2>&1 | findstr /i "Login\|Admin" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Admin Panel (/%%p/),High
        echo %IP%,%PORT%,Admin Panel (/%%p/),High >> "%CSV_FILE%"
        set "VULN=1"
    )
)

:: ============================================================
:: 14. API EXPOSURE
:: ============================================================
for %%a in (api/ swagger/ graphql) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -I "%URL%%%a" 2>&1 | findstr /i "200 OK" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,API Endpoint Exposed (%%a),Medium
        echo %IP%,%PORT%,API Endpoint Exposed (%%a),Medium >> "%CSV_FILE%"
        set "VULN=1"
    )
)

:: ============================================================
:: 15. OPEN REDIRECT
:: ============================================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -L "%URL%?redirect=http://evil.com" 2>&1 | findstr /i "evil.com" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Open Redirect Possible,Medium
    echo %IP%,%PORT%,Open Redirect Possible,Medium >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 16. BACKUP FILES
:: ============================================================
for %%b in (backup.old backup.sql database.sql) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -I "%URL%%%b" 2>&1 | findstr /i "200 OK" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Backup File (%%b),High
        echo %IP%,%PORT%,Backup File (%%b),High >> "%CSV_FILE%"
        set "VULN=1"
    )
)

:: ============================================================
:: 17. INFORMATION DISCLOSURE
:: ============================================================
findstr /i "x-powered-by:" "%OUTDIR%\headers.txt" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,X-Powered-By Disclosure,Low
    echo %IP%,%PORT%,X-Powered-By Disclosure,Low >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "x-aspnet-version:" "%OUTDIR%\headers.txt" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,ASP.NET Version Disclosure,Low
    echo %IP%,%PORT%,ASP.NET Version Disclosure,Low >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "server:" "%OUTDIR%\headers.txt" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Server Banner Disclosure,Low
    echo %IP%,%PORT%,Server Banner Disclosure,Low >> "%CSV_FILE%"
    set "VULN=1"
)

findstr /i "etag:" "%OUTDIR%\headers.txt" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,ETag Disclosure,Low
    echo %IP%,%PORT%,ETag Disclosure,Low >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: 18. CACHE CONTROL MISSING
:: ============================================================
findstr /i "cache-control:" "%OUTDIR%\headers.txt" >nul
if errorlevel 1 (
    echo %IP%,%PORT%,Cache-Control Missing,Low
    echo %IP%,%PORT%,Cache-Control Missing,Low >> "%CSV_FILE%"
    set "VULN=1"
)

:: ============================================================
:: CLEANUP
:: ============================================================
if "!VULN!"=="0" (
    rd /s /q "%OUTDIR%" 2>nul
) else (
    echo [🔴] %IP%:%PORT% - Vulnerabilities Found
)

exit /b