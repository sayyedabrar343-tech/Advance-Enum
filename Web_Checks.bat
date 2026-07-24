@echo off
setlocal enabledelayedexpansion

:: ============================================
:: ULTIMATE VULNERABILITY SCANNER
:: PORTS 80,443,8443
:: ONLY CURL + WINDOWS INBUILT TOOLS
:: ONLY VULN FINDINGS (SAFE IGNORED)
:: ============================================

set "OUTPUT_DIR=Vuln_Results"
set "CSV_FILE=%OUTPUT_DIR%\Vulnerabilities.csv"
set "FULL_LOG=%OUTPUT_DIR%\Full_Scan_Log.txt"
set "TIMEOUT=10"
set "USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
echo IP,Port,Vulnerability,Risk > "%CSV_FILE%"
echo Full Scan Log - %date% %time% > "%FULL_LOG%"
echo. >> "%FULL_LOG%"

:: ============================================
:: IP LISTS
:: ============================================
set "IP_LIST_80=205.145.93.204 205.145.93.205 205.145.93.206 205.145.107.188 205.145.107.189 205.145.107.192 205.145.107.193 205.145.107.194 205.145.107.195 205.145.107.196 205.145.107.197 205.145.107.198 205.145.107.199 205.145.107.200 205.145.107.201 205.145.107.202 205.145.107.203 205.145.107.204 205.145.107.205 205.145.107.206 205.145.107.207 205.145.107.208 205.145.107.209 205.145.107.210 205.145.107.211 205.145.107.212 205.145.107.213 205.145.107.214 205.145.107.215 205.145.107.216 205.145.107.217 205.145.107.218 205.145.107.219 205.145.107.220 205.145.107.221 205.145.107.222 205.145.107.223 205.145.107.224 205.145.107.225 205.145.107.226 205.145.107.227 205.145.107.228 205.145.107.229 205.145.107.230 205.145.107.231 205.145.107.232 205.145.107.233 205.145.107.234 205.145.107.235 205.145.107.236 205.145.107.237 205.145.107.238 205.145.107.239 205.145.107.240 205.145.107.241 205.145.107.242 205.145.107.243 205.145.107.244 205.145.107.245 205.145.107.246 205.145.107.247 205.145.107.248 205.145.107.249 205.145.107.250 205.145.107.251 205.145.107.252 205.145.107.253 205.145.107.254 205.145.107.255 205.145.127.61 205.145.127.64 205.145.127.65 205.145.127.66 205.145.127.67 205.145.127.68 205.145.127.69 205.145.127.70 205.145.127.71 205.145.127.72 205.145.127.73 205.145.127.74 205.145.127.75 205.145.127.76 205.145.127.77 205.145.127.78 205.145.127.79 205.145.127.80 205.145.127.81 205.145.127.82 205.145.127.83 205.145.127.84 205.145.127.85 205.145.127.86 205.145.127.87"

set "IP_LIST_443=205.145.93.228 205.145.93.230 205.145.93.231 205.145.93.232 205.145.93.234 205.145.125.228 205.145.125.230 205.145.125.231 205.145.125.232"

set "IP_LIST_8443=205.145.93.228 205.145.93.230 205.145.93.231 205.145.93.232 205.145.93.234 205.145.125.228 205.145.125.230 205.145.125.231 205.145.125.232"

:: ============================================
:: SCAN
:: ============================================
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
echo ===== SCAN COMPLETE =====
echo Vulnerabilities Found: %CSV_FILE%
echo Full Log: %FULL_LOG%
pause
exit /b

:: ============================================
:: FUNCTION: SCAN IP:PORT
:: ============================================
:ScanIP
set "IP=%1"
set "PORT=%2"

if "%PORT%"=="80" (set "PROTO=http") else (set "PROTO=https")

set "OUTDIR=%OUTPUT_DIR%\%IP%_%PORT%"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

set "URL=%PROTO%://%IP%:%PORT%/"

echo [%PORT%] Checking %IP%... >> "%FULL_LOG%"

:: ----- HEADERS -----
curl -k -s -L -m %TIMEOUT% -A "%USER_AGENT%" -D "%OUTDIR%\headers.txt" -o nul "%URL%"
if errorlevel 1 (
    echo %IP%,%PORT%,DEAD, >> "%CSV_FILE%"
    rd /s /q "%OUTDIR%" 2>nul
    exit /b
)

set "VULN_COUNT=0"

:: ============================================
:: CHECK 1: SECURITY HEADERS
:: ============================================
set "CSP=Not Found"
set "X_FRAME=Not Found"
set "X_CONTENT_TYPE=Not Found"
set "HSTS=Not Found"
set "REFERRER=Not Found"
set "PERMISSIONS=Not Found"
set "CACHE=Not Found"

for /f "delims=" %%a in ('type "%OUTDIR%\headers.txt"') do (
    set "line=%%a"
    echo !line! | findstr /i "content-security-policy:" >nul && set "CSP=Found"
    echo !line! | findstr /i "x-frame-options:" >nul && set "X_FRAME=Found"
    echo !line! | findstr /i "x-content-type-options:" >nul && set "X_CONTENT_TYPE=Found"
    echo !line! | findstr /i "strict-transport-security:" >nul && set "HSTS=Found"
    echo !line! | findstr /i "referrer-policy:" >nul && set "REFERRER=Found"
    echo !line! | findstr /i "permissions-policy:" >nul && set "PERMISSIONS=Found"
    echo !line! | findstr /i "cache-control:" >nul && set "CACHE=Found"
)

if not "%CSP%"=="Found" (
    echo %IP%,%PORT%,Missing CSP Header,Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if not "%X_FRAME%"=="Found" (
    echo %IP%,%PORT%,Missing X-Frame-Options,Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if not "%X_CONTENT_TYPE%"=="Found" (
    echo %IP%,%PORT%,Missing X-Content-Type-Options,Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if not "%HSTS%"=="Found" (
    echo %IP%,%PORT%,Missing HSTS,Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if not "%REFERRER%"=="Found" (
    echo %IP%,%PORT%,Missing Referrer-Policy,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if not "%PERMISSIONS%"=="Found" (
    echo %IP%,%PORT%,Missing Permissions-Policy,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if not "%CACHE%"=="Found" (
    echo %IP%,%PORT%,Missing Cache-Control,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 2: COOKIE SECURITY
:: ============================================
set "COOKIE_HTTPONLY=OK"
set "COOKIE_SECURE=OK"
set "COOKIE_SAMESITE=OK"

for /f "delims=" %%a in ('type "%OUTDIR%\headers.txt"') do (
    set "line=%%a"
    echo !line! | findstr /i "set-cookie:" >nul && (
        echo !line! | findstr /i "HttpOnly" >nul || set "COOKIE_HTTPONLY=Missing"
        echo !line! | findstr /i "Secure" >nul || set "COOKIE_SECURE=Missing"
        echo !line! | findstr /i "SameSite" >nul || set "COOKIE_SAMESITE=Missing"
    )
)

if "%COOKIE_HTTPONLY%"=="Missing" (
    echo %IP%,%PORT%,Cookie missing HttpOnly flag,Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if "%COOKIE_SECURE%"=="Missing" (
    echo %IP%,%PORT%,Cookie missing Secure flag,Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
if "%COOKIE_SAMESITE%"=="Missing" (
    echo %IP%,%PORT%,Cookie missing SameSite flag,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 3: HTTP METHODS (TRACE, PUT, DELETE)
:: ============================================
curl -k -s -m %TIMEOUT% -X OPTIONS -A "%USER_AGENT%" -i "%URL%" > "%OUTDIR%\methods.txt"
type "%OUTDIR%\methods.txt" | findstr /i "TRACE" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,TRACE method enabled,High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

curl -k -s -m %TIMEOUT% -X PUT -A "%USER_AGENT%" "%URL%" 2>&1 | findstr /i "405\|200" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,PUT Method Allowed,High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

curl -k -s -m %TIMEOUT% -X DELETE -A "%USER_AGENT%" "%URL%" 2>&1 | findstr /i "405\|200" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,DELETE Method Allowed,High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 4: DIRECTORY LISTING
:: ============================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%" | findstr /i "Directory listing for\|Index of /" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Directory Listing Enabled,High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 5: WEAK TLS
:: ============================================
set "TLS_WEAK=No"
if "%PORT%"=="443" (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.0 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 set "TLS_WEAK=Yes"
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.1 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 set "TLS_WEAK=Yes"
)
if "%PORT%"=="8443" (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.0 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 set "TLS_WEAK=Yes"
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" --tlsv1.1 "%URL%" 2>&1 | findstr /i "SSL" >nul
    if not errorlevel 1 set "TLS_WEAK=Yes"
)

if "%TLS_WEAK%"=="Yes" (
    echo %IP%,%PORT%,Weak TLS version supported (v1.0/v1.1),High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 6: INFORMATION DISCLOSURE
:: ============================================
type "%OUTDIR%\headers.txt" | findstr /i "x-powered-by:" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,X-Powered-By Header Disclosure,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
type "%OUTDIR%\headers.txt" | findstr /i "x-aspnet-version:" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,ASP.NET Version Disclosure,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
type "%OUTDIR%\headers.txt" | findstr /i "server:" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Server Banner Disclosure,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)
type "%OUTDIR%\headers.txt" | findstr /i "etag:" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,ETag Header Disclosure,Low >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 7: CORS MISCONFIGURATION
:: ============================================
curl -k -s -m %TIMEOUT% -H "Origin: https://evil.com" -I "%URL%" 2>&1 | findstr /i "Access-Control-Allow-Origin:" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,CORS Wildcard (Access-Control-Allow-Origin: *),High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 8: HOST HEADER INJECTION
:: ============================================
curl -k -s -m %TIMEOUT% -H "Host: evil.com" -I "%URL%" 2>&1 | findstr /i "200 OK" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Host Header Injection Possible,High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 9: SENSITIVE FILES
:: ============================================
for %%f in (config.php .env web.config .htaccess README.md composer.json package.json backup.zip backup.sql) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -I "%URL%%%f" 2>&1 | findstr /i "200 OK" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Sensitive File Exposed (%%f),High >> "%CSV_FILE%"
        set /a VULN_COUNT+=1
    )
)

:: ============================================
:: CHECK 10: GIT/SVN EXPOSURE
:: ============================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%.git/config" | findstr /i "repositoryformatversion" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Git Exposed (.git/config),High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%.svn/entries" | findstr /i "dir" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,SVN Exposed (.svn/entries),High >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 11: SERVER STATUS / PHP INFO
:: ============================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%server-status" | findstr /i "Apache Status\|nginx" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Server Status Exposed (/server-status),Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%phpinfo.php" | findstr /i "PHP Version" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,PHP Info Exposed (/phpinfo.php),Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 12: AWS METADATA (SSRF)
:: ============================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "http://169.254.169.254/latest/meta-data/" | findstr /i "instance-id" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,AWS Metadata Accessible (SSRF),Critical >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: CHECK 13: ADMIN PANELS
:: ============================================
for %%p in (admin administrator login dashboard wp-admin cpanel phpmyadmin manager adminpanel) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" "%URL%%%p/" -o "%OUTDIR%\%%p.html"
    findstr /i "Login\|Sign In\|Dashboard\|Admin" "%OUTDIR%\%%p.html" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Admin Panel Exposed (/%%p/),High >> "%CSV_FILE%"
        set /a VULN_COUNT+=1
    )
)

:: ============================================
:: CHECK 14: API EXPOSURE
:: ============================================
for %%a in (api/ api/v1/ swagger/ swagger.json openapi.json graphql) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -I "%URL%%%a" 2>&1 | findstr /i "200 OK" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,API Endpoint Exposed (%%a),Medium >> "%CSV_FILE%"
        set /a VULN_COUNT+=1
    )
)

:: ============================================
:: CHECK 15: BACKUP FILES (EXTRA)
:: ============================================
for %%b in (backup.old backup.sql database.sql dump.sql) do (
    curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -I "%URL%%%b" 2>&1 | findstr /i "200 OK" >nul
    if not errorlevel 1 (
        echo %IP%,%PORT%,Backup File Exposed (%%b),High >> "%CSV_FILE%"
        set /a VULN_COUNT+=1
    )
)

:: ============================================
:: CHECK 16: OPEN REDIRECT
:: ============================================
curl -k -s -m %TIMEOUT% -A "%USER_AGENT%" -L "%URL%?redirect=http://evil.com" 2>&1 | findstr /i "evil.com" >nul
if not errorlevel 1 (
    echo %IP%,%PORT%,Open Redirect Possible (?redirect=),Medium >> "%CSV_FILE%"
    set /a VULN_COUNT+=1
)

:: ============================================
:: ONLY SAVE IF VULN FOUND
:: ============================================
if %VULN_COUNT% GTR 0 (
    (
        echo ========================================
        echo VULNERABILITIES FOUND
        echo Target: %IP%:%PORT%
        echo Total Vulnerabilities: %VULN_COUNT%
        echo ========================================
        echo.
        type "%CSV_FILE%" | findstr /i "%IP%:%PORT%"
    ) > "%OUTDIR%\vuln_summary.txt"

    echo [🔴] %IP%:%PORT% - %VULN_COUNT% vuln(s) found
    echo %IP%:%PORT% - %VULN_COUNT% vuln(s) found >> "%FULL_LOG%"
) else (
    rd /s /q "%OUTDIR%" 2>nul
    echo %IP%:%PORT% - No vulnerabilities found >> "%FULL_LOG%"
)

exit /b