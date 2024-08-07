@echo off
setlocal enabledelayedexpansion

if "%1"=="" (
    echo Usage: analyze_package package-name
    exit /b 1
)

set PACKAGE_NAME=%1
set WORK_DIR=%~dp0%PACKAGE_NAME%
set HASH_FILE=%~dp0hash.csv

if exist "%WORK_DIR%" rd /s /q "%WORK_DIR%"
mkdir "%WORK_DIR%"
cd "%WORK_DIR%"


if not exist "%HASH_FILE%" (
    echo Creating %HASH_FILE%...
    type nul > "%HASH_FILE%"
)

for /f "tokens=*" %%i in ('python c:/scripts/analyse_package.py %PACKAGE_NAME%') do (
    set "OUTPUT=%%i"
    echo DEBUG: Output=!OUTPUT!
    if "!OUTPUT:~0,4!"=="URL:" (
        set "PACKAGE_URL=!OUTPUT:~5!"
    ) else if "!OUTPUT:~0,6!"=="Score:" (
        set "SCORE=!OUTPUT:~7!"
        echo DEBUG: Score=!SCORE!
        set "GLOBAL_SCORE=!SCORE!"
    )
)

if %SCORE% GEQ 5 (
    goto :CONTINUES
) else (
    echo The vulnerability score is below 5, please refer to the vulnerability report.
    echo FAILED
    goto :END
)

:CONTINUES

if "%PACKAGE_URL%"=="" (
    echo ERROR: No URL returned for package %PACKAGE_NAME%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

curl -O %PACKAGE_URL%
if %errorlevel% neq 0 (
    echo ERROR: Failed to download package from %PACKAGE_URL%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

set PACKAGE_FILE=
for %%f in (*.tar.gz) do set PACKAGE_FILE=%%f
for %%f in (*.zip) do set PACKAGE_FILE=%%f

if "%PACKAGE_FILE%"=="" (
    echo ERROR: No package file found for %PACKAGE_NAME%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

certutil -hashfile "%PACKAGE_FILE%" SHA256 > temp_hash.txt
set /p FILE_HASH=<temp_hash.txt

for /f "skip=1 delims=" %%a in ('type temp_hash.txt ^| findstr /r /v "^CertUtil"') do (
    set "FILE_HASH=%%a"
    goto hash_extracted
)
:hash_extracted

set FILE_HASH=%FILE_HASH: =%

findstr /c:"!FILE_HASH!" "%HASH_FILE%" >nul

if %errorlevel% equ 0 (
    echo Hash already exists in %HASH_FILE%, stopping further analysis.
    goto :INSTALL_PACKAGE
) else (
    echo Hash not found in %HASH_FILE%, continuing analysis.
)

for %%f in (*.tar.gz) do tar -xvf %%f >nul 2>&1
for %%f in (*.zip) do tar -xvf %%f >nul 2>&1

set EXTRACTED_DIR=
for /d %%d in (%WORK_DIR%\*) do (
    set EXTRACTED_DIR=%%d
    cd !EXTRACTED_DIR!
    goto :FOUND_DIR
)
:FOUND_DIR

if "%EXTRACTED_DIR%"=="" (
    echo ERROR: Failed to extract package %PACKAGE_NAME%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

:: Check if __init__.py exists
if not exist "__init__.py" (
    echo No __init__.py found, creating a placeholder.
    echo # Placeholder > __init__.py
)

if exist requirements.txt (
    echo Installing dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install dependencies for %PACKAGE_NAME%.
        cd %~dp0
        rd /s /q "%WORK_DIR%"
        exit /b 1
    )
)


:: Scan the package with YARA rule using yara_scan.py
echo Scanning package: %PACKAGE_FILE% with yara_scan.py
python c:/scripts/yara_scan.py %EXTRACTED_DIR% %PACKAGE_NAME% > yara_temp.txt 2>&1
set /p YARA_RESULT=<yara_temp.txt
type yara_temp.txt
del yara_temp.txt > nul

:: Check YARA scan result for matches
echo %YARA_RESULT% | findstr /c:"Files with matches: 0, Total matches: 0" >nul
if %errorlevel% neq 0 (
    echo ERROR: yara_scan.py identified potential issues with %PACKAGE_FILE%.
    echo The hash %FILE_HASH% for file %PACKAGE_FILE% can be used to update %HASH_FILE% if it is a false positive.
    echo FAILED
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
) else (
    echo No YARA matches found. Proceeding with static analysis.
)

echo Running Pylint...
pylint . > pylint_report.txt

set PYLINT_SCORE=0
set "filepath=pylint_report.txt"


for /f "tokens=*" %%A in (%filepath%) do (
    set "line=%%A"
    if "!line:Your code has been rated at=!" neq "!line!" (
        set "line=!line:Your code has been rated at =!"
        for /f "tokens=1 delims=/" %%B in ("!line!") do (
            set "rating=%%B"
        )
    )
)

if defined rating (
    set "rating=%rating:.=,%"
    powershell -Command "$rating=[double]::Parse('%rating:,=.%'); Write-Output $rating" > temp_rating.txt
    set /p rating=<temp_rating.txt
    del temp_rating.txt
    set PYLINT_SCORE=%rating%
) else (
    echo Cannot find pylint score in the file.
    set PYLINT_SCORE=0
)

set "int_pylint_score=%PYLINT_SCORE:.=%"

if %int_pylint_score%==0 (
    echo Pylint score not found, using global score found through vulnerability analysis.
    set AVERAGE_SCORE=%GLOBAL_SCORE%
) else (
    powershell -Command "$avg=[math]::Round((%PYLINT_SCORE% + %GLOBAL_SCORE%) / 2, 2); Write-Output $avg" > temp_avg.txt
    set /p AVERAGE_SCORE=<temp_avg.txt
    del temp_avg.txt
)

echo PYLINT_SCORE: %PYLINT_SCORE%
echo FINAL_SAFETY_SCORE: %AVERAGE_SCORE%

if %AVERAGE_SCORE% GEQ 6 (
    echo %PACKAGE_FILE%,%FILE_HASH% >> "%HASH_FILE%"
    echo The hash %FILE_HASH% for file %PACKAGE_FILE% has been added to %HASH_FILE%.
    echo PASSED
    goto :INSTALL_PACKAGE
) else (
    echo The average score is below 6, please refer to the vulnerability report.
    echo FAILED
    goto :END
)

:INSTALL_PACKAGE
cd %~dp0
rd /s /q "%WORK_DIR%"
echo Installing the package...
pip install %PACKAGE_NAME%

:END
cd %~dp0

