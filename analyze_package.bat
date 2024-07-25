@echo off
setlocal enabledelayedexpansion

:: Check if a package name is provided
if "%1"=="" (
    echo Usage: analyze_package package-name
    exit /b 1
)

set PACKAGE_NAME=%1
set WORK_DIR=%~dp0%PACKAGE_NAME%

:: Set the file path for the hash storage CSV file
set HASH_FILE=%~dp0hash.csv

:: Create a temporary directory for the package
if exist "%WORK_DIR%" rd /s /q "%WORK_DIR%"
mkdir "%WORK_DIR%"
cd "%WORK_DIR%"

:: Ensure hash.csv exists
if not exist "%HASH_FILE%" (
    echo Creating %HASH_FILE%...
    type nul > "%HASH_FILE%"
)


:: Call analyse_package.py with the package name as an argument and capture the output
for /f "tokens=*" %%i in ('python c:/scripts/analyse_package.py %PACKAGE_NAME%') do (
    set "OUTPUT=%%i"
    echo DEBUG: Output=!OUTPUT!
    if "!OUTPUT:~0,4!"=="URL:" (
        set "PACKAGE_URL=!OUTPUT:~5!"
    ) else if "!OUTPUT:~0,6!"=="Score:" (
        set "SCORE=!OUTPUT:~7!"
    )
)

:: Debugging output
echo DEBUG: Package URL=%PACKAGE_URL%
echo DEBUG: Score=%SCORE%

:: Check if the URL was captured
if "%PACKAGE_URL%"=="" (
    echo ERROR: No URL returned for package %PACKAGE_NAME%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

:: Download the package using curl
curl -O %PACKAGE_URL%
if %errorlevel% neq 0 (
    echo ERROR: Failed to download package from %PACKAGE_URL%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)
:: Calculate the hash code of the downloaded package
set PACKAGE_FILE=
for %%f in (*.tar.gz) do set PACKAGE_FILE=%%f
for %%f in (*.zip) do set PACKAGE_FILE=%%f

if "%PACKAGE_FILE%"=="" (
    echo ERROR: No package file found for %PACKAGE_NAME%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

:: Calculate the hash code of the downloaded package and extract the hash
certutil -hashfile "%PACKAGE_FILE%" SHA256 > temp_hash.txt
set /p FILE_HASH=<temp_hash.txt

:: Extract only the hash value (skip the certutil output lines)
for /f "skip=1 delims=" %%a in ('type temp_hash.txt ^| findstr /r /v "^CertUtil"') do (
    set "FILE_HASH=%%a"
    goto hash_extracted
)
:hash_extracted

:: Remove any trailing spaces from the hash value
set FILE_HASH=%FILE_HASH: =%

:: Check if the hash exists in the hash.csv file
findstr /c:"!FILE_HASH!" "%HASH_FILE%" >nul

if %errorlevel% equ 0 (
    echo Hash already exists in %HASH_FILE%, stopping further analysis.
    goto :END
) else (
    echo Hash not found in %HASH_FILE%, continuing analysis.
)


:: Extract the package
for %%f in (*.tar.gz) do tar -xvf %%f
for %%f in (*.zip) do tar -xvf %%f

:: Change to the extracted package directory
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

:: List dependencies from requirements.txt if it exists within the whole directory
set REQUIREMENTS_FILE=
set REQor /r %%f in (requirements.txt) do (
   set REQUIREMENTS_FIL=%%f
 )
:FOUND_REQUIREMENTS

if defined REQUIREMENTS_FILE (
    echo Listing dependencies from !REQUIREMENTS_FILE!:
    type "!REQUIREMENTS_FILE!"
) else (
    echo No requirements.txt found.
)
:: Check if __init__.py exists
if not exist "__init__.py" (
    echo No __init__.py found, creating a placeholder.
    echo # Placeholder > __init__.py
)

:: Install package dependencies
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
python c:/scripts/yara_scan.py %EXTRACTED_DIR% > yara_temp.txt 2>&1
set /p YARA_RESULT=<yara_temp.txt
type yara_temp.txt
del yara_temp.txt > nul

:: Check YARA scan result for matches
echo %YARA_RESULT% | findstr /c:"Files with matches: 0, Total matches: 0" >nul
if %errorlevel% neq 0 (
    echo ERROR: yara_scan.py identified potential issues with %PACKAGE_FILE%.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
) else (
    echo No YARA matches found. Proceeding with hash storage.
    :: Append the file name and hash to the hash storage CSV file
    echo %PACKAGE_FILE%,%FILE_HASH% >> "%HASH_FILE%"
    echo The hash %FILE_HASH% for file %PACKAGE_FILE% has been added to %HASH_FILE%.
)

:: Run static analysis
echo Running Pylint...
pylint . > pylint_report.txt

set PYLINT_SCORE=0
for /f "tokens=6 delims= " %%i in ('type pylint_report.txt ^| findstr /c:"Your code has been rated at"') do (
    set "SCORE=%%i"
)

:: Check if SCORE was set
if not defined SCORE (
    echo ERROR: Pylint analysis failed.
    cd %~dp0
    rd /s /q "%WORK_DIR%"
    exit /b 1
)

:: Remove the decimal point from the SCORE and convert it to a numeric value
echo SCORE before conversion: %SCORE%
set "SCORE=%SCORE:.=%"
echo SCORE after conversion: %SCORE%
set /a PYLINT_SCORE=%SCORE%

:: Calculate average score
echo PYLINT_SCORE: %PYLINT_SCORE%
if %PYLINT_SCORE%==0 (
    set AVERAGE_SCORE=%SCORE%
) else (
    set /a AVERAGE_SCORE=(%SCORE% + %PYLINT_SCORE%) / 2
)

:: Check if average score is higher than 6
if %AVERAGE_SCORE% GEQ 6 (
    :: Store the score in a file for future use
    echo %PACKAGE_NAME%,%AVERAGE_SCORE% >> "%HASH_FILE%"
)

:END
cd %~dp0
rd /s /q "%WORK_DIR%"


echo Analysis complete!
