@echo off
setlocal enabledelayedexpansion

REM Script to create virtual environment and build with PyInstaller
set SCRIPT_NAME=SLScheevo.py
set OUTPUT_NAME=SLScheevo.exe

echo Setting up build environment...

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python could not be found
    echo Please make sure Python is installed and in your PATH
    pause
    exit /b 1
)

REM Create virtual environment
echo Creating virtual environment...
python -m venv .venv

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements from the provided requirements.txt
echo Installing requirements...
pip install -r requirements.txt

REM Install additional build dependencies if needed
echo Installing additional build dependencies...
pip install setuptools wheel

REM Install PyInstaller
echo Installing PyInstaller...
pip install pyinstaller

REM Create build directory
if not exist build mkdir build

REM Build with PyInstaller
echo Building executable with PyInstaller...
pyinstaller --onefile ^
            --name "%OUTPUT_NAME%" ^
            --distpath ./build ^
            --workpath ./build/temp ^
            --specpath ./build ^
            --hidden-import=steam ^
            --hidden-import=steam.client ^
            --hidden-import=steam.webauth ^
            --hidden-import=steam.enums ^
            --hidden-import=steam.core ^
            --hidden-import=steam.core.msg ^
            --hidden-import=steam.enums.common ^
            --hidden-import=steam.enums.emsg ^
            --hidden-import=configobj ^
            --hidden-import=requests ^
            --hidden-import=certifi ^
            --hidden-import=beautifulsoup4 ^
            --hidden-import=bs4 ^
            "%SCRIPT_NAME%"

REM Check if build was successful
if exist "./build/%OUTPUT_NAME%" (
    echo Build successful! Executable created: ./build/%OUTPUT_NAME%
    echo You can run it with: .\build\%OUTPUT_NAME%
) else (
    echo Build failed!
    pause
    exit /b 1
)

REM Deactivate virtual environment
call .venv\Scripts\deactivate.bat

echo Done!
pause
