@echo off
setlocal enabledelayedexpansion

set SCRIPT_NAME=SLScheevo.py
set OUTPUT_NAME=SLScheevo.exe
set VENV_DIR=.venv

echo Setting up build environment...

:: Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python could not be found
    echo Please make sure Python is installed and in your PATH
    pause
    exit /b 1
)

:: Create virtual environment
echo Creating Python virtual environment...
python -m venv .venv

:: Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

:: Install requirements
echo Installing requirements...
python -m pip install --upgrade pip setuptools wheel pyinstaller
pip install -r requirements.txt

REM Create build directory
if not exist build mkdir build

REM Build with PyInstaller
echo Building executable with PyInstaller...
pyinstaller --onefile ^
            --name "%OUTPUT_NAME%" ^
            --distpath ./build ^
            --workpath ./build/temp ^
            --specpath ./build ^
            "%SCRIPT_NAME%"

REM Check build result
if exist "./build/%OUTPUT_NAME%" (
    echo Build successful! Executable created: ./build/%OUTPUT_NAME%
) else (
    echo Build failed!
    pause
    exit /b 1
)

call "%VENV_DIR%\Scripts\deactivate.bat"
echo Done!
