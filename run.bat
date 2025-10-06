@echo off

REM Check if virtual environment exists
if not exist ".venv" (
    echo Virtual environment not found. Please run build.bat first.
    pause
    exit /b 1
)

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Run the script
python SLScheevo.py %*

REM Deactivate virtual environment
call .venv\Scripts\deactivate.bat
