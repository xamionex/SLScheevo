@echo off

REM build first
build.bat

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Run the script
python SLScheevo.py %*

REM Deactivate virtual environment
call .venv\Scripts\deactivate.bat
