@echo off
cd "%~dp0"

:: Create virtual environment
echo Creating Python virtual environment...
python -m venv .venv

:: Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

:: Install requirements
echo Installing requirements...
pip install -r requirements.txt

:: Run the main script
python src/main.py

pause
