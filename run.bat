@echo off
echo =========================================
echo    Starting IDS-Connected Firewall
echo =========================================

REM Check if the virtual environment folder exists
if not exist "venv\Scripts\activate.bat" (
    echo [1/3] Creating virtual environment...
    python -m venv venv
    
    echo [2/3] Activating environment and installing packages... (This only happens once!)
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    echo [1/2] Activating existing virtual environment...
    call venv\Scripts\activate.bat
)

echo [Ready] Starting the server...
python main.py

pause
