@echo off
echo ===================================
echo SAP Audit Tool - Setup Script
echo ===================================

REM Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Python not found! Please install Python 3.7+ and try again.
    exit /b 1
)

REM Check Python version
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)"
if %ERRORLEVEL% neq 0 (
    echo Python 3.7 or higher is required.
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist venv\ (
    echo Creating virtual environment...
    python -m venv venv
) else (
    echo Virtual environment already exists.
)

REM Activate virtual environment and install dependencies
echo Activating virtual environment...
call venv\Scripts\activate

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo ===================================
echo Setup completed successfully!
echo.
echo To activate the virtual environment:
echo   call venv\Scripts\activate
echo.
echo To run the SAP Audit Tool:
echo   python run_sap_audit.py
echo ===================================
