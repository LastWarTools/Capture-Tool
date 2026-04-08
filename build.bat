@echo off
echo Building Last War Capture Tool...
echo.

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.8+ first.
    pause
    exit /b 1
)

:: Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

:: Build exe
echo.
echo Building executable...
pyinstaller --onefile ^
    --windowed ^
    --name "LastWarCapture" ^
    --hidden-import=scapy.layers.all ^
    --hidden-import=scapy.arch.windows ^
    lastwar_capture.py

echo.
echo Build complete! Executable is in: dist\LastWarCapture.exe
echo.
pause
