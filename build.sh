#!/bin/bash
# Build script for Mac/Linux

echo "Building Last War Capture Tool..."

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt

# Build
echo "Building executable..."
pyinstaller --onefile \
    --windowed \
    --name "LastWarCapture" \
    --hidden-import=scapy.layers.all \
    lastwar_capture.py

echo ""
echo "Build complete! Executable is in: dist/LastWarCapture"
