#!/bin/bash

# Script to create virtual environment and build with PyInstaller
SCRIPT_NAME="SLScheevo.py"
OUTPUT_NAME="SLScheevo"

echo "Setting up build environment..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 could not be found"
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv .venv

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements from the provided requirements.txt
echo "Installing requirements..."
pip install -r requirements.txt

# Install additional build dependencies if needed
echo "Installing additional build dependencies..."
pip install setuptools wheel

# Install PyInstaller
echo "Installing PyInstaller..."
pip install pyinstaller

# Create build directory
mkdir -p build

# Build with PyInstaller
echo "Building executable with PyInstaller..."
pyinstaller --onefile \
            --name "$OUTPUT_NAME" \
            --distpath ./build \
            --workpath ./build/temp \
            --specpath ./build \
            --hidden-import="steam" \
            --hidden-import="steam.client" \
            --hidden-import="steam.webauth" \
            --hidden-import="steam.enums" \
            --hidden-import="steam.core" \
            --hidden-import="steam.core.msg" \
            --hidden-import="steam.enums.common" \
            --hidden-import="steam.enums.emsg" \
            --hidden-import="configobj" \
            --hidden-import="requests" \
            --hidden-import="certifi" \
            --hidden-import="beautifulsoup4" \
            --hidden-import="bs4" \
            "$SCRIPT_NAME"

# Check if build was successful
if [ -f "./build/$OUTPUT_NAME" ]; then
    echo "Build successful! Executable created: ./build/$OUTPUT_NAME"
    echo "You can run it with: ./build/$OUTPUT_NAME"
else
    echo "Build failed!"
    exit 1
fi

# Deactivate virtual environment
deactivate

echo "Done!"
