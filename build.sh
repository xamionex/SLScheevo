#!/bin/bash
set -e

SCRIPT_NAME="SLScheevo.py"
OUTPUT_NAME="SLScheevo"
VENV_DIR=".venv"

echo "Setting up build environment..."

# Check if Python 3 is available
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found"
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Always ensure environment is current
echo "Upgrading pip and ensuring requirements are installed..."
pip install --upgrade pip setuptools wheel pyinstaller
pip install -r requirements.txt

# Create build directory
mkdir -p build

# Build with PyInstaller
echo "Building executable with PyInstaller..."
pyinstaller --onefile \
    --name "$OUTPUT_NAME" \
    --distpath ./build \
    --workpath ./build/temp \
    --specpath ./build \
    "$SCRIPT_NAME"

# Check build success
if [ -f "./build/$OUTPUT_NAME" ] || [ -f "./build/$OUTPUT_NAME.exe" ]; then
    echo "Build successful! Executable created: ./build/$OUTPUT_NAME"
else
    read -p "Build failed!"
    exit 1
fi

deactivate
echo "Done!"
