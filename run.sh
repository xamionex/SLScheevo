#!/bin/bash
cd "$(dirname "$(realpath "$0")")"

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv .venv

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Run the main script with preserved environment
exec python SLScheevo.py
