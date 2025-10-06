#!/bin/bash

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Please run build.sh first."
    exit 1
fi

# Activate virtual environment
source .venv/bin/activate

# Run the script
python SLScheevo.py "$@"

# Deactivate virtual environment
deactivate
