#!/bin/bash

# Build first
./build.sh

# Activate virtual environment
source .venv/bin/activate

# Run the script
python SLScheevo.py "$@"

# Deactivate virtual environment
deactivate
