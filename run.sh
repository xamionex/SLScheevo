#!/bin/bash
cd "$(dirname "$(realpath "$0")")"

venv() {
    python3 -m venv .venv
    source .venv/bin/activate
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        echo "missing requirements.txt, slscheevo might not work"
    fi
}

if [ ! $NOVENV ]; then
    venv
else
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    else
        venv
    fi
fi

# Run the main script with preserved environment
exec python SLScheevo.py $@
