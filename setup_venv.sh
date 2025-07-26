#!/bin/bash

echo "Creating virtual environment in .venv..."
python3 -m venv .venv

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing required packages..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Launching Streamlit app..."
streamlit run frontend/app.py

#for macOS/Linux/WSL users
#run chmod +x setup_venv.sh before executing it