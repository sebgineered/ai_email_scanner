@echo off
echo Creating virtual environment in .venv...
python -m venv .venv

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Installing required packages...
pip install --upgrade pip
pip install -r requirements.txt

echo Launching Streamlit app...
streamlit run frontend/app.py

pause
