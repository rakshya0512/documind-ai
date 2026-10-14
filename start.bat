@echo off
REM One command: build the frontend and run everything on http://localhost:8000
cd /d "%~dp0"
cd frontend
call npm install --no-audit --no-fund || exit /b 1
call npm run build || exit /b 1
cd ..
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
pip install -r backend\requirements.txt || exit /b 1
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
