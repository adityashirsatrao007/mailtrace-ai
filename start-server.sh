#!/bin/bash
cd "/home/aditya/Documents/Default Project/mailtrace-ai/backend"
source venv/bin/activate
exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
