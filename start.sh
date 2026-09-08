#!/bin/bash
# MailTrace AI - Production Startup

echo "=== MailTrace AI ==="
echo "Starting backend..."

cd "$(dirname "$0")/backend"
source venv/bin/activate
exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
