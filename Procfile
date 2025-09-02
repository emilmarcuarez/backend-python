release: python -m playwright install --with-deps chromium
web: gunicorn app_flask:app --bind 0.0.0.0:$PORT --workers 1 --worker-class sync --timeout 120 --keep-alive 5 --max-requests 1000 --max-requests-jitter 100 --preload
