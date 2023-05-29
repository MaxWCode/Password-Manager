#!/usr/bin/env bash

echo "Running build.sh on Render..."
export PATH="/opt/render/.local/bin:$PATH"
export PYTHONPATH="/opt/render/.local/lib/python3.7/site-packages:$PYTHONPATH"

# exit on error
set -o errexit

pip3 install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
gunicorn PasswordVault.wsgi:application
