#!/usr/bin/env bash

echo "Running build.sh on Render..."

# exit on error
set -o errexit

pip install -r requirements.txt
export PATH="/opt/render/.local/bin:$PATH"
python manage.py collectstatic --no-input
python manage.py migrate
sudo apt install gunicorn3