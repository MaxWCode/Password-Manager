#!/usr/bin/env bash

echo "Running build.sh on Render..."

# exit on error
set -o errexit

pip3 install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
pip3 install git+https://github.com/benoitc/gunicorn.git
export PATH="/opt/render/.local/bin:$PATH"

