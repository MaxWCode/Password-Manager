#!/usr/bin/env bash
echo "Running build.sh on Render..."

pip install gunicorn
gunicorn PasswordVault.wsgi:application
