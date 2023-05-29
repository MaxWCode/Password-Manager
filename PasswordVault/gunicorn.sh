#!/usr/bin/env bash
gunicorn PasswordVault.wsgi:application
