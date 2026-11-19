#!/bin/sh
set -eu

cd "$(dirname "$0")"
export PORT="${PORT:-18320}"
export RACK_ENV=production
exec bundle exec puma --no-config --workers 0 --threads 1:16 --bind "tcp://127.0.0.1:$PORT" config.ru
