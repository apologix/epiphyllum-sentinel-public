#!/bin/sh
# Compatibility entry point; secrets are initialized by Docker, without host languages.
set -eu
cd "$(dirname "$0")/.."
exec docker compose up -d --build
