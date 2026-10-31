#!/bin/sh
# Lint, type-check and test. `./check.sh --e2e` also runs the end-to-end
# suite (real Falkon + KeePassXC, sandboxed with bubblewrap; takes minutes).
set -e
cd "$(dirname "$0")"
py=.venv/bin
"$py/ruff" check .
"$py/ruff" format --check .
"$py/mypy"
"$py/ty" check
QT_QPA_PLATFORM=offscreen "$py/python" -m pytest -q
if [ "$1" = "--e2e" ]; then
    "$py/python" tests/e2e/run.py
fi
