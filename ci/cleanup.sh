#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
compose down --volumes --remove-orphans >/dev/null 2>&1 || true
