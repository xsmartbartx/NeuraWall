#!/usr/bin/env bash
# Run the control plane locally with synthetic demo traffic.
# Console: http://localhost:8080  (admin@neurawall.local / Demo-Admin-Pass-1!)
set -euo pipefail
cd "$(dirname "$0")/.."
export NEURAWALL_DEMO_MODE=true
export NEURAWALL_DATA_DIR="${NEURAWALL_DATA_DIR:-./data}"
export NEURAWALL_LOG_JSON=false
export NEURAWALL_AUTH__BOOTSTRAP_ADMIN_PASSWORD="${NEURAWALL_AUTH__BOOTSTRAP_ADMIN_PASSWORD:-Demo-Admin-Pass-1!}"
export NEURAWALL_POLICY__ROLLOUT_STAGE_SECONDS="${NEURAWALL_POLICY__ROLLOUT_STAGE_SECONDS:-60}"
exec uv run neurawall server --port "${PORT:-8080}"
