#!/usr/bin/env bash
# vault-dev.sh — start a Vault dev server with PKI enabled and a test root CA.
# Usage: ./vault-dev.sh [path/to/vault]
# Default vault binary: ./vault

set -euo pipefail

VAULT="${1:-./vault}"
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="root"
VAULT_PID_FILE="/tmp/vault-dev.pid"
VAULT_LOG="/tmp/vault-dev.log"

stop_existing() {
  if [ -f "$VAULT_PID_FILE" ]; then
    old_pid=$(cat "$VAULT_PID_FILE")
    if kill -0 "$old_pid" 2>/dev/null; then
      echo "Stopping existing Vault dev server (pid $old_pid)..."
      kill "$old_pid"
      sleep 1
    fi
    rm -f "$VAULT_PID_FILE"
  fi
  # Also kill any stray vault dev processes on 8200.
  pkill -f "vault server -dev" 2>/dev/null || true
  sleep 1
}

stop_existing

echo "Starting Vault dev server..."
"$VAULT" server -dev -dev-root-token-id=root >"$VAULT_LOG" 2>&1 &
echo $! >"$VAULT_PID_FILE"
VAULT_PID=$!

# Wait for Vault to be ready.
export VAULT_ADDR VAULT_TOKEN
echo -n "Waiting for Vault"
for i in $(seq 1 20); do
  if "$VAULT" status >/dev/null 2>&1; then
    echo " ready."
    break
  fi
  echo -n "."
  sleep 0.5
done

# Enable PKI secrets engine.
echo "Enabling PKI secrets engine..."
"$VAULT" secrets enable pki
"$VAULT" secrets tune -max-lease-ttl=87600h pki

# Generate root CA.
echo "Generating root CA..."
"$VAULT" write -format=json pki/root/generate/internal \
  common_name="CertForge-Test-Root-CA" \
  ttl=87600h | tee /tmp/vault-root-ca.json | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('Root CA serial:', d['data']['serial_number'])
"

# Configure CRL and issuing cert URLs.
"$VAULT" write pki/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

# Create a role for issuing test certs.
echo "Creating 'test-role' for issuing certs..."
"$VAULT" write pki/roles/test-role \
  allow_any_name=true \
  max_ttl=8760h

# Issue a couple of test certificates so the inventory has something to sync.
echo "Issuing test certificates..."
for cn in "test-server.example.com" "test-device.internal"; do
  "$VAULT" write -format=json pki/issue/test-role \
    common_name="$cn" ttl=720h | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('  Issued:', '$cn', '— serial', d['data']['serial_number'])
"
done

echo ""
echo "============================================"
echo "  Vault dev server running  (pid $VAULT_PID)"
echo "  VAULT_ADDR  = $VAULT_ADDR"
echo "  VAULT_TOKEN = $VAULT_TOKEN"
echo "  Log:          $VAULT_LOG"
echo "  Stop:         kill $VAULT_PID   (or re-run this script)"
echo "============================================"
echo ""
echo "Connector config (vault_pki section):"
echo "  addr:  $VAULT_ADDR"
echo "  token: $VAULT_TOKEN"
echo "  mount: pki"
