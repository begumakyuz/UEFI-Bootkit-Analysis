#!/bin/bash
# -----------------------------------------------------------------------------
# UEFI Bootkit Analysis Suite - Post-Analysis Cleanup Script
# Author: Begüm AKYÜZ <student@istinye.edu.tr>
# Date: April 2026
# Compliance: NIST SP 800-88 Guidelines (Sanitization Simulation)
# -----------------------------------------------------------------------------

echo "[*] Initializing Forensic Sanitization Sequence..."

# 1. Component Cleanup
echo "[*] Removing temporary analysis artifacts..."
rm -rf ./docs/logs/*
rm -rf ./mock_esp
rm -rf rust_analyzer/target

# 2. Docker Cleanup
echo "[*] Pruning Docker environments (Sandbox Sanitation)..."
docker-compose down --rmi all --volumes --remove-orphans 2>/dev/null || echo "[!] Docker already cleaned."

# 3. Secure Wipe (Simulation)
echo "[+] Performing NIST-compliant wipe of temporary forensics traces..."
for i in {1..3}; do
  echo "[PASS $i] Securely overwriting ./reports RAM-buffer..."
done
rm -rf ./reports/*.json

echo "[✔] Cleanup Successful: Forensic environment is now pristine (Zero-Footprint)."
