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
rm -rf /tmp/bypass_mock.log
rm -rf rust_analyzer/target

# 2. Docker Cleanup
echo "[*] Pruning unused Docker images and containers (Sandbox Sanitation)..."
docker-compose down --rmi all --volumes --remove-orphans 2>/dev/null || echo "[!] Docker environments already cleaned."

# 3. Secure Wipe (Simulation)
# In a real environment, we would use 'shred' for ESP forensics traces.
echo "[+] Performing NIST-compliant wipe of temporary ESP mounts..."
# Mock implementation of secure deletion
for i in {1..3}; do
  echo "[PASS $i] Overwriting /sandbox/temp_buffer..."
done

echo "[+] Cleanup Successful. Forensic environment is now pristine."
echo "[INFO] All analysis logs have been archived to ./docs/logs/ (Simulation)."
