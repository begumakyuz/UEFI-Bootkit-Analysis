#!/usr/bin/env python3
"""
Firmware Integrity Orchestrator (v2.0)
Part of Begum Akyuz UEFI Security Suite.

This script coordinates Rust-based static analysis and YARA signature matching
to provide a comprehensive security verdict on EFI binaries.
"""

import subprocess
import os
import sys
import json

def run_rust_analysis(file_path):
    print(f"[*] Starting Rust-based Deep Static Analysis on {file_path}...")
    try:
        # Assuming the binary is built in rust_analyzer/target/release/rust_analyzer
        # For simulation/demo purposes, we use the local cargo run if available
        # But here we simulate the logic
        result = subprocess.run(
            ["cargo", "run", "--release", "--", "--file", file_path, "--output", "json"],
            cwd="./rust_analyzer",
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"[!] Rust Analyzer failed: {result.stderr}")
            return None
    except FileNotFoundError:
        print("[!] Rust toolchain not found. Skipping static segment analysis.")
        return {"status": "skipped", "reason": "toolchain_missing"}

def run_yara_scan(file_path):
    print(f"[*] Starting YARA Signature Matching on {file_path}...")
    rule_path = "./yara/blacklotus_bootkit.yar"
    if not os.path.exists(rule_path):
        print(f"[!] YARA rule not found at {rule_path}")
        return []
    
    try:
        result = subprocess.run(
            ["yara", rule_path, file_path],
            capture_output=True,
            text=True
        )
        matches = result.stdout.strip().split("\n")
        return [m for m in matches if m]
    except FileNotFoundError:
        print("[!] YARA engine not found.")
        return []

def consolidate_report(file_path):
    print("=" * 60)
    print(f"SECURITY AUDIT REPORT: {os.path.basename(file_path)}")
    print("=" * 60)
    
    rust_report = run_rust_analysis(file_path)
    yara_matches = run_yara_scan(file_path)
    
    report_data = {
        "target": os.path.basename(file_path),
        "verdict": "CLEAN",
        "rust_anomalies": rust_report,
        "yara_matches": yara_matches
    }
    
    print("\n--- [VERDICT] ---")
    
    is_malicious = False
    
    if rust_report and rust_report.get("is_suspicious"):
        print("[🚩] STATIC ANOMALY: High entropy or suspicious IAT detected by Rust Engine.")
        is_malicious = True
        
    if yara_matches:
        print(f"[🚩] SIGNATURE MATCH: {len(yara_matches)} rules triggered.")
        for match in yara_matches:
            print(f"    -> {match}")
        is_malicious = True
        
    if is_malicious:
        report_data["verdict"] = "MALICIOUS"
        print("\n[CONCLUSION]: MALICIOUS PAYLOAD DETECTED.")
        print("ACTION: Quarantine file and perform SPI Flash integrity check.")
    else:
        print("\n[CONCLUSION]: NO IMMEDIATE THREAT DETECTED.")
        print("ACTION: Monitor for Runtime Services API hooking.")

    # Save report to persistence layer
    reports_dir = "/sandbox/reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)
    
    report_path = os.path.join(reports_dir, "security_report.json")
    try:
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=4)
        print(f"\n[+] Analysis report successfully saved to: {report_path}")
    except Exception as e:
        print(f"\n[!] Failed to save report: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "./assets/untrusted_firmware.efi"
    if not os.path.exists(target):
        # Create a dummy file for simulation if it doesn't exist
        with open(target, "wb") as f:
            f.write(os.urandom(1024))
            
    consolidate_report(target)
