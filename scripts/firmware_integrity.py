#!/usr/bin/env python3
"""
Firmware Integrity Orchestrator (v3.0)
Advanced Security Analysis Suite for UEFI/EFI Integrity.

This script acts as the master orchestrator, combining Rust-based static 
analysis, deep signature scanning, and YARA-based legacy pattern matching.
"""

import subprocess
import os
import sys
import json
import datetime
import logging

# Configure logging for professional forensics output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

class FirmwareAnalyst:
    def __init__(self, target_path):
        self.target = target_path
        self.report_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "target": os.path.basename(target_path),
            "verdict": "UNKNOWN",
            "engines": []
        }

    def run_rust_engine(self, deep_scan=True):
        """Executes the Rust static analyzer with optional deep signature scanning."""
        logging.info(f"Launching Rust Analysis Engine on {self.target}...")
        cmd = ["cargo", "run", "--release", "--", "--file", self.target, "--output", "json"]
        if deep_scan:
            cmd.append("--signatures")
            
        try:
            result = subprocess.run(
                cmd,
                cwd="./rust_analyzer",
                capture_output=True,
                text=True,
                timeout=30 # Safety timeout
            )
            if result.returncode == 0:
                parsed = json.loads(result.stdout)
                self.report_data["engines"].append({
                    "name": "RustCore",
                    "status": "Success",
                    "data": parsed
                })
                return parsed
            else:
                logging.error(f"Rust Core Error: {result.stderr}")
                return None
        except Exception as e:
            logging.error(f"Failed to execute Rust Engine: {e}")
            return None

    def run_yara_engine(self):
        """Runs legacy YARA rules for known bootkit strings."""
        logging.info("Initializing YARA Signature Matcher...")
        rule_path = "./yara/blacklotus_bootkit.yar"
        if not os.path.exists(rule_path):
            logging.warning(f"YARA rules missing at {rule_path}. Skipping.")
            return []
            
        try:
            # Check if yara is installed
            result = subprocess.run(["yara", "--version"], capture_output=True)
            if result.returncode != 0:
                 return []
                 
            result = subprocess.run(
                ["yara", rule_path, self.target],
                capture_output=True,
                text=True
            )
            matches = [m.strip() for m in result.stdout.split("\n") if m.strip()]
            self.report_data["engines"].append({
                "name": "YaraLegacy",
                "status": "Success",
                "matches": matches
            })
            return matches
        except FileNotFoundError:
            logging.warning("YARA executable not found in PATH.")
            return []

    def evaluate_threats(self, rust_data, yara_matches):
        """Aggregates multi-engine results to produce a final security verdict."""
        is_suspicious = False
        reasons = []

        # Analyze Rust Core Findings
        if rust_data:
            for verdict in rust_data:
                v_type = verdict.get("type")
                if v_type == "PE":
                    if verdict.get("entropy", 0) > 7.2:
                        is_suspicious = True
                        reasons.append(f"High Entropy ({verdict['entropy']:.2f}) - Packed Payload?")
                elif v_type == "SIGNATURES":
                    hits = verdict.get("hits", [])
                    if hits:
                        is_suspicious = True
                        reasons.append(f"{len(hits)} Deep Signatures Triggered.")

        # Analyze YARA Matches
        if yara_matches:
            is_suspicious = True
            reasons.append(f"{len(yara_matches)} YARA String matches detected.")

        self.report_data["verdict"] = "MALICIOUS" if is_suspicious else "CLEAN"
        self.report_data["threat_reasons"] = reasons
        
        return is_suspicious

    def save_forensic_evidence(self):
        """Persists the consolidated report to the forensic reports directory."""
        reports_dir = "./reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, "security_audit_v3.json")
        try:
            with open(report_path, "w") as f:
                json.dump(self.report_data, f, indent=4)
            logging.info(f"Forensic bundle saved: {report_path}")
        except Exception as e:
            logging.error(f"Persistence Failed: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python firmware_integrity.py <path_to_efi>")
        sys.exit(1)
        
    target = sys.argv[1]
    if not os.path.exists(target):
        logging.error(f"Target not found: {target}")
        sys.exit(1)

    analyst = FirmwareAnalyst(target)
    rust_results = analyst.run_rust_engine(deep_scan=True)
    yara_results = analyst.run_yara_engine()
    
    is_threat = analyst.evaluate_threats(rust_results, yara_results)
    analyst.save_forensic_evidence()
    
    # Final Terminal Output
    print("\n" + "="*40)
    print(f" FINAL VERDICT: {analyst.report_data['verdict']} ")
    print("="*40)
    if is_threat:
        for reason in analyst.report_data["threat_reasons"]:
            print(f" [!] {reason}")
    else:
        print(" [√] No known malicious patterns identified.")
    print("="*40 + "\n")

if __name__ == "__main__":
    main()
