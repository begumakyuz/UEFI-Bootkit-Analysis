#!/usr/bin/env python3
"""
Integration Tests for UEFI Bootkit Analysis Suite.
Verifies the end-to-end orchestration of Rust diagnostics and Python visualization.
"""

import unittest
import os
import subprocess
import json
import shutil

class TestUEFIForensics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Prepares a dummy EFI binary for testing purposes."""
        cls.test_file = "tests/test_payload.efi"
        os.makedirs("tests", exist_ok=True)
        with open(cls.test_file, "wb") as f:
            # Create a 4KB file with some high-entropy random data at the end
            f.write(b"\x4D\x5A" + b"\x00" * 510) # MZ Header
            f.write(os.urandom(3584))

    def test_rust_analyzer_execution(self):
        """Verifies that the Rust analyzer can be called and returns valid JSON."""
        print("[*] Testing Rust Analyzer Integration...")
        result = subprocess.run(
            ["cargo", "run", "--release", "--", "--file", self.test_file, "--output", "json"],
            cwd="./rust_analyzer",
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0, f"Rust analyzer failed: {result.stderr}")
        
        # Verify JSON structure
        data = json.loads(result.stdout)
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) > 0)
        self.assertEqual(data[0]["type"], "PE")

    def test_visualization_script(self):
        """Ensures the ASCII visualization script runs without errors."""
        print("[*] Testing Visualization Engine...")
        result = subprocess.run(
            ["python", "scripts/visualize_analysis.py", self.test_file],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Visualizing Entropy Topology", result.stdout)
        self.assertIn("0x000000", result.stdout)

    def test_orchestrator_persistence(self):
        """Checks if the master script correctly persists reports to the filesystem."""
        print("[*] Testing Orchestrator Persistence...")
        result = subprocess.run(
            ["python", "scripts/firmware_integrity.py", self.test_file],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        
        report_path = "reports/security_audit_v3.json"
        self.assertTrue(os.path.exists(report_path), "Report file was not created.")
        
        with open(report_path, "r") as f:
            report_data = json.load(f)
            self.assertEqual(report_data["target"], "test_payload.efi")
            self.assertIn("verdict", report_data)

    @classmethod
    def tearDownClass(cls):
        """Cleans up test artifacts."""
        if os.path.exists(cls.test_file):
            os.remove(cls.test_file)
        if os.path.exists("reports/security_audit_v3.json"):
            os.remove("reports/security_audit_v3.json")

if __name__ == "__main__":
    unittest.main()
