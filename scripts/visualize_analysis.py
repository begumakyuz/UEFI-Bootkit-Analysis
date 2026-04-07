#!/usr/bin/env python3
"""
Forensic Visualization Tool (v1.0)
Begum Akyuz - Academy Series

Generates ASCII visualizations of binary entropy and security metrics 
to assist analysts in identifying malicious 'Hot-Zones' in UEFI firmware.
"""

import sys
import os
import math

def calculate_entropy_of_block(data):
    """Calculates Shannon entropy for a block of bytes."""
    if not data:
        return 0
    entropy = 0
    probs = [data.count(b) / len(data) for b in set(data)]
    for p in probs:
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def draw_entropy_chart(file_path, block_size=1024):
    """Generates an ASCII bar chart of entropy across file segments."""
    print(f"\n[*] Visualizing Entropy Topology for: {os.path.basename(file_path)}")
    print("-" * 60)
    
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
        segments = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        
        for i, segment in enumerate(segments):
            entropy = calculate_entropy_of_block(segment)
            bar_len = int(entropy * 5) # Scale to 40 chars max (8 * 5)
            
            # Color indicator (simulated with characters)
            indicator = "[ OK ]"
            if entropy > 7.0:
                indicator = "[PACKED]"
            elif entropy > 6.0:
                indicator = "[SUSP]"
                
            offset = i * block_size
            print(f"0x{offset:06X} | {'█' * bar_len}{' ' * (40 - bar_len)} | {entropy:.2f} {indicator}")
            
    except Exception as e:
        print(f"[!] Visualization failed: {e}")

def print_forensic_summary(file_path):
    """Prints a professional summary of the file being visualized."""
    size = os.path.getsize(file_path)
    print("\n--- FORENSIC FILE METADATA ---")
    print(f"Filename:   {os.path.basename(file_path)}")
    print(f"Size:       {size} bytes ({size/1024:.2f} KB)")
    print(f"Segments:   {math.ceil(size/1024)} Analysis Blocks")
    print("-" * 30)

def main():
    if len(sys.argv) < 2:
        print("\n[!] Usage: python visualize_analysis.py <target_file>")
        sys.exit(1)
        
    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"[!] Error: {target} not accessible.")
        sys.exit(1)
        
    print_forensic_summary(target)
    draw_entropy_chart(target)
    print("\n[+] Analysis Complete: High-density segments (>= 7.2) require manual disassembly.\n")

if __name__ == "__main__":
    main()
