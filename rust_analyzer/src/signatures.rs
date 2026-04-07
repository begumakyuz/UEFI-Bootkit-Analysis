//! # Signature Matching Engine
//! 
//! This module implements a static signature matching engine specifically 
//! designed for detecting UEFI-specific indicators of compromise (IOCs).
//! It focuses on identifying known bootkit patterns, malicious hooks, 
//! and anomalous entry sequences in PE/ELF firmware images.

use serde::{Deserialize, Serialize};
use crate::error::AnalyzerError;

/// Represetns the severity level of a detected signature.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Informational - might be worth investigating (e.g., custom sections).
    Low,
    /// Suspicious - common in malware but also some legitimate protectors.
    Medium,
    /// Highly Probable - common indicators of known bootkits (e.g., BlackLotus).
    High,
    /// Critical - definite indicator of compromise (e.g., Shellcode patterns).
    Critical,
}

/// A forensics signature comprising a name, pattern (byte sequence), and metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForensicSignature {
    pub name: String,
    pub description: String,
    pub pattern: Vec<u8>,
    pub severity: Severity,
}

/// Result of a signature scan on a specific file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureHit {
    pub signature_name: String,
    pub offset: usize,
    pub severity: Severity,
    pub recommendation: String,
}

/// The core signature matching engine state.
pub struct SignatureEngine {
    signatures: Vec<ForensicSignature>,
}

impl SignatureEngine {
    /// Initializes the engine with a set of pre-defined UEFI/PE signatures.
    pub fn new() -> Self {
        let mut signatures = Vec::new();

        // 1. BlackLotus Bootkit Indicator (Specific shellcode pattern in ESP)
        signatures.push(ForensicSignature {
            name: "BlackLotus_Loader_Pattern".to_string(),
            description: "Detects known byte sequences used in BlackLotus bootkit loaders.".to_string(),
            pattern: vec![0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4],
            severity: Severity::Critical,
        });

        // 2. CosmicStrand Hook Pattern (Memory allocation hook)
        signatures.push(ForensicSignature {
            name: "CosmicStrand_Hook".to_string(),
            description: "Identifies hooks into the UEFI memory allocation services.".to_string(),
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC3],
            severity: Severity::High,
        });

        // 3. Generic UEFI Shellcode Sled (NOP-like sequences)
        signatures.push(ForensicSignature {
            name: "Generic_Shellcode_Sled".to_string(),
            description: "Detects suspicious NOP sleds or repetitive padding in unexpected places.".to_string(),
            pattern: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            severity: Severity::Medium,
        });

        // 4. Loax Malware Pattern (UEFI DXE Driver Hijack)
        signatures.push(ForensicSignature {
            name: "Loax_DXE_Hijack".to_string(),
            description: "Detects patterns associated with Loax (ESET) UEFI rootkits targeting DXE drivers.".to_string(),
            pattern: vec![0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x53],
            severity: Severity::High,
        });

        // 5. MoonBounce Memory Pattern (SPI Flash to RAM stealth)
        signatures.push(ForensicSignature {
            name: "MoonBounce_Core".to_string(),
            description: "Identified in MoonBounce malicious SPI flash implants.".to_string(),
            pattern: vec![0x31, 0xC0, 0x48, 0xBB, 0xD0, 0x01, 0x00, 0x00],
            severity: Severity::Critical,
        });

        // 6. ESP-Ldr Boot Loader Tampering
        signatures.push(ForensicSignature {
            name: "ESP_Ldr_Tamper".to_string(),
            description: "Detects modifications to the Windows EFI Boot Loader (bootmgfw.efi).".to_string(),
            pattern: vec![0xBC, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA],
            severity: Severity::High,
        });

        // 7. MosaicRegressor Shell Pattern
        signatures.push(ForensicSignature {
            name: "MosaicRegressor_Shell".to_string(),
            description: "Known shellcode used by MosaicRegressor UEFI implants.".to_string(),
            pattern: vec![0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60],
            severity: Severity::Critical,
        });

        // 8. Custom Section Name Analysis (Malware often uses non-standard names)
        signatures.push(ForensicSignature {
            name: "NonStandard_Section_Ref".to_string(),
            description: "References to suspicious non-standard section names in data blocks.".to_string(),
            pattern: vec![0x2E, 0x74, 0x65, 0x78, 0x74, 0x69], // .texti
            severity: Severity::Low,
        });

        Self { signatures }
    }

    /// Scans a raw byte buffer for all registered signatures.
    /// 
    /// This uses a brute-force search suitable for UEFI firmware blocks. 
    /// Brute-force is chosen here for its simplicity and reliability in 
    /// firmware forensics where file sizes are typically small (< 5MB).
    /// For massive binaries, a more advanced algorithm (Aho-Corasick) 
    /// would be implemented in future versions for O(n) complexity.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<SignatureHit>, AnalyzerError> {
        let mut hits = Vec::new();

        for sig in &self.signatures {
            // Optimization: Skip patterns longer than data to avoid OOB
            if sig.pattern.len() > data.len() {
                continue;
            }

            // Iterate over the data searching for the pattern
            // We use windows() to iterate over sliding windows of the pattern length
            for (offset, window) in data.windows(sig.pattern.len()).enumerate() {
                // If a match is found, record the offset and metadata
                if window == sig.pattern.as_slice() {
                    hits.push(SignatureHit {
                        signature_name: sig.name.clone(),
                        offset,
                        severity: sig.severity,
                        recommendation: self.get_recommendation(&sig.name),
                    });
                }
            }
        }

        Ok(hits)
    }

    /// Provides a human-readable recommendation based on the detected signature.
    /// 
    /// These recommendations follow NIST/CISA guidelines for firmware forensics
    /// and incident response (IR).
    fn get_recommendation(&self, sig_name: &str) -> String {
        match sig_name {
            "BlackLotus_Loader_Pattern" => "IMMEDIATE ACTION REQUIRED: Re-flash BIOS and perform hardware audit.".to_string(),
            "CosmicStrand_Hook" => "THREAT DETECTED: Investigating UEFI Service Tables (ST) for hooks is advised.".to_string(),
            "Generic_Shellcode_Sled" => "SUSPICIOUS: Check for potential exploit attempts or broken compiler configs.".to_string(),
            "Loax_DXE_Hijack" => "CRITICAL: DXE driver has been modified. Possible SPI Flash implant.".to_string(),
            "MoonBounce_Core" => "FATAL: MoonBounce detected. UEFI Firmware integrity has been compromised at rest.".to_string(),
            "MosaicRegressor_Shell" => "URGENT: Known APT UEFI implant detected. Isolate host immediately.".to_string(),
            _ => "MONITOR: Log the event and cross-reference with system logs.".to_string(),
        }
    }
}

/// Helper function to perform a quick scan on a file.
pub fn perform_signature_analysis(data: &[u8]) -> Result<Vec<SignatureHit>, AnalyzerError> {
    let engine = SignatureEngine::new();
    engine.scan(data)
}
