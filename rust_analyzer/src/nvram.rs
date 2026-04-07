//! # UEFI NVRAM Variable Analysis Module
//! 
//! This module implements a forensics scanner for the Unified Extensible 
//! Firmware Interface (UEFI) Non-Volatile Random Access Memory (NVRAM).
//! 
//! Bootkits often leverage NVRAM variables for persistence, hijacking the 
//! boot manager (e.g., Shim, MOK), or storing malicious configuration data 
//! that survives operating system reinstallation.

use serde::{Deserialize, Serialize};
use crate::error::AnalyzerError;

/// GUIDs commonly associated with UEFI variables.
pub mod guids {
    /// Global Variable GUID (EFI_GLOBAL_VARIABLE_GUID)
    pub const EFI_GLOBAL_VARIABLE: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
    /// Shim / Secure Boot GUID
    pub const SHIM_VARIABLE: &str = "605dab50-e046-4300-abb9-72901307ebb1";
}

/// Represents a UEFI NVRAM variable entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UefiVariable {
    pub name: String,
    pub guid: String,
    pub attributes: u32,
    pub data_size: usize,
    pub data_sha256: String,
}

/// Severity of an NVRAM anomaly.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum NvramSeverity {
    /// Secure Boot related modification.
    Critical,
    /// Unauthorized boot manager entry.
    High,
    /// Suspicious name or oversized data.
    Medium,
    /// Informational.
    Low,
}

/// A forensic hit in the NVRAM scan.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NvramHit {
    pub variable_name: String,
    pub severity: NvramSeverity,
    pub description: String,
    pub recommendation: String,
}

/// The NVRAM scanning engine.
pub struct NvramScanner;

impl NvramScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scans a collection of UEFI variables for known malicious patterns.
    /// 
    /// This follows the "Indicator of Compromise" (IOC) methodology used 
    /// by forensics tools like `uefivariable-fingerprint`.
    pub fn scan_variables(&self, variables: &[UefiVariable]) -> Vec<NvramHit> {
        let mut hits = Vec::new();

        for var in variables {
            // 1. Check for Shim Hijacking (BlackLotus style)
            if var.name == "MokListTrusted" && var.guid == guids::SHIM_VARIABLE {
                if var.data_size > 4096 {
                    hits.push(NvramHit {
                        variable_name: var.name.clone(),
                        severity: NvramSeverity::Critical,
                        description: "Oversized MokListTrusted variable detected. Possible unauthorized MOK injection.".to_string(),
                        recommendation: "Verify all enrolled MOK certificates against corporate policy.".to_string(),
                    });
                }
            }

            // 2. Check for suspicious BootOrder modifications
            if var.name == "BootOrder" && var.guid == guids::EFI_GLOBAL_VARIABLE {
                // In a forensic image, we'd parse the BootOrder and check for new EFI targets
                // For this simulation, we check for unusual attributes
                if var.attributes & 0x80000000 != 0 {
                    hits.push(NvramHit {
                        variable_name: var.name.clone(),
                        severity: NvramSeverity::High,
                        description: "Non-standard attributes in BootOrder. Potential persistence via boot hijacking.".to_string(),
                        recommendation: "Examine the EFI system partition for unofficial .efi loaders.".to_string(),
                    });
                }
            }

            // 3. Check for 'dbx' (Revocation List) tampering
            if var.name == "dbx" && var.guid == guids::EFI_GLOBAL_VARIABLE {
                // Malicious bootkits might try to clear the revocation list
                if var.data_size < 100 {
                    hits.push(NvramHit {
                        variable_name: var.name.clone(),
                        severity: NvramSeverity::Critical,
                        description: "Anomalously small Secure Boot Revocation List (dbx). Risk of known exploit bypass.".to_string(),
                        recommendation: "Manually re-import the latest DBX update from UEFI.org or Microsoft.".to_string(),
                    });
                }
            }
        }

        hits
    }

    /// Simulation helper: Generates a sample set of NVRAM variables for testing.
    pub fn get_mock_variables() -> Vec<UefiVariable> {
        vec![
            UefiVariable {
                name: "BootOrder".to_string(),
                guid: guids::EFI_GLOBAL_VARIABLE.to_string(),
                attributes: 0x00000007, // Standard
                data_size: 16,
                data_sha256: "abc...".to_string(),
            },
            UefiVariable {
                name: "MokListTrusted".to_string(),
                guid: guids::SHIM_VARIABLE.to_string(),
                attributes: 0x00000007,
                data_size: 5000, // MALICIOUS - TOO LARGE
                data_sha256: "def...".to_string(),
            }
        ]
    }
}
