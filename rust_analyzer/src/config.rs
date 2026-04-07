//! # Engine Configuration and Threshold Management
//! 
//! This module provides a centralized configuration system for the UEFI 
//! forensic suite. It allows security analysts to tune detection thresholds, 
//! enable/disable specific scanning modules (like NVRAM/PE), and define 
//! report generation parameters.
//! 
//! Using a structured configuration ensures that the forensic process 
//! is repeatable and auditable across different incident response scenarios.

use serde::{Deserialize, Serialize};

/// Global configuration for the forensic suite.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EngineConfig {
    /// General settings for core analysis.
    pub general: GeneralConfig,
    /// Settings for the PE/ELF structural analysis.
    pub parser: ParserConfig,
    /// Settings for the signature matching engine.
    pub signatures: SignatureConfig,
    /// Reporting and output preferences.
    pub reporting: ReportingConfig,
}

/// Core engine settings.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeneralConfig {
    /// Enable multi-threaded analysis for large firmware directories.
    pub parallel: bool,
    /// Log level for forensic activities (info, warn, error, debug).
    pub log_level: String,
    /// Maximum file size to analyze (default: 64MB) to prevent DoS.
    pub max_file_size: usize,
}

/// PE/ELF parser specific thresholds.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParserConfig {
    /// Shannon entropy threshold for packing detection (Default: 7.2).
    pub entropy_threshold: f64,
    /// Minimum IAT size for non-suspicious binaries (Default: 10).
    pub iat_min_imports: usize,
    /// Enable entry point proximity scanning (requires disassembler).
    pub enable_disasm: bool,
}

/// Signature matching engine settings.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureConfig {
    /// Enable deep byte-pattern scanning across all sections.
    pub enable_deep_scan: bool,
    /// Performance mode for signature matching (brute-force vs aho-corasick).
    pub search_algorithm: String,
}

/// Report formatting and persistence settings.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportingConfig {
    /// Default output format (json, md, html).
    pub default_format: String,
    /// Include verbose forensic descriptions in the final report.
    pub verbose: bool,
    /// Path to the directory where forensic reports should be persistent.
    pub output_dir: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                parallel: false,
                log_level: "info".to_string(),
                max_file_size: 64 * 1024 * 1024,
            },
            parser: ParserConfig {
                entropy_threshold: 7.2,
                iat_min_imports: 10,
                enable_disasm: true,
            },
            signatures: SignatureConfig {
                enable_deep_scan: true,
                search_algorithm: "aho-corasick".to_string(),
            },
            reporting: ReportingConfig {
                default_format: "md".to_string(),
                verbose: true,
                output_dir: "./reports".to_string(),
            },
        }
    }
}

impl EngineConfig {
    /// Loads a configuration from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }

    /// Exports the current configuration to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
