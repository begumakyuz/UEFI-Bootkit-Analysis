use pelite::pe64::{Pe, PeFile};
use serde::{Deserialize, Serialize};
use std::fs;
use crate::entropy::calculate_shannon_entropy;
use crate::error::AnalyzerError;

#[derive(Serialize, Deserialize, Debug)]
pub struct SectionAnalysis {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_size: u32,
    pub entropy: f64,
    pub is_packed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PEAnalysisResult {
    pub file_path: String,
    pub sections: Vec<SectionAnalysis>,
    pub iat_size: usize,
    pub is_suspicious: bool,
    pub entropy_explanation: String,
    pub machine: u16,
    pub subsystem: u16,
    pub entry_point: u32,
    pub image_base: u64,
    pub ep_is_suspicious: bool,
}

const ENTROPY_THRESHOLD: f64 = 7.2;
const IAT_SUSPICIOUS_THRESHOLD: usize = 10;

/// Analyzes a PE file for common UEFI bootkit characteristics.
/// 
/// This function performs:
/// 1. Section enumeration and entropy calculation (detecting packed payloads).
/// 2. Import Address Table (IAT) density analysis (malicious drivers often have few imports).
/// 3. Entry Point (EP) validation (checking if the EP resides in an unusual or non-standard section).
pub fn analyze_pe_file(path: &str) -> Result<PEAnalysisResult, AnalyzerError> {
    let file_map = match pelite::FileMap::open(path) {
        Ok(m) => m,
        Err(e) => return Err(AnalyzerError::PeParseError(e.to_string())),
    };

    let pe = match PeFile::from_bytes(file_map.as_ref()) {
        Ok(p) => p,
        Err(e) => return Err(AnalyzerError::PeParseError(e.to_string())),
    };

    let optional_header = pe.optional_header();
    let file_header = pe.file_header();

    let mut sections = Vec::new();
    let mut packed_sections_count = 0;
    let mut max_entropy = 0.0;

    for section in pe.section_headers() {
        let name_bytes = &section.Name;
        let name = String::from_utf8_lossy(name_bytes).trim_matches('\0').to_string();
        
        let raw_data = match pe.get_section_bytes(section) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let entropy = calculate_shannon_entropy(raw_data);
        if entropy > max_entropy {
            max_entropy = entropy;
        }

        let is_packed = entropy >= ENTROPY_THRESHOLD;
        if is_packed {
            packed_sections_count += 1;
        }

        sections.push(SectionAnalysis {
            name,
            virtual_address: section.VirtualAddress,
            virtual_size: section.VirtualSize,
            raw_data_size: section.SizeOfRawData,
            entropy,
            is_packed,
        });
    }

    let mut iat_size = 0;
    if let Ok(imports) = pe.imports() {
        for _ in imports {
            iat_size += 1; 
        }
    }

    // Logic: High entropy + small IAT is a strong indicator of a packed malware loader.
    let is_suspicious = packed_sections_count > 0 && iat_size < IAT_SUSPICIOUS_THRESHOLD;
    
    let entropy_explanation = format!(
        "Max section entropy ({:.2}) indicates {} content.",
        max_entropy,
        if max_entropy > 7.5 { "highly encrypted/packed" } else { "standard" }
    );

    // Advanced EP Analysis: Check if AddressOfEntryPoint points to an unusual section.
    // Legitimate UEFI drivers usually have their EP in the first code section (.text).
    let entry_point = optional_header.AddressOfEntryPoint;
    let mut ep_is_suspicious = true;
    for section in &sections {
        if entry_point >= section.virtual_address && entry_point < (section.virtual_address + section.virtual_size) {
            if section.name == ".text" || section.name == "CODE" {
                ep_is_suspicious = false;
            }
        }
    }

    Ok(PEAnalysisResult {
        file_path: path.to_string(),
        sections,
        iat_size,
        is_suspicious,
        entropy_explanation,
        machine: file_header.Machine,
        subsystem: optional_header.Subsystem,
        entry_point,
        image_base: optional_header.ImageBase,
        ep_is_suspicious,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicion_logic() {
        // Logic check: High entropy + small IAT = suspicious
        let packed_sections_count = 1;
        let iat_size = 5;
        let is_suspicious = packed_sections_count > 0 && iat_size < IAT_SUSPICIOUS_THRESHOLD;
        assert!(is_suspicious);

        // Logic check: High entropy + large IAT = NOT suspicious (likely legitimate compression)
        let packed_sections_count = 1;
        let iat_size = 50;
        let is_suspicious = packed_sections_count > 0 && iat_size < IAT_SUSPICIOUS_THRESHOLD;
        assert!(!is_suspicious);
    }
}
