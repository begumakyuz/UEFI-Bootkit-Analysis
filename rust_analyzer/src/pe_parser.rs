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
    pub machine: u16,
    pub subsystem: u16,
    pub entry_point: u32,
    pub image_base: u64,
}

const ENTROPY_THRESHOLD: f64 = 7.2;
const IAT_SUSPICIOUS_THRESHOLD: usize = 10;

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

    for section in pe.section_headers() {
        let name_bytes = &section.Name;
        let name = String::from_utf8_lossy(name_bytes).trim_matches('\0').to_string();
        
        let raw_data = match pe.get_section_bytes(section) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let entropy = calculate_shannon_entropy(raw_data);
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

    let is_suspicious = packed_sections_count > 0 && iat_size < IAT_SUSPICIOUS_THRESHOLD;

    Ok(PEAnalysisResult {
        file_path: path.to_string(),
        sections,
        iat_size,
        is_suspicious,
        machine: file_header.Machine,
        subsystem: optional_header.Subsystem,
        entry_point: optional_header.AddressOfEntryPoint,
        image_base: optional_header.ImageBase,
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
