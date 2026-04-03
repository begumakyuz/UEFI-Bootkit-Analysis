use pelite::pe64::{Pe, PeFile};
use serde::{Deserialize, Serialize};
use std::fs;
use crate::entropy::calculate_shannon_entropy;

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
}

const ENTROPY_THRESHOLD: f64 = 7.2;
const IAT_SUSPICIOUS_THRESHOLD: usize = 10; // Few imports usually mean runtime unpacking

pub fn analyze_pe_file(path: &str) -> Result<PEAnalysisResult, String> {
    // Read raw byte stream mapping Virtual Address (VA) to Raw Offset internally via pelite
    let file_map = match pelite::FileMap::open(path) {
        Ok(m) => m,
        Err(e) => return Err(format!("Failed to open file: {}", e)),
    };

    let pe = match PeFile::from_bytes(file_map.as_ref()) {
        Ok(p) => p,
        Err(e) => return Err(format!("Failed to parse PE file: {}", e)),
    };

    let mut sections = Vec::new();
    let mut packed_sections_count = 0;

    // Map section headers and calculate entropy from raw byte streams
    for section in pe.section_headers() {
        let name_bytes = &section.Name;
        let name = String::from_utf8_lossy(name_bytes).trim_matches('\0').to_string();
        
        // Extract raw bytes for the section
        let raw_data = match pe.get_section_bytes(section) {
            Ok(bytes) => bytes,
            Err(_) => continue, // Skip unmapped or zero-byte sections
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

    // Correlate with IAT anomalies
    // Extract Import Address Table (IAT) safely
    let mut iat_size = 0;
    if let Ok(imports) = pe.imports() {
        for _ in imports {
            // Count total imported DLLs/functions roughly by iterating
            iat_size += 1; 
        }
    }

    // Heuristics: High entropy sections + unusually small IAT = definitely packed/encrypted
    let is_suspicious = packed_sections_count > 0 && iat_size < IAT_SUSPICIOUS_THRESHOLD;

    Ok(PEAnalysisResult {
        file_path: path.to_string(),
        sections,
        iat_size,
        is_suspicious,
    })
}
