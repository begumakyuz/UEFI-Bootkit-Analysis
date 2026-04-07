use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use std::fs;
use crate::entropy::calculate_shannon_entropy;
use crate::error::AnalyzerError;

#[derive(Serialize, Deserialize, Debug)]
pub struct ELFSectionAnalysis {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_suspicious: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ELFAnalysisResult {
    pub file_path: String,
    pub sections: Vec<ELFSectionAnalysis>,
    pub entry_point: u64,
}

const ENTROPY_THRESHOLD: f64 = 7.0;

pub fn analyze_elf_file(path: &str) -> Result<ELFAnalysisResult, AnalyzerError> {
    let buffer = fs::read(path)?;
    let elf = Elf::parse(&buffer).map_err(|e| AnalyzerError::ElfParseError(e.to_string()))?;

    let mut sections_analysis = Vec::new();

    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown");
        
        let start = section.sh_offset as usize;
        let end = start + section.sh_size as usize;
        
        if end <= buffer.len() {
            let section_data = &buffer[start..end];
            let entropy = calculate_shannon_entropy(section_data);
            
            sections_analysis.push(ELFSectionAnalysis {
                name: name.to_string(),
                virtual_address: section.sh_addr,
                size: section.sh_size,
                entropy,
                is_suspicious: entropy >= ENTROPY_THRESHOLD,
            });
        }
    }

    Ok(ELFAnalysisResult {
        file_path: path.to_string(),
        sections: sections_analysis,
        entry_point: elf.entry,
    })
}
