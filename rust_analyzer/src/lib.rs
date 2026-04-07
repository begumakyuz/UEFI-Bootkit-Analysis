pub mod entropy;
pub mod pe_parser;
pub mod elf_parser;
pub mod error;

pub use crate::error::AnalyzerError;
pub use crate::pe_parser::{analyze_pe_file, PEAnalysisResult};
pub use crate::elf_parser::{analyze_elf_file, ELFAnalysisResult};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum SecurityVerdict {
    PE(PEAnalysisResult),
    ELF(ELFAnalysisResult),
    UNKNOWN { file: String, error: String },
}
