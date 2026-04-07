pub mod config;
pub mod nvram;
pub mod entropy;
pub mod pe_parser;
pub mod elf_parser;
pub mod error;
pub mod signatures;
pub mod reporter;

pub use crate::error::AnalyzerError;
pub use crate::pe_parser::{analyze_pe_file, PEAnalysisResult};
pub use crate::elf_parser::{analyze_elf_file, ELFAnalysisResult};
pub use crate::nvram::{NvramScanner, UefiVariable};
pub use crate::config::EngineConfig;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum SecurityVerdict {
    PE(PEAnalysisResult),
    ELF(ELFAnalysisResult),
    SIGNATURES { file: String, hits: Vec<signatures::SignatureHit> },
    NVRAM { variables: Vec<UefiVariable>, hits: Vec<nvram::NvramHit> },
    UNKNOWN { file: String, error: String },
}
