use std::fmt;

#[derive(Debug)]
pub enum AnalyzerError {
    IoError(std::io.Error),
    PeParseError(String),
    ElfParseError(String),
    UnsupportedFormat(String),
}

impl fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalyzerError::IoError(e) => write!(f, "IO Error: {}", e),
            AnalyzerError::PeParseError(s) => write!(f, "PE Parse Error: {}", s),
            AnalyzerError::ElfParseError(s) => write!(f, "ELF Parse Error: {}", s),
            AnalyzerError::UnsupportedFormat(s) => write!(f, "Unsupported Format: {}", s),
        }
    }
}

impl From<std::io.Error> for AnalyzerError {
    fn from(error: std::io.Error) -> Self {
        AnalyzerError::IoError(error)
    }
}
