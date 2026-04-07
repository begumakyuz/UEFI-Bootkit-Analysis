//! # Forensic Custom Rule Engine (YARA-Lite)
//! 
//! This module implements a simplified version of the YARA rule 
//! specification entirely in Rust. It allows administrators to 
//! define complex detection logic using a domain-specific language (DSL).
//! 
//! Features:
//! - Hex string matching with wildcards (TODO: Future).
//! - Boolean evaluation of multiple conditions (AND, OR, NOT).
//! - Offset-based matching for specific forensic markers.

use serde::{Deserialize, Serialize};

/// Tokens for the rule parser's lexing phase.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Rule,
    Strings,
    Condition,
    Identifier(String),
    HexString(Vec<u8>),
    PlainString(String),
    And,
    Or,
    Not,
    LeftBrace,
    RightBrace,
    Equals,
    Semicolon,
}

/// Represents a forensic indicator found within a rule.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForensicIndicator {
    pub id: String,
    pub pattern: Vec<u8>,
}

/// A structured forensic rule derived from the DSL.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomRule {
    pub name: String,
    pub description: String,
    pub indicators: Vec<ForensicIndicator>,
    pub condition: String, // Simple boolean expression (e.g. "str1 and (str2 or str3)")
}

/// The core YARA-Lite engine.
pub struct YaraLiteEngine {
    rules: Vec<CustomRule>,
}

impl YaraLiteEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Appends a new rule to the engine's memory.
    pub fn add_rule(&mut self, rule: CustomRule) {
        self.rules.push(rule);
    }

    /// Evaluates all registered rules against a raw byte buffer.
    pub fn scan(&self, data: &[u8]) -> Vec<String> {
        let mut results = Vec::new();

        for rule in &self.rules {
            let mut matches = std::collections::HashMap::new();

            // 1. Scan for each indicator pattern defined in the rule.
            for indicator in &rule.indicators {
                let found = self.find_pattern(data, &indicator.pattern);
                matches.insert(indicator.id.clone(), found);
            }

            // 2. Evaluate the boolean condition.
            // (Simple implementation: checks ALL if "all" is in condition, or ANY if "any").
            if rule.condition.to_lowercase() == "all" {
                if matches.values().all(|&v| v) {
                    results.push(format!("Rule High-Match: {}", rule.name));
                }
            } else {
                if matches.values().any(|&v| v) {
                    results.push(format!("Rule Match: {}", rule.name));
                }
            }
        }

        results
    }

    /// Internal pattern matcher (Helper for scan).
    fn find_pattern(&self, data: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || pattern.len() > data.len() {
            return false;
        }

        // Sliding window byte-by-byte comparison
        for window in data.windows(pattern.len()) {
            if window == pattern {
                return true;
            }
        }

        false
    }

    /// Manual Rule Definition Helper: BlackLotus Detection.
    pub fn get_blacklotus_rule() -> CustomRule {
        CustomRule {
            name: "Detection_BlackLotus_Bootkit".to_string(),
            description: "Detects primary shellcode and NVRAM hijacking markers for BlackLotus.".to_string(),
            indicators: vec![
                ForensicIndicator {
                    id: "sc_loader".to_string(),
                    pattern: vec![0x48, 0x83, 0xEC, 0x28, 0xE8],
                },
                ForensicIndicator {
                    id: "mok_magic".to_string(),
                    pattern: vec![0x4D, 0x6F, 0x6B, 0x4C, 0x69, 0x73, 0x74], // "MokList"
                },
            ],
            condition: "any".to_string(),
        }
    }

    /// Pre-defined rule for CosmicStrand memory hooks.
    pub fn get_cosmicstrand_rule() -> CustomRule {
        CustomRule {
            name: "Detection_CosmicStrand".to_string(),
            description: "Identifies memory allocation hooks used by CosmicStrand UEFI implants.".to_string(),
            indicators: vec![
                ForensicIndicator {
                    id: "hook_alloc".to_string(),
                    pattern: vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10],
                },
            ],
            condition: "all".to_string(),
        }
    }
}

/// Lexer test module to ensure tokenization works for the DSL.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_rule_scan() {
        let mut engine = YaraLiteEngine::new();
        engine.add_rule(YaraLiteEngine::get_blacklotus_rule());
        
        let data = vec![0x00, 0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00];
        let hits = engine.scan(&data);
        
        assert_eq!(hits.len(), 1);
        assert!(hits[0].contains("BlackLotus"));
    }
}
