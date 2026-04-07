use clap::Parser;
use rust_analyzer::{
    analyze_pe_file, analyze_elf_file, SecurityVerdict, 
    signatures::perform_signature_analysis,
    reporter::{MarkdownReporter, ReportConfig, JsonReporter}
};
use std::path::Path;
use std::fs::read;

/// Command line interface for the Begum Akyuz - UEFI Security Suite.
#[derive(Parser)]
#[command(name = "Begum Akyuz - UEFI Security Suite")]
#[command(author = "Begüm AKYÜZ <student@istinye.edu.tr>")]
#[command(version = "2.2")]
#[command(about = "Advanced Forensic Analysis of UEFI/EFI binaries for Bootkit Indicators.", long_about = None)]
struct Cli {
    /// Path to the binary file (EFI/ELF) to analyze
    #[arg(short, long)]
    file: String,

    /// Output format (json, ascii, md)
    #[arg(short, long, default_value_t = String::from("json"))]
    output: String,

    /// Enable deep signature scanning for known UEFI IOCs
    #[arg(short, long, default_value_t = false)]
    signatures: bool,
}

fn main() {
    let cli = Cli::parse();
    let path = Path::new(&cli.file);

    // 1. Pre-analysis existence check
    if !path.exists() {
        eprintln!("Error: Target file not found at: {}", cli.file);
        std::process::exit(1);
    }

    let mut results = Vec::new();

    // 2. Perform Static Structure Analysis (PE/ELF)
    let static_verdict = match analyze_pe_file(&cli.file) {
        Ok(pe_res) => SecurityVerdict::PE(pe_res),
        Err(_) => {
            match analyze_elf_file(&cli.file) {
                Ok(elf_res) => SecurityVerdict::ELF(elf_res),
                Err(e) => SecurityVerdict::UNKNOWN {
                    file: cli.file.clone(),
                    error: format!("Structural analysis failed: {}", e),
                },
            }
        }
    };
    results.push(static_verdict);

    // 3. Optional Deep Signature Scanning
    if cli.signatures {
        match read(&cli.file) {
            Ok(data) => {
                match perform_signature_analysis(&data) {
                    Ok(hits) => {
                        results.push(SecurityVerdict::SIGNATURES { 
                            file: cli.file.clone(), 
                            hits 
                        });
                    }
                    Err(e) => eprintln!("Signature analysis failed: {}", e),
                }
            }
            Err(e) => eprintln!("Failed to read file for signatures: {}", e),
        }
    }

    // 4. Report Generation Phase
    match cli.output.to_lowercase().as_str() {
        "json" => {
            match JsonReporter::export_json(&results) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("JSON Export Error: {}", e),
            }
        }
        "md" => {
            let reporter = MarkdownReporter::new(ReportConfig::default());
            let report = reporter.generate_report(&results);
            println!("{}", report);
        }
        _ => {
            // Default: Professional Terminal Report (ASCII)
            println!("========================================================");
            println!("   BEGUM AKYUZ SECURITY SUITE: UEFI AUDIT REPORT        ");
            println!("========================================================");
            for res in results {
                match res {
                    SecurityVerdict::PE(res) => {
                        println!("Engine: PE Parser (Firmware Mode)");
                        println!("- Entropy Score: {:.2}", res.entropy);
                        println!("- Indicators: {}", if res.is_suspicious { "🚩 MALICIOUS" } else { "✅ CLEAN" });
                    }
                    SecurityVerdict::ELF(res) => {
                        println!("Engine: ELF Parser (Bootloader Mode)");
                        println!("- Format: ELF64/32 Verified");
                        println!("- Entry Point: 0x{:X}", res.entry_point);
                    }
                    SecurityVerdict::SIGNATURES { file: _, hits } => {
                        println!("Engine: Deep Signature Scanner");
                        println!("- Hits Found: {}", hits.len());
                        for hit in hits {
                            println!("  [!] {} found at offset 0x{:X} (Severity: {:?})", 
                                     hit.signature_name, hit.offset, hit.severity);
                        }
                    }
                    SecurityVerdict::UNKNOWN { file: _, error } => {
                        println!("Engine: General Processor");
                        println!("- Result: ❌ ERROR ({})", error);
                    }
                }
            }
            println!("========================================================");
        }
    }
}
