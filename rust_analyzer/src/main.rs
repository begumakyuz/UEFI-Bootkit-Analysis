use clap::Parser;
use rust_analyzer::{analyze_pe_file, analyze_elf_file, SecurityVerdict};
use std::path::Path;

#[derive(Parser)]
#[command(name = "Begum Akyuz - UEFI Security Suite")]
#[command(author = "Begüm AKYÜZ <student@istinye.edu.tr>")]
#[command(version = "2.0")]
#[command(about = "Advanced Multi-Format (PE/ELF) Static Analysis Tool for determining UEFI/Bootloader malformities.", long_about = None)]
struct Cli {
    /// Path to the binary file (EFI/ELF) to analyze
    #[arg(short, long)]
    file: String,

    /// Output format (json or ascii)
    #[arg(short, long, default_value_t = String::from("json"))]
    output: String,
}

fn main() {
    let cli = Cli::parse();
    let path = Path::new(&cli.file);

    if !path.exists() {
        eprintln!("Error: File not found at {}", cli.file);
        return;
    }

    // Auto-detect format and analyze
    let verdict = match analyze_pe_file(&cli.file) {
        Ok(pe_res) => SecurityVerdict::PE(pe_res),
        Err(_) => {
            // If PE fails, try ELF
            match analyze_elf_file(&cli.file) {
                Ok(elf_res) => SecurityVerdict::ELF(elf_res),
                Err(e) => SecurityVerdict::UNKNOWN {
                    file: cli.file.clone(),
                    error: format!("Failed to parse as PE or ELF: {}", e),
                },
            }
        }
    };

    if cli.output.to_lowercase() == "json" {
        match serde_json::to_string_pretty(&verdict) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Failed to serialize to JSON: {}", e),
        }
    } else {
        // Professional ASCII Report
        println!("--- BEGUM AKYUZ SECURITY SUITE: AUDIT REPORT ---");
        match verdict {
            SecurityVerdict::PE(res) => {
                println!("Format: Portable Executable (UEFI/EFI)");
                println!("Verdict: {}", if res.is_suspicious { "🚩 MALICIOUS" } else { "✅ CLEAN" });
                println!("Imports: {}", res.iat_size);
            }
            SecurityVerdict::ELF(res) => {
                println!("Format: ELF (Legacy/Linux Bootloader)");
                println!("Verdict: ✅ ANALYZED");
                println!("Entry Point: 0x{:08X}", res.entry_point);
            }
            SecurityVerdict::UNKNOWN { file, error } => {
                println!("File: {}", file);
                println!("Status: ❌ ERROR");
                println!("Detail: {}", error);
            }
        }
    }
}
