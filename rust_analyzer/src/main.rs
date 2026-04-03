mod entropy;
mod pe_parser;

use clap::Parser;
use pe_parser::analyze_pe_file;
use serde_json;

#[derive(Parser)]
#[command(name = "Rust Entropy & IAT Analyzer")]
#[command(author = "Cyber Security Expert")]
#[command(version = "1.0")]
#[command(about = "Advanced Static Analysis Tool for determining PE/ELF malformities based on Shannon Entropy and IAT correlation", long_about = None)]
struct Cli {
    /// Path to the PE/ELF file to analyze
    #[arg(short, long)]
    file: String,

    /// Output format (json or ascii)
    #[arg(short, long, default_value_t = String::from("json"))]
    output: String,
}

fn main() {
    let cli = Cli::parse();

    match analyze_pe_file(&cli.file) {
        Ok(analysis_result) => {
            if cli.output.to_lowercase() == "json" {
                match serde_json::to_string_pretty(&analysis_result) {
                    Ok(json) => println!("{}", json),
                    Err(e) => eprintln!("Failed to serialize to JSON: {}", e),
                }
            } else {
                // ASCII Output
                println!("--- PE Analysis Report ---");
                println!("File: {}", analysis_result.file_path);
                println!("IAT Size (Imported Modules): {}", analysis_result.iat_size);
                println!("Suspicious/Packed: {}", analysis_result.is_suspicious);
                println!("Sections:");
                for sec in &analysis_result.sections {
                    println!(
                        "  - Name: {:<8} VA: 0x{:08X} RawSize: {:<8} Entropy: {:.4} (Packed: {})",
                        sec.name, sec.virtual_address, sec.raw_data_size, sec.entropy, sec.is_packed
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("Error analyzing file: {}", e);
        }
    }
}
