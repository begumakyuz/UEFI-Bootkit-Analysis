use clap::Parser;
use rust_analyzer::{
    analyze_pe_file, analyze_elf_file, SecurityVerdict, 
    signatures::perform_signature_analysis,
    reporter::{MarkdownReporter, ReportConfig, JsonReporter},
    html_reporter::HtmlReporter,
    config::EngineConfig,
    yara_parser::YaraLiteEngine
};
use std::path::Path;
use std::fs::read;

/// # Begüm Akyüz - UEFI Forensics & Security Suite (v4.0 Elite)
/// 
/// Professional command-line interface for the analysis of UEFI firmware 
/// objects, bootloaders, and system drivers. This suite is designed 
/// specifically for academic research into Ring-2 (SMM) and Ring-1 
/// (Kernel) threats like BlackLotus, MoonBounce, and CosmicStrand.
#[derive(Parser)]
#[command(name = "Begum Akyuz - UEFI Security Suite")]
#[command(author = "Begüm AKYÜZ <student@istinye.edu.tr>")]
#[command(version = "4.0 Elite")]
#[command(about = "Elite Forensic Analysis of UEFI/EFI binaries for Bootkit Indicators.", long_about = None)]
struct Cli {
    /// Path to the binary file (EFI/ELF) to analyze
    #[arg(short, long)]
    file: String,

    /// Output format (json, md, html, ascii)
    #[arg(short, long, default_value_t = String::from("ascii"))]
    output: String,

    /// Enable deep signature scanning for known UEFI IOCs
    #[arg(short, long, default_value_t = true)]
    signatures: bool,

    /// Path to a custom engine configuration file (optional)
    #[arg(short, long)]
    config: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let path = Path::new(&cli.file);

    // Initial project branding
    eprintln!("[*] Initializing Begüm Akyüz Forensic Suite v4.0 Elite...");

    // 1. Configuration Loading Phase
    // The engine defaults to high-sensitivity thresholds for UEFI analysis.
    let config = if let Some(config_path) = cli.config {
        match std::fs::read_to_string(config_path) {
            Ok(s) => EngineConfig::from_json(&s).unwrap_or_default(),
            Err(_) => EngineConfig::default(),
        }
    } else {
        EngineConfig::default()
    };

    // 2. Pre-analysis existence check
    if !path.exists() {
        eprintln!("[!] Error: Target forensic object not found at: {}", cli.file);
        std::process::exit(1);
    }

    let mut results = Vec::new();

    // 3. Perform Static Structure Analysis (PE/ELF)
    // The analyzer identifies suspicious sections, entry points, and IAT patterns.
    eprintln!("[*] Processing structural analysis for {}...", cli.file);
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

    // 4. Custom YARA-Lite Scanning Phase
    // We utilize a high-performance pattern matching engine to scan for UEFI-specific indicators.
    if cli.signatures {
        eprintln!("[*] Running Deep Signature & YARA-Lite scans...");
        match read(&cli.file) {
            Ok(data) => {
                // Signature Engine (Standard)
                match perform_signature_analysis(&data) {
                    Ok(hits) => {
                        results.push(SecurityVerdict::SIGNATURES { 
                            file: cli.file.clone(), 
                            hits 
                        });
                    }
                    Err(e) => eprintln!("[!] Signature analysis failed: {}", e),
                }

                // YARA-Lite Custom Rules Engine
                let mut yara_engine = YaraLiteEngine::new();
                yara_engine.add_rule(YaraLiteEngine::get_blacklotus_rule());
                yara_engine.add_rule(YaraLiteEngine::get_cosmicstrand_rule());
                
                let yara_hits = yara_engine.scan(&data);
                for hit in yara_hits {
                    eprintln!("[!] INDICATOR MATCH: {}", hit);
                    // (Logic to integrate into results list as needed)
                }
            }
            Err(e) => eprintln!("[!] Failed to read file for signatures: {}", e),
        }
    }

    // 5. High-Fidelity Report Generation Phase
    // Professional reporting allows security teams to persist and audit findings.
    match cli.output.to_lowercase().as_str() {
        "json" => {
            match JsonReporter::export_json(&results) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("[!] JSON Export Error: {}", e),
            }
        }
        "md" => {
            let reporter = MarkdownReporter::new(ReportConfig::default());
            let report = reporter.generate_report(&results);
            println!("{}", report);
        }
        "html" => {
            let reporter = HtmlReporter::new("Begüm AKYÜZ");
            let dashboard = reporter.generate_dashboard(&results);
            println!("{}", dashboard);
            
            // Optionally save to disk if configured
            let _ = reporter.save_report("forensic_dashboard.html", &dashboard);
            eprintln!("[+] Professional Dashboard generated: forensic_dashboard.html");
        }
        _ => {
            // Default: Professional Terminal Report (ASCII Dashboard)
            println!("+--------------------------------------------------------------+");
            println!("|  BEGÜM AKYÜZ SECURITY SUITE: ELITE FORENSIC AUDIT (v4.0)     |");
            println!("+--------------------------------------------------------------+");
            for res in results {
                match res {
                    SecurityVerdict::PE(res) => {
                        println!("| > Module: PE Firmware Binary ({})", if res.is_suspicious { "🚩" } else { "✅" });
                        println!("|   - Max Entropy: {}", res.entropy_explanation);
                        println!("|   - EP State: 0x{:X} ({})", res.entry_point, if res.ep_is_suspicious { "ANOMALOUS" } else { "NORMAL" });
                    }
                    SecurityVerdict::SIGNATURES { file: _, hits } => {
                        println!("| > Engine: Deep Pattern Scan (Matches: {})", hits.len());
                        for hit in hits {
                            println!("|   [!] {:?} Match: {}", hit.severity, hit.signature_name);
                        }
                    }
                    _ => {}
                }
            }
            println!("+--------------------------------------------------------------+");
        }
    }
}
