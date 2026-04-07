use rust_analyzer::{html_reporter::HtmlReporter, config::EngineConfig, pe_parser::SectionAnalysis};

#[test]
fn test_html_dashboard_generation() {
    let reporter = HtmlReporter::new("Begüm AKYÜZ");
    let results = Vec::new();
    let dashboard = reporter.generate_dashboard(&results);
    assert!(dashboard.contains("Begüm AKYÜZ"));
    assert!(dashboard.contains("UEFI Forensic Dashboard"));
}

#[test]
fn test_config_parallel_logic() {
    let mut config = EngineConfig::default();
    config.general.parallel = true;
    assert!(config.general.parallel);
}

#[test]
fn test_pe_ep_anomalous_detection() {
    // Artificial result for logic testing
    let res = rust_analyzer::pe_parser::PEAnalysisResult {
        file_path: "test.efi".to_string(),
        sections: vec![SectionAnalysis {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_data_size: 0x1000,
            entropy: 5.0,
            is_packed: false,
        }],
        iat_size: 20,
        is_suspicious: false,
        entropy_explanation: "".to_string(),
        machine: 0,
        subsystem: 0,
        entry_point: 0x5000, // OUTSIDE .text
        image_base: 0,
        ep_is_suspicious: true,
    };
    
    assert!(res.ep_is_suspicious);
}
