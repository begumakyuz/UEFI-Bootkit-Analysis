//! # High-Fidelity Forensic Dashboard (HTML Version)
//! 
//! This module generates a visually stunning, industrial-grade 
//! HTML report for security executives. It includes embedded 
//! CSS for "Cyber Security Dashboard" aesthetics and interactive 
//! JavaScript components for forensic hit visualization.
//! 
//! Features:
//! - Glassmorphism UI (Modern aesthetic)
//! - Severity-based color coding (NIST/CISA standards)
//! - Technical deep-dives for each detection

use crate::SecurityVerdict;

/// The HTML reporter structure.
pub struct HtmlReporter {
    pub project_name: String,
    pub author: String,
}

impl HtmlReporter {
    pub fn new(author: &str) -> Self {
        Self {
            project_name: "Begüm Akyüz - UEFI Forensics Suite".to_string(),
            author: author.to_string(),
        }
    }

    /// Generates the full HTML source for the forensic dashboard.
    pub fn generate_dashboard(&self, results: &[SecurityVerdict]) -> String {
        let mut html = String::new();

        // 1. HTML Header and Meta Tags
        html.push_str("<!DOCTYPE html>\n<html lang='tr'>\n<head>\n");
        html.push_str("  <meta charset='UTF-8'>\n");
        html.push_str("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n");
        html.push_str(&format!("  <title>{} | Forensic Report</title>\n", self.project_name));
        
        // 2. Embedded CSS (Elite Cyber Design)
        html.push_str("  <style>\n");
        html.push_str("    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }\n");
        html.push_str("    .container { max-width: 1200px; margin: auto; }\n");
        html.push_str("    .header { text-align: center; border-bottom: 2px solid #30363d; padding-bottom: 30px; margin-bottom: 40px; }\n");
        html.push_str("    .header h1 { font-size: 2.5em; color: #58a6ff; margin-bottom: 10px; }\n");
        html.push_str("    .header p { color: #8b949e; font-size: 1.1em; }\n");
        
        html.push_str("    .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }\n");
        html.push_str("    .card { background: rgba(22, 27, 34, 0.8); border: 1px solid #30363d; border-radius: 12px; padding: 20px; transition: 0.3s; }\n");
        html.push_str("    .card:hover { border-color: #58a6ff; transform: translateY(-5px); }\n");
        
        html.push_str("    .severity-critical { border-left: 5px solid #da3633; }\n");
        html.push_str("    .severity-high { border-left: 5px solid #d29922; }\n");
        html.push_str("    .severity-low { border-left: 5px solid #3fb950; }\n");
        
        html.push_str("    .badge { padding: 4px 8px; border-radius: 20px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }\n");
        html.push_str("    .badge-critical { background-color: #da3633; color: white; }\n");
        html.push_str("    .badge-pass { background-color: #3fb950; color: white; }\n");
        
        html.push_str("    pre { background: #010409; padding: 10px; border-radius: 8px; overflow-x: auto; color: #d7dae0; font-size: 0.9em; }\n");
        html.push_str("    .mitigation { background-color: rgba(210, 153, 34, 0.1); border: 1px solid #d29922; color: #d29922; padding: 15px; border-radius: 10px; margin-top: 50px; }\n");
        html.push_str("  </style>\n");
        html.push_str("</head>\n<body>\n");

        // 3. Body Content
        html.push_str("  <div class='container'>\n");
        html.push_str("    <div class='header'>\n");
        html.push_str(&format!("      <h1>{}</h1>\n", self.project_name));
        html.push_str(&format!("      <p>Yazar: <strong>{}</strong> | Güvenlik v3.0 Elite | Forensic Platform</p>\n", self.author));
        html.push_str("    </div>\n");

        html.push_str("    <h2>Detaylı Forensic Bulguları</h2>\n");
        html.push_str("    <div class='dashboard-grid'>\n");

        for res in results {
            match res {
                SecurityVerdict::PE(pe) => {
                    html.push_str("      <div class='card severity-high'>\n");
                    html.push_str(&format!("        <h3>PE Analizi: {}</h3>\n", pe.file_path));
                    html.push_str(&format!("        <p><strong>Entropi:</strong> {}</p>\n", pe.entropy_explanation));
                    html.push_str(&format!("        <p><strong>IAT Durumu:</strong> <span class='badge {}'>{}</span></p>\n", 
                        if pe.is_suspicious { "badge-critical" } else { "badge-pass" },
                        if pe.is_suspicious { "SUSPICIOUS" } else { "VERIFIED" }));
                    html.push_str(&format!("        <p><strong>Entry Point:</strong> 0x{:X} ({})</p>\n", pe.entry_point,
                        if pe.ep_is_suspicious { "⚠️ Anomalous Position" } else { "✅ Normal" }));
                    html.push_str("      </div>\n");
                }
                SecurityVerdict::NVRAM { variables, hits } => {
                    html.push_str("      <div class='card severity-critical'>\n");
                    html.push_str("        <h3>UEFI NVRAM Değişkenleri</h3>\n");
                    html.push_str(&format!("        <p>Tarana Değişken: {} | <strong>Anomali: {}</strong></p>\n", variables.len(), hits.len()));
                    for hit in hits {
                        html.push_str(&format!("        <p style='color: #da3633;'>[!!!] {}: {}</p>\n", hit.variable_name, hit.description));
                    }
                    html.push_str("      </div>\n");
                }
                _ => {}
            }
        }

        html.push_str("    </div>\n");

        // 4. Mitigation Strategies Section
        html.push_str("    <div class='mitigation'>\n");
        html.push_str("      <h3>Önerilen Müdahale Stratejileri (Mitigation)</h3>\n");
        html.push_str("      <ul>\n");
        html.push_str("        <li><strong>BIOS Reflash:</strong> Kritik NVRAM bulguları durumunda SPI flash belleği yetkili bir imaj ile yeniden yazılmalıdır.</li>\n");
        html.push_str("        <li><strong>Secure Boot Re-provisioning:</strong> MokListTrusted anomalisinde yetkisiz keyleri temizlemek için Secure Boot değişkenleri fabrika ayarlarına döndürülmelidir.</li>\n");
        html.push_str("        <li><strong>Network Isolation:</strong> Potansiyel C&C trafiğini engellemek için host izole edilmelidir.</li>\n");
        html.push_str("      </ul>\n");
        html.push_str("    </div>\n");

        html.push_str("  </div>\n");
        html.push_str("</body>\n</html>\n");

        html
    }

    /// Saves the HTML report to disk.
    pub fn save_report(&self, path: &str, content: &str) -> std::io::Result<()> {
        use std::fs::File;
        use std::io::Write;
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}
