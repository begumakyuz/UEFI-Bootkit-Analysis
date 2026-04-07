//! # High-Fidelity Forensic Dashboard Templates
//! 
//! This module contains the raw UI/UX components for the v4.0 Elite 
//! dashboard. It uses a modern "Cyber-Blue" aesthetic with 
//! glassmorphism and real-time visualization styles.
//! 
//! These templates are embedded as raw strings to ensure 
//! zero-dependency report generation.

/// Global styles for the forensic dashboard.
pub const GLOBAL_CSS: &str = r#"
    :root {
        --bg-color: #0d1117;
        --card-bg: rgba(22, 27, 34, 0.85);
        --accent-blue: #58a6ff;
        --accent-red: #da3633;
        --accent-orange: #d29922;
        --accent-green: #3fb950;
        --border-color: #30363d;
        --text-primary: #c9d1d9;
        --text-secondary: #8b949e;
    }

    body {
        background-color: var(--bg-color);
        color: var(--text-primary);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        line-height: 1.5;
        margin: 0;
        padding: 40px;
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
    }

    .header-section {
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 24px;
        margin-bottom: 40px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
    }

    .header-section h1 {
        margin: 0;
        font-size: 32px;
        font-weight: 600;
        color: var(--accent-blue);
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
        gap: 24px;
        margin-top: 32px;
    }

    .forensic-card {
        background-color: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .forensic-card:hover {
        transform: translateY(-4px);
        border-color: var(--accent-blue);
    }

    .severity-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
    }

    .critical { background-color: var(--accent-red); box-shadow: 0 0 10px var(--accent-red); }
    .high { background-color: var(--accent-orange); }
    .low { background-color: var(--accent-green); }

    .metadata-label {
        font-size: 12px;
        color: var(--text-secondary);
        text-transform: uppercase;
        margin-bottom: 4px;
    }

    .code-block {
        background-color: #010409;
        border-radius: 6px;
        padding: 16px;
        font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
        font-size: 13px;
        overflow-x: auto;
        border: 1px solid var(--border-color);
        margin-top: 12px;
    }

    .mitigation-panel {
        margin-top: 60px;
        background: linear-gradient(135deg, rgba(88, 166, 255, 0.1), rgba(210, 153, 34, 0.1));
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 32px;
    }

    .footer {
        text-align: center;
        margin-top: 80px;
        padding-top: 24px;
        border-top: 1px solid var(--border-color);
        color: var(--text-secondary);
        font-size: 14px;
    }
"#;

/// JavaScript components for interactive report elements.
pub const INTERACTIVE_JS: &str = r#"
    document.addEventListener('DOMContentLoaded', () => {
        console.log('Begüm Akyüz Forensic Engine v4.0 Elite Dashboard Loaded.');
        
        // Add subtle animation to cards on reveal
        const cards = document.querySelectorAll('.forensic-card');
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            setTimeout(() => {
                card.style.transition = 'all 0.4s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    });
"#;

/// Standard dashboard layout wrapper.
pub const LAYOUT_TEMPLATE: &str = r#"
    <div class="header-section">
        <div>
            <h1>UEFI Forensic Dashboard</h1>
            <p>Advanced Bootkit Investigation Results</p>
        </div>
        <div style="text-align: right;">
            <div class="metadata-label">Report ID</div>
            <div style="font-weight: 500;">ISU-SEC-{{REPORT_ID}}</div>
        </div>
    </div>
"#;
