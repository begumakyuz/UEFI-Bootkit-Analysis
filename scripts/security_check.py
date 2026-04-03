import os
import sys

def check_env_configuration():
    """
    Güvenlik Analizi aracı ve çevre değişkenleri kontrolleri.
    .env konfigürasyonunu kullanarak projenin kurallara uygunluğunu dener.
    """
    yara_path = os.getenv("YARA_RULES_PATH", "./yara/blacklotus_bootkit.yar")
    analysis_mode = os.getenv("ANALYSIS_MODE", "strict")
    
    if analysis_mode != "strict":
        return False, "HATA: Analiz modu 'strict' olmali. (SecOps Kriteri İhlali)"
        
    return True, f"Güvenlik tarama yapılandırması başarılı. Hedef kural: {yara_path}"

if __name__ == "__main__":
    status, msg = check_env_configuration()
    print(msg)
    sys.exit(0 if status else 1)
