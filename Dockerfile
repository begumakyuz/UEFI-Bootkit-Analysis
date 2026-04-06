# UEFI Bootkit Analysis Sandbox (Rootless Docker Architecture)
# Bu Docker imajı, zararlı bir .efi dosyasını güvenli bir şekilde analiz etmek 
# ve UEFITool / Python araçlarını Host sistemden izole etmek için kurgulanmıştır.

FROM ubuntu:22.04

# Run as non-root user for Container Security (Least Privilege)
RUN groupadd -r analyst && useradd -r -g analyst -m analyst

# Gerekli Forensic ve Reverse Engineering paketleri
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    yara \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# UEFITool (CLI version) kurulumu
# Using a more robust download link for UEFIExtract
RUN wget -q https://github.com/LongSoft/UEFITool/releases/download/A68/UEFIExtract_0.28.0_linux.zip -O /tmp/uefitool.zip \
    && unzip -q /tmp/uefitool.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/UEFIExtract || echo "UEFIExtract installation failed, skipping..."

WORKDIR /sandbox

# Kodların konteynere aktarılması
COPY --chown=analyst:analyst . .

# Konteyner güvenliği: Analizi kısıtlı kullanıcı yetkileriyle başlat (Rootless)
USER analyst

ENTRYPOINT ["python3", "./scripts/resolve_gbs.py"]
