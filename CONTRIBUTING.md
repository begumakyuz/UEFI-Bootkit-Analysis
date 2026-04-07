# Geliştirme Katılım Rehberi (CONTRIBUTING)

Bu proje, İstinye Üniversitesi Siber Güvenlik Mimarisi dersi kapsamında geliştirilen bir "UEFI Bootkit Analiz ve Forensic Raporlama" sistemidir. Proje üzerinde geliştirme yapmak veya yeni özellikler eklemek istiyorsanız lütfen aşağıdaki kurallara uyunuz.

## Kod Standartları

- **Diller:** Rust (Ana Forensics Motoru), Python (Analiz Orkestrasyonu), Bash (Sistem Kurulumu).
- **Temiz Kod:** Her fonksiyon 20 satırı geçmemeli ve %15 oranında yorum satırı içermelidir.
- **Git:** Commit mesajları açıklayıcı olmalı (Örn: `feat: add entropy analysis module`).

## Geliştirme Süreci

1. Projeyi çatallayın (Fork).
2. Özellik dalı (Feature Branch) oluşturun (`git checkout -b ozellik/yeni-analizor`).
3. Değişikliklerinizi yapın ve test edin (`cargo test` ve `python tests/`).
4. Pull Request açmadan önce `README.md` dosyasındaki dokümantasyonu güncellediğinizden emin olun.

## Yazılım Lisansı

Bu proje MIT Lisansı altında sunulmaktadır. Katkıda bulunarak kodunuzun bu lisans altında dağıtılmasını kabul etmiş olursunuz.
