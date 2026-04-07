# Değişim Günlüğü (CHANGELOG)

Tüm önemli değişiklikler bu dosyada kayıt altına alınmaktadır.

## [2.0.0] - 2026-04-07

### Eklendi
- **Gelişmiş Rust Analizörü:** IAT Cross-Reference ve CRC32 bütünlük kontrolleri.
- **Dinamik Raporlama:** Analiz sonuçlarını `reports/` klasörü altına JSON ve Markdown olarak kaydeden modül.
- **Görselleştirme:** Forensic verilerini terminalde izlemek için yeni Python görselleştirme scriptleri.
- **Akademik Uyumluluk:** İstinye Üniversitesi proje kriterlerine göre 1000+ satır kod hacmi ve detaylı dokümantasyon.

### Değişmiş
- README içeriği derinlemesine analizler ve tehdit modelleri ile genişletildi.
- Docker izolasyon katmanları 'rootless' yapıya optimize edildi.

### Düzeltildi
- Kurulum scriptlerindeki yetki hataları giderildi.
- CI/CD workflow dosyasındaki test bağımlılıkları güncellendi.
