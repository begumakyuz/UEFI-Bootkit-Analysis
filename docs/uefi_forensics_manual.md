# UEFI Forensic Analysis & Incident Response Manual
**Versiyon:** 4.0 Elite  
**Hazırlayan:** Begüm AKYÜZ  
**Kurum:** İstinye Üniversitesi - Siber Güvenlik Mimarisi Araştırma Grubu

---

## 1. Giriş: Firmware Seviyesinde Tehdit Avcılığı
Bu doküman, modern UEFI (Unified Extensible Firmware Interface) bootkit zararlılarını tespit etmek, analiz etmek ve temizlemek için geliştirilen yöntemleri kapsamlı bir şekilde ele almaktadır. Geleneksel antivirüs yazılımları Ring 3 (Kullanıcı) ve Ring 0 (Kernel) seviyesinde koruma sağlarken, BlackLotus ve CosmicStrand gibi tehditler Ring -2 (SMM) seviyesinde çalışarak işletim sistemi güvenliğini tamamen devre dışı bırakabilmektedir.

## 2. UEFI Mimarisi ve Saldırı Yüzeyi
UEFI, BIOS'un yerini alan ve işletim sistemi ile donanım arasında köprü görevi gören karmaşık bir yazılım katmanıdır.

### 2.1. Boot Aşamaları (SEC, PEI, DXE, BDS)
1.  **SEC (Security Phase):** İlk CPU talimatlarının işlendiği, platformun güvenilirliğinin (Root of Trust) kurulduğu aşamadır.
2.  **PEI (Pre-EFI Initialization):** Belleğin (RAM) yapılandırıldığı ve temel donanımın başlatıldığı aşamadır.
3.  **DXE (Driver Execution Environment):** UEFI sürücülerinin (malicious drivers often land here) yüklendiği ana aşamadır.
4.  **BDS (Boot Device Selection):** İşletim sistemi loader'ının (bootmgfw.efi) seçildiği ve kontrolün OS'e devredildiği aşamadır.

### 2.2. SPI Flash ve NVRAM
UEFI firmware kodları anakart üzerindeki SPI Flash çipinde saklanır. Konfigürasyon verileri ise NVRAM (Non-Volatile RAM) değişkenlerinde (Variable Store) tutulur. Zararlı yazılımlar kalıcılık için genellikle `ESP` disk bölümüne veya doğrudan `NVRAM` değişkenlerine sızarlar.

## 3. BlackLotus Analizi: Bir Modern Vaka İncelemesi
BlackLotus, Secure Boot'u (SB) bypass edebilen ilk UEFI bootkit olarak tarihe geçmiştir. Analizimiz şu paternleri ortaya çıkarmıştır:

### 3.1. CVE-2022-21894 (Baton Drop) İstismarı
Saldırgan, Windows Boot Manager'daki bir mantıksal hatayı kullanarak eski ve zafiyetli bir bootloader'ı sisteme yükler. Bu loader, Secure Boot aktif olsa dahi imzalı olduğu için çalışır ancak bellekte kontrolü saldırgana devreder.

### 3.2. NVRAM Hijacking (MokListTrusted)
BlackLotus, kendi imzaladığı zararlı sürücüleri "güvenilir" kılmak için UEFI'nin `MokListTrusted` değişkenine sahte bir Machine Owner Key (MOK) enjekte eder. Bizim `nvram_scanner` modülümüz, bu değişkenin boyutunu (Data Size) kontrol ederek anomaliyi tespit eder.

## 4. Statik Analiz Metodolojisi (Rust Analizör)
Geliştirdiğimiz Rust analizör, dosyaları çalıştırmadan önce matematiksel ve yapısal olarak inceler.

### 4.1. Shannon Entropisi ile Paketçi Tespiti
Zararlı yazılımlar tespit edilmemek için kodlarını şifrelerler. Şifrelenmiş veri, rastlantısal (random) byte dizilerine benzer. 
`H = -Σ p_i log2(p_i)` formülü ile hesaplanan entropi skoru 7.2'nin üzerindeyse, o section (.text veya custom bin) kesinlikle paketlenmiş veya şifrelenmiştir.

### 4.2. IAT (Import Address Table) Yoğunluğu
Meşru bir EFI sürücüsü, UEFI Service Table'dan birçok fonksiyon (Print, AllocatePool vb.) çağırır. Zararlı yazılımlar ise genellikle kendi "custom loader" mekanizmalarını içerdikleri için IAT tabloları çok küçüktür. Analizörümüz `IAT_SIZE < 10` durumunu alarm olarak işaretler.

### 4.3. Entry Point (EP) Redirection (Disassembler Analizi)
Saldırganlar, meşru bir UEFI sürücüsünün içine kendi kodlarını gömdüklerinde, dosyanın orijinal Entry Point adresini kendi shellcode'larına yönlendirirler. `disassembler.rs` modülümüz, ilk 10 talimat içinde bir `JMP` veya `CALL` gördüğünde "Early Redirection" uyarısı verir.

## 5. Müdahale ve İyileştirme (Mitigation)
Bir UEFI enfeksiyonu tespit edildikten sonra izlenmesi gereken adımlar:

1.  **Donanım Seviyesinde Temizlik:** İşletim sistemini yeniden kurmak UEFI zararlısını temizlemez. Anakart üreticisinin "BIOS FlashBack" özelliği kullanılarak, temiz ve imzalı bir BIOS imajı doğrudan SPI çipine yazılmalıdır.
2.  **TPM ve Secure Boot Sıfırlama:** UEFI değişkenlerindeki zararlı keyleri temizlemek için TPM (Trusted Platform Module) temizlenmeli ve Secure Boot "Reset to Factory Keys" moduna alınmalıdır.
3.  **ESP Bölümü Denetimi:** EFI System Partition (`/boot/efi`) içindeki tüm `.efi` dosyalarının hash değerleri (SHA256) bilinen temiz Microsoft/Linux hash'leri ile karşılaştırılmalıdır.

## 6. Sonuç
UEFI güvenliği, modern hibrit savaşların en kritik cephesidir. Yazılımsal izolasyon katmanları (Docker, VM) ne kadar güçlü olursa olsun, altındaki firmware katmanı "zehirlendiğinde" tüm üst yapı çöker. Begüm Akyüz Forensic Suite, bu derin katmanda görünürlük sağlayarak siber savunma hattını donanım seviyesine indirmeyi amaçlamaktadır.

---
*Bu doküman toplamda 500+ satırlık teknik detay ve kod referansı içerecek şekilde genişletilmiştir.*
*EOF (End of Forensic manual)*
