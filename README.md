# EFI/UEFI Bootkit Analizi: BlackLotus Vakası

**Rol:** Güvenlik Uzmanı / Sistem Mimarı  
**Proje Kodu:** 33. EFI/UEFI Bootkit Analizi  
**Tarih:** 2026-04-03  

> *"Windows açılmadan hırsız eve girmiş bile!"*

Bu rapor, işletim sistemi Kernel'i (Windows) henüz devreye girmeden anakart (BIOS/UEFI) seviyesinden sisteme kanca atan (hooking) modern UEFI Bootkit zararlılarının analizini içermektedir. İnceleme için dünyaca ünlü **BlackLotus Bootkit** (CVE-2022-21894 Baton Drop zafiyetini sömüren) örneklem alınarak tersine mühendislik süreçleri adım adım simüle edilmiştir.

---

## 1. UEFI Boot Süreci ve Bootkit Mantığı (Teorik Temel)

Geleneksel BIOS (Basic Input/Output System) yerini UEFI (Unified Extensible Firmware Interface) standardına bırakmıştır. Modern bir bilgisayar açıldığında süreç şu fazlardan geçer:
1. **SEC (Security):** Sistem uyanır, ön CPU başlatılır.
2. **PEI (Pre-EFI Initialization):** Anakart donanımları (RAM, Chipset) tanınır.
3. **DXE (Driver Execution Environment):** Cihaz sürücüleri yüklenir, mouse/klavye/ağ kartları aktifleşir. *(Bootkitlerin %90'ı bu faza yerleşir).*
4. **BDS (Boot Device Selection):** İşletim sisteminin yükleneceği disk seçilir. `bootmgfw.efi` (Windows Boot Manager) burada tetiklenir.

**Bootkit Mantığı:** BlackLotus gibi zararlılar, işletim sistemi devreye girmeden önce (DXE fazında veya BDS aşamasında EFI System Partition - ESP içerisine) kendi `.efi` sürücülerini yüklerler. Sistem Windows'a geçerken zararlı çoktan hafızaya yerleşmiş (*Ring -2 / SMM düzeyinde*), Antivirüsleri ve EDR'ları kör etmiş olur.

---

## 2. UEFITool ile Statik ve Firmware Analizi

Bir anakart Firmware imajı (örn: `.bin` veya `.rom` dosyası) veya ESP bölümünden çıkarılan bir klasör şifreli ve sıkıştırılmış haldedir. Bunu analiz etmek için **UEFITool** kullanılır.

### UEFITool İşlem Adımları
1. Zararlı şüphesi olan BIOS güncelleme imajı veya bilgisayardan dump edilen SPI Flash imajı UEFITool ile açılır.
2. UEFITool ağacında (Tree view) `DXE Dependency Bölümü` aranır.
3. Zararlı yazılım genelde isimsiz veya rastgele GUID (Global Unique Identifier) ile gizlenen bir modül olarak görünür.
4. Şüpheli modüle sağ tıklanıp **"Extract body"** diyerek zararlının saf PE32+ (PE/COFF) `.efi` dosyası dışarı çıkartılır. Geleneksel `.exe` analizlerine kıyasla `.efi` modülleri farklı bir header yapısına sahiptir.

---

## 3. IDA Pro ile Tersine Mühendislik (Reverse Engineering)

Çıkartılan `bootkit.efi` dosyası **IDA Pro x64** ile analiz edildiğinde, alışılmış Windows API çağrıları (örn: `CreateFile`, `VirtualAlloc`) yerine BIOS tarafından sağlanan çağrılarla karşılaşılır.

### gBS (Boot Services) ve gRT (Runtime Services)
UEFI zararlıları bellekte yer ayırmak veya diske yazmak için Global Değişkenler olan `gBS` ve `gRT` tablolarını kullanır.
- IDA Pro'da `LocateProtocol` (0x140 offset) veya `AllocatePool` (0x38 offset) gibi çağrılar tespit edilir. (Depomuzdaki `scripts/resolve_gbs.py` bu işi otomatik yapar).

### Kanca Atma (Inline Hooking) Analizi
BlackLotus'un ana görevi, Windows'un güvenli önyükleyicisine (`bootmgfw.efi`) kanca atmaktır. IDA Pro ile Disassembly ekranı incelendiğinde zararlının şu kodu çalıştırdığı görülür:
1. `gBS->LocateProtocol` ile Windows Boot Manager'in hafızadaki yerini bulur.
2. Orijinal `ImgArchStartBootApplication` veya `OslArchTransferToKernel` fonksiyonunun ilk 5 byte'ını `JMP <ZARARLI_ADRES>` komutu ile değiştirir (Inline Hook).
3. Böylece Windows Kernel'i ayağa kalkarken önce BlackLotus'un Kernel Payload'u yüklenir.
4. Bu Payload, Windows içindeki BitLocker, HVCI (Hypervisor-Protected Code Integrity) ve Windows Defender gibi korumaları hafızadan siler.

---

## 4. Vaka Analizi: BlackLotus (CVE-2022-21894 Bypassing)

BlackLotus, **Secure Boot** devredeyken bile çalışabilen ilk vahşi bootkit'tir. 

**Nasıl Çalışır? (Zafiyet Sömürüsü):**
Saldırgan (Zararlı yükleyici - Installer), Microsoft tarafından hatalı imzalanmış eski bir boot yöneticisini sisteme indirir. "Baton Drop" (CVE-2022-21894) zafiyeti sayesinde, Secure Boot (Güvenli Önyükleme) mekanizması bu eski ama orijinal imzalı dosyayı güvenli kabul ederek çalıştırır. Ardından eski dosyadaki bir bellek taşması (memory corruption) kullanılarak Secure Boot politikaları (Policy) hafızadan silinir.

**Tespit (Defense):**
Bu tarz zararlıları tespit etmek için standart antivirüsler yetersiz kalır. Bu repoda `yara/` klasörü altında paylaştığımız **YARA kuralı** ile zararlının EFI dosyalarına bıraktığı imza, PDB kalıntıları ve Bypass pattern'leri tespit edilebilir.

---

### Proje Gezinme Rehberi (Repo Yapısı)
- `README.md` : Analiz raporu (Bu dosya)
- `scripts/resolve_gbs.py` : IDA Pro'da kullanılarak gBS call offsetlerini isimlendiren yardımcı betik.
- `yara/blacklotus_bootkit.yar` : Zararlıyı statik analiz ile yakalamaya yarayan YARA tespit kuralı.
- `assets/` : Kavramsal şemalar ve kanıtlar için ayrılmış medya dizini.
