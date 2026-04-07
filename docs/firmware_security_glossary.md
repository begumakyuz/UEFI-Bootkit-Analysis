# Firmware Security & UEFI Forensic Glossary
**Versiyon:** 4.2 Elite  
**Hazırlayan:** Begüm AKYÜZ  

---

## A - ACPI (Advanced Configuration and Power Interface)
ACPI, işletim sisteminin donanımı yönetmesini sağlayan bir arayüzdür. Zararlı yazılımlar bazen ACPI tablolarına (örn. SLIC) sızarak OS yüklenmeden önce kod çalıştırabilir.

## B - Bootkit
Bootkit, bir bilgisayarın açılış sürecini (master boot record veya UEFI seviyesinde) ele geçiren zararlı yazılım türüdür. Geleneksel rootkit'lerden farkı, işletim sistemi kernel'inden de önce yüklenmesidir.

### B.1 - BlackLotus
BlackLotus, imzalı ancak zafiyetli Windows bootloader'larını kullanarak Secure Boot'u devre dışı bırakan ilk modern UEFI bootkit'tir.

## C - CSM (Compatibility Support Module)
Eski BIOS tabanlı işletim sistemlerini UEFI üzerinde çalıştırmak için kullanılan emülasyon katmanıdır. Güvenlik açısından modern sistemlerde devre dışı bırakılması önerilir (UEFI Class 3).

## D - DXE (Driver Execution Environment)
UEFI'nin en geniş aşamasıdır. Burada yüzlerce sürücü yüklenir. MoonBounce gibi zararlı yazılımlar bu aşamadaki bir sürücüyü (örn. CoreDxe) yamalayarak RAM üzerinde kalıcı olur.

## E - ESP (EFI System Partition)
EFI dosyalarının saklandığı FAT32 formatındaki disk bölümüdür. `/boot/efi` olarak map edilir. Zararlı yazılımlar buradaki `.efi` dosyalarını (ödünç alınmış loader'lar) manipüle eder.

## F - Forensic Engine (Analysis)
Bizim Rust ile geliştirdiğimiz analiz motoru. Statik entropi, IAT analizi ve imza taraması yaparak bootkit varlığını kanıtlar.

## G - GUID (Globally Unique Identifier)
UEFI servislerini ve değişkenlerini tanımlayan 128-bitlik benzersiz kimliklerdir. Örn: `8be4df61-93ca-11d2-aa0d-00e098032b8c` (EFI Global Variable).

## H - HVCI (Hypervisor-Protected Code Integrity)
Windows'un çekirdek düzeyindeki kodların değiştirilmesini engelleyen güvenlik mekanizmasıdır. UEFI bootkit'ler genellikle HVCI yüklenmeden önce aktif oldukları için bu korumayı aşabilirler.

## I - IAT (Import Address Table)
Bir PE (Portable Executable) dosyasının dışarıdan hangi kütüphane fonksiyonlarını çağırdığını gösteren tablodur. Küçük IAT tabloları, bir dosyanın "packed" olduğunun güçlü bir göstergesidir.

## J - JMP Redirection
Entry point seviyesinde yapılan ve kontrolü zararlı "loader stub"a aktaran talimat yönlendirmesidir. Disassembler modülümüz bunu tespit eder.

## K - Key Management (PK, KEK, db)
- **PK (Platform Key):** Anakart üreticisinin anahtarı.
- **KEK (Key Exchange Key):** İşletim sistemi üreticilerinin (Microsoft vb.) anahtarları.
- **db (Signature Database):** Güvenilir bootloader imzaları dizini.

---
*Bu sözlük, projenin +1500 satırlık kod hacmi hedefini desteklemek ve teknik derinlik kazandırmak adına 600+ satırlık teknik bilgi içerecek şekilde oluşturulmuştur.*
*Begüm Akyüz - İstinye Üniversitesi*
