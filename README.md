# EFI/UEFI Bootkit Analizi: BlackLotus Vakası (5 Aşamalı Güvenlik İncelemesi)

**Rol:** Güvenlik Uzmanı / Sistem Mimarı  
**Proje Kodu:** 33. EFI/UEFI Bootkit Analizi  
**Tarih:** 2026-04-03  

Bu doküman, "**İşletim sistemi (Windows) bile başlamadan anakart üzerinden sisteme kanca atan bir bootkit malware yapısının analiz edilmesi**" konulu bitirme çalışmasını, Vize Projesi'nin **Zorunlu 5 Aşama Kriteri**'ne harfiyen uyarak sunmaktadır. BlackLotus zararlısı bir vaka çalışması olarak ele alınmış, bu repoya özgü CI/CD siber otomasyonları ve Docker zafiyet inceleme simülasyonları eklenmiştir.

---

## Adım 1: Kurulum ve install.sh Analizi (Enfeksiyon Mekanizması)

Zararlı yazılımların (özellikle Bootkitlerin) en kritik aşaması kurulum anıdır. Repomuzdaki `install.sh` simülasyon scripti incelendiğinde saldırganın şu yolu izlediği görülür:
1. İşletim sistemindeki EFI System Partition (ESP) tespit edilir `(/boot/efi)` veya zorla mount edilir.
2. Açık kaynak araçların aksine `curl | bash` yapmaz; kurbanın sistemine gizlice iner, `bootmgfw.efi` (Windows bootloader) dosyasını yeniden adlandırıp, kendisini orijinal önyükleyici gibi gösterir.
3. Repodaki YARA kuralları (`yara/blacklotus_bootkit.yar`), zararlının bu kurulum anında bıraktığı PDB dizinlerini (`bootkit.pdb`) saptamak için yazılmıştır.

> **Kritik Soru Yanıtı:** İndirilen kaynaklar güvenli değil, sahte bir imza (Baton Drop - CVE-2022-21894) taşıyor. Bootkitler, Hash (İmza) kontrolü yapan Microsoft **Secure Boot** sistemini, eski ama geçerli imzalı bir Windows kernel hatasını istismar ederek atlatır.

---

## Adım 2: İzolasyon ve İz Bırakmadan Temizlik (Forensics & Cleanup)

Geleneksel bir yazılımın aksine anakart seviyesine (SMM, Ring -2) yerleşmiş bir virüsü sistemden silmek çok zordur.

> **Kritik Soru Yanıtı: Kayıt veya kalıntı dosya kalmadığından tam olarak nasıl emin olacaksınız?**
1. **İzolasyon:** İşlem, zararlının Windows kernel'i içinden engellenemeyeceği için sistem tamamen kapalıyken (Live USB Forensic dağıtımı kullanılarak) dışarıdan yapılmalıdır.
2. **NVRAM ve Değişken Temizliği:** UEFI NVRAM değişkenleri olan `BootOrder` ve `BootCurrent` kayıtları incelenip zararlının eklediği entry'ler (Örn: `Setup` veya `MokList`) `efibootmgr` veya BIOS üzerinden sıfırlanmalıdır.
3. **ESP Dizin Temizliği:** `\EFI\Microsoft\Boot` altındaki sahte `.efi` dosyaları uçurulup orijinali `bcdboot` komutuyla onarılır. Tüm logların (`bcdedit` flagleri dâhil) orijinal sıfır durumuna döndüğü test makinelerinde kanıtlanmıştır.

---

## Adım 3: İş Akışları (CI/CD) ve Webhook Pipeline Analizi

Bir siber güvenlik reposunda otomasyon şarttır. Bu projedeki `.github/workflows/analysis.yml` dosyasını incelediğimizde YARA analiz motorunun otomatik tetiklendiğini görürüz.

> **Kritik Soru Yanıtı: "Webhook" nedir ve bu proje özelinde ne işe yarar?**
**Webhook**, bir olay gerçekleştiğinde (Push yapılması) başka bir servisi HTTP(S) POST isteğiyle otomatik haberdar eden mekanizmadır. 
Bu "UEFI Analiz" projesinde CI/CD Akışı: Bir analist repoya şüpheli bir `.efi` dosyası yüklediğinde (Push olayı), GitHub Webhook'u arka plandaki CI (Continuous Integration) sunucusunu uyarır. CI sunucusu, Ubuntu üzerinde otomatik olarak repodaki `analysis.yml` komutlarını çalıştırır ve yüklenen dosyanın **BlackLotus Zararlısı** olup olmadığını `yara` ile test eder. Sistemin insan eli değmeden %100 otomatize güvenliğini sağlar.

---

## Adım 4: Docker Mimarisi ve Konteyner Güvenliği

Tehlikeli bir UEFI zararlısını analiz ederken sistemi riske atmamak için repoya bir `Dockerfile` eklenmiştir.

> **Kritik Soru Yanıtı: Docker imajı nedir? Konteyner sisteme nereden erişebilir, VM ile farkı nedir?**
- **Docker Mimari Simülasyonumuz:** Repomuzdaki `Dockerfile`, Multi-stage ve "Rootless" mimari kullanır. `USER analyst (1000)` komutuyla ayrıcalıkları asgari (Least Privilege) seviyeye çekilmiştir. İçerisine `UEFITool` ve `Python` kurulmuştur.
- **Konteyner Erişim Sınırı:** Konteynerler Host'un İşletim Sistemi Çekirdeğini (Kernel) kullanır, sanallaştırma yazılımsaldır (cgroups & namespaces). Bootkitler Kernel öncesi çalıştığından Docker içindeyken "tehlikesizdir" çünkü donanımsal (UEFI) erişimleri kısıtlıdır. Ancak privilege escalation olursa Kernel dışına çıkabilir.
- **Güvenliği Sağlamak:** Bu yüzden `read_only` dosya sistemleri uygulanmalıdır. **VM (Sanal Makine)** ise tamamen bağımsız bir Hypervisor ve sanal anakart sunduğu için UEFI Bootkitlerin gerçek detonasyonu (patlatılıp test edilmesi) Docker'da değil, ancak bir VM ortamında yapılabilir!

---

## Adım 5: Kaynak Kod ve Akış Analizi (Threat Modeling & Auth Bypass)

Buradaki `Entry Point`, Windows'un önyükleme uygulamasıdır. Zararlı yazılım `routers` yerine doğrudan anakart boot hizmetlerine kanca atar.

> **Kritik Soru Yanıtı: Hacker kaynak koda bakarak sistemi dışarıdan nasıl etkisiz bırakır? (Auth Analizi)**
- **Hooking Operasyonu:** BlackLotus, bir web uygulaması gibi Session_ID sızdırmaz; IDA Pro ile yazılan `scripts/resolve_gbs.py` kodumuzda da görüldüğü üzere `gBS->LocateProtocol` kullanarak Windows'un `OslArchTransferToKernel` noktasına sızar.
- **Kimlik Doğrulama Katliamı (Bypass):** Bootkit bu kancayı attıktan sonra en büyük Auth sistemi olan "Windows BitLocker"ı, "HVCI" kalkanlarını ve "Windows Defender" kimlik doğrulama politikalarını (registry / BCD argümanlarını `testsigning` yaparak) bellekten (RAM'den) kalıcı olarak siler ve bypass/atlatma operasyonunu tamamlar.
