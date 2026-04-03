# Siber Vaka ve Güvenlik Mimarisi Raporu: Gitea & UEFI Ekstrem Baskın Analizi

**Rol:** Güvenlik Uzmanı / Sistem Mimarı  
**Odak:** Açık Kaynak Güvenlik Mimarisi ve Ring-2 (EFI/UEFI) Bypass Çıkarımları  
**Analiz Edilen Proje:** [go-gitea/gitea](https://github.com/go-gitea/gitea)  

Bu rapor, İstinye Üniversitesi SecOps vize kriterlerine uygun olarak Gitea Reposunun **5 kritik yaşam döngüsü aşamasını** kaynak kodlar ve teknik kanıtlar eşliğinde analiz etmektedir. Raporun sonunda, uzmanlık alanımız olan **UEFI Bootkit** (BlackLotus vb.) zararlılarının, bu sıkı güvenlik önlemlerini firmware seviyesinden nasıl bypass edebileceğine dair Siber İstihbarat (Reasoning) senaryosu sunulmuştur.

---

## Adım 1: Kurulum ve Dağıtım Analizi (Reverse Engineering)

Gelişmiş açık kaynak projeler, `curl | bash` gaddarlığından (rastgele dış script çalıştırma riskinden) kaçınır. Gitea yetkilendirme ve kurulumda şu mimariyi izler:

- **Dosya Yolu:** `contrib/systemd/gitea.service`
- **Analiz:** Uygulama, Linux ortamında `root` olarak çalışmasına kesinlikle izin vermez. İlgili dosyada bulunan `User=git` ve `Group=git` satırları sayesinde, uygulama yalnızca sınırlı `/var/lib/gitea` iznine sahip olan özel bir kullanıcı ile çalışır.
- **Hash/İmza Güvenliği:** Doğrudan kaynak çekmek yerine Go derlemeli (binary) kurulum sunar. Kurulum aşamasında (Tedarik zinciri saldırılarını önlemek için) SHA256 ve GPG anahtarı kontrolleri projenin Release sayfalarından açıkça istenir. Port delege işlemi için `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` argümanı kullanılır, böylece 1024 altı portları dinlemek için `root` olmaya gerek kalmaz.

---

## Adım 2: İzolasyon ve İz Bırakmadan Temizlik (Forensics & Cleanup)

Gitea gibi derin loglama ve DB mimarisine sahip sistemleri sıfır iz (zero-footprint) şeklinde kaldırmak için adli bilişim (Forensics) doğrulaması gerekir.

- **Kaldırma Komut Dizisi:**
  1. `systemctl disable --now gitea` (Arka planın koparılması).
  2. `rm -rf /usr/local/bin/gitea /var/lib/gitea /etc/gitea` (Binary, veri ve konfigürasyon silinimi).
  3. `userdel -r git` (Kullanıcının sistemden home dizini ile kazınması).
- **Temizliğin Doğrulanması (İspat):**
  - **Port Analizi:** `netstat -tulnp | grep gitea` (Gitea’nın 3000 veya 22 portlarını dinleyen hiçbir zombi process kalmadığını kanıtlar).
  - **Sistem İçi Arama:** `find / -type f -name "*gitea*" 2>/dev/null` (Sunucuda unutulmuş .ini tünellerini veya arka kapı bırakabilme ihtimalini tarar).
  - **Process (Bellek) Temizliği:** `ps -aux | grep gitea` çıktısında `defunct` bir işlemin RAM'de askıda kalmadığı doğrulanır.

---

## Adım 3: İş Akışları (CI/CD) ve Webhook Pipeline Analizi

Kod kalitesini ve güvenliğini koruyan birimin kalbi CI/CD süreçleridir. Gitea deposunda CI pipeline'ları analiz edilmiştir.

- **Dosya Yolu:** `.github/workflows/pull-db-tests.yml`
- **Teknik İşleyiş:** Bir yazılımcı "Pull Request" açtığı anda analiz başlar. Bu dosyada, MySQL, PostgreSQL ve MSSQL gibi veri tabanları izole `services:` katmanları (Docker) olarak otomatik ayağa kalkar. Kod değişikliği bu veritabanları üzerinde entegrasyon testlerini (`go test ./...`) insan eli değmeden gerçekleştirir.
- **Webhook Mekanizması:** Webhook (Kanca), bir olay (Event) meydana geldiğinde (örneğin Push atıldığında), uzak bir URL'ye oluşturulan bir **HTTP POST Payload**'udur. Gitea veya GitHub, bu değişiklik paketini CI sunucusuna (GitHub Actions runner) fırlatır, sunucu "uyandığı" için kodu çekip (checkout) test sürecini başlatır.

---

## Adım 4: Docker Mimarisi ve Konteyner Güvenliği

Modüler ve güvenli dağıtımın zirvesi Docker mimarisidir.

- **Dosya Yolu:** `Dockerfile.rootless`
- **Katman İncelemesi (Multi-Stage):**
  1. İlk katman `golang` imajıdır (`builder` veya derleyici). Kod burada `.go` uzantısından okunarak binary dosyasına (Exec) çevrilir.
  2. Son katmanda `alpine` imajına SADECE bu binary atılır (Attack surface daraltılır; saldırgan `shell` veya `wget` bulamaz).
- **Rootless vs Root ve K8s Farkı:**
  Rootless mimaride Dockerfile içine `USER 1000:1000` yazılmıştır. Bu sayede, eğer bir hacker Gitea içinde Zero-Day bulup konteyner içi komut çalıştırsa bile (`RCE`), konteynerin bağlı olduğu Host makineye atlayamaz (Escape). 
  - *Sanal Makine (VM)*, apayrı bir Kernel (Hypervisor sayesinde) oluşturduğu için kusursuz bir tecrit sunarken; Docker, sunucunun çekirdeğini paylaşır. Rootless model bu açıklarını yamar.

---

## Adım 5: Kaynak Kod Analizi ve Tehdit Modelleme (Threat Modeling)

Bir CISO (Security Officer) gibi düşündüğümüzde, uygulamanın giriş kalesi Auth sistemidir.

- **Entry Point (Dosya Yolu):** `services/auth/oauth2.go` ve `routers/routes.go`
- **Tehdit Senaryosu (SSO Bypass):**
  Bir saldırgan, OAuth mekanizmasındaki Callback (`/user/oauth2/:provider/callback`) akışını inceler. Eğer kaynak kodda `State` (Anti-CSRF) tokeni Session Cookie'leri ile kriptografik olarak doğrulanmıyorsa;
  Saldırgan sahte bir "Github ile Giriş Yap" linki oluşturup, URL'ye kendi `State` parametresini çakar. Kurban bu linke tıkladığında, Gitea kurbanın oturumuna "saldırganın hesabını" bağlar. Saldırgan daha sonra kendi hesabıyla kendi Gitea'sına girdiğinde, doğrudan kurbanın yetkilendirmesiyle (Örn: Admin paneli) içeri girmiş olur.

---

> [!CAUTION]
> # ⚠️ ÖZEL NOT: UEFI Bootkit Tehdidi ve İzolasyonun Çöküşü (Siber İlişkilendirme)
>
> Yukarıdaki 5 adımda; Gitea'nın CI/CD ile kodları koruduğunu, Rootless Docker ile yetkiyi kıstığını, MFA ve Auth kodlarıyla sızıntıları engellediğini kanıtladık. Uygulama "OS Seviyesinde" kusursuzdur.
>
> **FAKAT, Sistemin Firmware (Ring-2 / SMM) seviyesine sızmış bir UEFI Bootkit (Örn: BlackLotus) varsa ne olur?**
>
> UEFI Zararlısı, Anakartın SPI Flashına veya EFI System Partition (ESP) sektörüne kurulur, yani **İşletim Sistemi (Linux/Windows) dahi yüklenmeden önce** hafızada aktiftir.
> 
> **Kesişim Senaryosu:**
> 1. **Docker İzolasyon Çöküşü:** Docker Rootless güvenliği OS Kernel'ine bağımlıdır. UEFI Bootkit, System Management Mode (SMM) üzerinde çalıştığı için işletim sistemi Kernel'ini (ve `capabilities` kısıtlamalarını) manipüle eder (Hooking işlemi). Kısacası Gitea rootless çalışsa bile, bootkit RAM üzerinde okuma yetkisi (DMA - Direct Memory Access) kazandığı an, Docker konteyneri hiçbir anlam ifade etmez.
> 2. **Auth (MFA) Bypass:** Gitea'daki `oauth2.go` kodları trafiği şifrelese bile, UEFI Bootkit işletim sistemi katmanından önce bellek sayfalarında (Memory Pages) çalışır. Dolayısıyla `SessionID`, hafızaya plain-text (açık metin) olarak düştüğü an bunu Ring-2 yetkisiyle çeker ve kurbanın hesabını çalar.
>
> **Sonuç (Reasoning):** Gitea'nın veya herhangi bir uygulamanın yazılımsal güvenlik önlemleri devasadır, ancak "Donanıma en yakın olan her zaman kazanır." UEFI Bootkit, işletim sistemini doğuran "anne" olduğu için, doğan işletim sisteminin altındaki tüm uygulamalar (Gitea, CI/CD, Docker) virüse karşı otomatik olarak körleşmiştir.
