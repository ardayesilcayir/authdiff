# authdiff — Ürün Gereksinimleri Dokümanı (PRD)

Nov 20, 2026 · @Arda

## 1. Özet

authdiff, REST API'lerdeki yetkilendirme açıklarını (BOLA/IDOR, BFLA, mass assignment) otomatik bulan, açık kaynaklı bir komut satırı aracıdır. OpenAPI dosyasını ve farklı yetki seviyesindeki kullanıcı oturumlarını alır, her endpoint'i her kimlikle çağırır, yanıtları akıllıca karşılaştırır ve bulguları SARIF, JSON ve HTML olarak raporlar.

| Alan | Değer |
| --- | --- |
| Proje adı | authdiff |
| Tür | Açık kaynak CLI güvenlik test aracı + GitHub Action |
| Hedef sürüm | v1.0 (ilk kararlı sürüm) |
| Lisans | MIT (öneri) |
| Ana dil | Go 1.23+ |
| Geliştirici | Tek kişi (bireysel portföy projesi) |
| Tahmini süre | 10 hafta, haftada 10–12 saat |

## 2. Projenin amacı ve problem tanımı

Amaç, klasik tarayıcıların en zayıf olduğu açık sınıfını (yetkilendirme mantığı hatalarını) tekrarlanabilir ve CI'a bağlanabilir şekilde test etmektir. OWASP API Security Top 10 (2023) listesinde API1 BOLA, API3 nesne özelliği düzeyinde yetki (mass assignment dahil) ve API5 BFLA, üçü de yetkilendirme sorunudur.

**Problem:**

- Yetki açığı bir "imza" ile yakalanamaz. `GET /orders/42` isteği teknik olarak geçerlidir. Sorun, isteği yapan kullanıcının o siparişin sahibi olmamasıdır.
- ZAP, Nikto gibi genel tarayıcılar tek bir oturumla çalışır. Kimlikler arasındaki farkı (A görebiliyor, B görebilmeli mi?) sistematik olarak sorgulamaz.
- Burp Suite eklentileri (Autorize vb.) bu işi elle, proxy üzerinden yapar. CI/CD'de otomatik çalışmaz ve OpenAPI'den test üretmez.
- Geliştirici ekipler yetki testlerini birim testlerde nadiren yazar. Bu açıklar genellikle sızma testinde ya da üretimde bulunur.

**Çözüm:** authdiff, bir "yetki matrisi" tanımlar (hangi rol hangi kaynağa erişebilmeli), bu matrisi OpenAPI'den üretilen isteklerle sınar ve beklenenle gerçekleşen arasındaki farkı bulgu olarak raporlar.

**Kişisel amaç (portföy):** Web güvenliği, Go ile sistem programlama, test disiplini ve DevSecOps yetkinliğini tek bir somut üründe göstermek; siber güvenlik stajı başvurularında teknik derinliği kanıtlayan bir referans oluşturmak.

## 3. Hedefler ve kapsam dışı

**Hedefler (v1.0):**

1. OpenAPI 3.x dosyasından endpoint envanterini otomatik çıkarmak.
2. En az 4 kimlik (admin, kullanıcı A, kullanıcı B, anonim) ile tüm endpoint'leri test etmek.
3. BOLA, BFLA, mass assignment ve kimlik doğrulamasız erişim açıklarını tespit etmek.
4. Demo laboratuvarındaki bilinen açıkların en az %90'ını bulmak, yanlış pozitif oranını %10'un altında tutmak.
5. Sonuçları SARIF ile GitHub Security sekmesine, HTML ile insan okunur rapora dökmek.
6. Bir GitHub Action ile her PR'da çalışabilmek.

**Kapsam dışı (v1.0'da yapılmayacak):**

- SQL injection, XSS gibi girdi tabanlı açık taraması (bunun için nuclei/ZAP var).
- GraphQL ve gRPC desteği (v2 adayı).
- Web arayüzü / dashboard (yalnızca statik HTML rapor).
- Kimlik bilgisi kaba kuvvet denemesi, DoS veya kapsam dışı sistemlere istek.
- Otomatik oturum açma akışları (OAuth/SSO otomasyonu); v1'de token'lar kullanıcı tarafından verilir.

## 4. Hedef kullanıcılar ve kullanım senaryoları

| Persona | İhtiyaç | authdiff'i nasıl kullanır |
| --- | --- | --- |
| Sızma testi uzmanı | Kısa sürede tüm endpoint'lerde yetki kontrolü | Yetkili test kapsamında `authdiff scan` ile ön tarama, bulguları elle doğrular |
| Backend geliştirici | Yetki hatasını üretime taşımamak | Yerelde veya staging'de çalıştırır, HTML raporu okur |
| DevSecOps / AppSec ekibi | Her PR'da otomatik yetki regresyon testi | GitHub Action + SARIF, kritik bulguda build kırılır |
| Bug bounty araştırmacısı | Program kapsamında IDOR avlamak | Kapsam dosyası ve düşük hız limitiyle çalıştırır |
| Öğrenci / eğitmen | BOLA'yı uygulamalı öğrenmek | Demo laboratuvarı (vuln-lab) ile birlikte kullanır |

**Kullanıcı hikayeleri:**

- Bir AppSec mühendisi olarak, OpenAPI dosyamı ve iki test kullanıcısının token'ını verip tek komutla hangi endpoint'lerin başkasının verisini döndürdüğünü görmek istiyorum.
- Bir geliştirici olarak, yeni eklediğim endpoint yetki matrisine uymuyorsa PR'ımın kırmızı olmasını istiyorum.
- Bir pentester olarak, aracın yalnızca izin verilen host'lara ve belirlediğim hızda istek atmasını istiyorum.
- Bir yönetici olarak, bulguları önem derecesine göre sıralanmış, kanıtlı (istek/yanıt) bir rapor olarak görmek istiyorum.
- Bir kullanıcı olarak, yanlış pozitif olduğunu bildiğim bulguyu bir kez susturup sonraki taramalarda görmemek istiyorum.

## 5. Özellikler (fonksiyonel gereksinimler)

Öncelikler: **P0** = v0.1 MVP için zorunlu, **P1** = v1.0 için zorunlu, **P2** = v1.0 sonrası / zaman kalırsa.

### 5.1 Girdi ve keşif

| ID | Özellik | Öncelik | Kabul kriteri |
| --- | --- | --- | --- |
| F-01 | OpenAPI 3.0/3.1 (YAML/JSON) ayrıştırma | P0 | Petstore ve vuln-lab spec'lerindeki tüm path + method çiftleri listelenir |
| F-02 | Parametre çıkarımı (path, query, header, body şeması) | P0 | Her endpoint için zorunlu parametreler örnek değerlerle doldurulur |
| F-03 | Swagger 2.0 desteği (otomatik dönüşüm) | P2 | 2.0 dosyası 3.0'a çevrilip aynı envanteri verir |
| F-04 | HAR / Burp XML içe aktarma (spec yoksa) | P2 | Kayıtlı trafikten endpoint listesi üretilir |
| F-05 | Endpoint filtreleme (`--include`, `--exclude`, etiket) | P1 | Glob desenleriyle seçilen endpoint'ler dışında istek atılmaz |

### 5.2 Kimlik ve oturum yönetimi

| ID | Özellik | Öncelik | Kabul kriteri |
| --- | --- | --- | --- |
| F-06 | Çoklu kimlik profili (Bearer, Cookie, API key, Basic) | P0 | En az 4 profil aynı taramada kullanılabilir |
| F-07 | Anonim profil (kimliksiz istek) | P0 | Her endpoint en az bir kez kimliksiz denenir |
| F-08 | Ortam değişkeninden gizli bilgi okuma (`${env:TOKEN}`) | P0 | Token'lar config dosyasına düz metin yazılmadan kullanılabilir |
| F-09 | Login endpoint'i ile token yenileme (basit form/JSON login) | P2 | Token süresi dolunca otomatik yenilenir |

### 5.3 Kaynak sahipliği ve yetki matrisi

| ID | Özellik | Öncelik | Kabul kriteri |
| --- | --- | --- | --- |
| F-10 | Profil başına sahip olunan kaynak ID'leri (`owns: {orderId: [101]}`) | P0 | ID'ler path/body parametrelerine doğru yerleştirilir |
| F-11 | Otomatik ID hasadı: profilin kendi yanıtlarından ID toplama | P1 | `GET /me/orders` yanıtındaki ID'ler sahiplik havuzuna eklenir |
| F-12 | Yetki matrisi tanımı (rol × endpoint → izinli/yasak) | P1 | Matris ile gerçek sonuç çelişince bulgu üretilir |
| F-13 | Matris yoksa çıkarım modu (sahip vs. yabancı karşılaştırması) | P0 | Matris verilmeden de BOLA tespit edilir |

### 5.4 Test motorları

| ID | Özellik | Öncelik | Kabul kriteri |
| --- | --- | --- | --- |
| F-14 | BOLA / IDOR: B'nin oturumuyla A'nın kaynağına erişim | P0 | vuln-lab'daki tüm BOLA açıkları bulunur |
| F-15 | BFLA: düşük yetkili rolle admin fonksiyonu çağırma | P0 | `DELETE /admin/users/{id}` gibi uçlar user rolüyle denenir |
| F-16 | Kimlik doğrulamasız erişim | P0 | Korunması gereken endpoint anonim 2xx dönerse bulgu üretilir |
| F-17 | Mass assignment: body'ye `role`, `isAdmin`, `ownerId` gibi alan ekleme | P1 | Eklenen alan sonraki GET'te kalıcı görülürse bulgu |
| F-18 | HTTP method değiştirme (GET izinli, PUT/DELETE kontrolsüz mu?) | P1 | Spec'te olmayan method'lar güvenli modda denenir |
| F-19 | Hassas veri sızıntısı: yanıtta şema dışı alan (`passwordHash`) | P2 | Şemada olmayan, hassas desenli alanlar işaretlenir |
| F-20 | YAML kural şablonları ile özel test yazma | P1 | Kullanıcı yeni bir şablonla kod değiştirmeden test ekler |

### 5.5 Karşılaştırma ve doğrulama

| ID | Özellik | Öncelik | Kabul kriteri |
| --- | --- | --- | --- |
| F-21 | Durum kodu karşılaştırması | P0 | Sahip 200 / yabancı 403 beklenir; yabancı 200 alırsa aday bulgu |
| F-22 | Yapısal JSON diff + benzerlik skoru (0–1) | P0 | Dinamik alanlar (zaman damgası, istek ID) göz ardı edilir |
| F-23 | Sahiplik kanıtı: yabancı yanıtta sahibin ID/e-postası geçiyor mu? | P1 | Kanıt varsa güven seviyesi "yüksek" olur |
| F-24 | Güven seviyesi (düşük/orta/yüksek) ve önem (CVSS 3.1 tahmini) | P1 | Her bulguda iki alan da doludur |
| F-25 | Baseline ve susturma (`.authdiff-ignore`) | P1 | Susturulan bulgu sonraki taramada raporlanmaz |

### 5.6 Çalışma, güvenlik ve çıktı

| ID | Özellik | Öncelik | Kabul kriteri |
| --- | --- | --- | --- |
| F-26 | Zorunlu kapsam dosyası (izinli host listesi) | P0 | Kapsam dışı host'a tek istek bile gitmez; test ile kanıtlanır |
| F-27 | Hız limiti ve eşzamanlılık ayarı (varsayılan 5 istek/sn) | P0 | Ölçülen hız ayarın %10 üstüne çıkmaz |
| F-28 | Güvenli mod: yıkıcı method'lar (DELETE, PUT) varsayılan kapalı | P0 | `--allow-destructive` olmadan DELETE gönderilmez |
| F-29 | Kuru çalıştırma (`--dry-run`): istek planını göster, gönderme | P1 | Plan tablo olarak basılır, ağa çıkış olmaz |
| F-30 | Rapor çıktıları: SARIF 2.1.0, JSON, HTML, terminal tablosu | P0 (JSON, terminal) / P1 (SARIF, HTML) | SARIF, GitHub code scanning'e hatasız yüklenir |
| F-31 | Kanıt kaydı: her bulgu için istek/yanıt çifti (token'lar maskeli) | P0 | Raporda hiçbir token açık görünmez |
| F-32 | Çıkış kodları ve `--fail-on high` eşiği | P1 | Eşik üstü bulguda exit code 1 döner |
| F-33 | GitHub Action (`uses: <github-kullanici>/authdiff-action@v1`) | P1 | Örnek workflow vuln-lab'a karşı yeşil/kırmızı sonuç verir |
| F-34 | Docker imajı (distroless) | P2 | `docker run` ile kurulumsuz çalışır |

## 6. Fonksiyonel olmayan gereksinimler

| Alan | Gereksinim | Ölçüt |
| --- | --- | --- |
| Performans | 200 endpoint × 4 profil (800 istek) taraması hız limiti dışında ek yük getirmemeli | Yerel vuln-lab'da 20 istek/sn ile < 60 sn |
| Bellek | Büyük spec'lerde (5.000 endpoint) sabit bellek | < 200 MB RSS |
| Taşınabilirlik | Tek statik binary | Linux, macOS, Windows; amd64 + arm64 |
| Güvenilirlik | Geçici ağ hatalarında yeniden deneme (exponential backoff, en fazla 3) | Kesilen tarama `--resume` ile kaldığı yerden sürer (P2) |
| Determinizm | Aynı girdi aynı bulgu setini üretmeli | Bulgu ID'si = hash(kural, method, path, profil çifti) |
| Güvenlik | Araç kendi üzerinden sızıntı üretmemeli | Token maskeleme, log'da gizli veri yok, bağımlılıklar `govulncheck` ile temiz |
| Kullanılabilirlik | 5 dakikada ilk sonuç | `authdiff init` + vuln-lab ile README'deki akış |
| Test kapsamı | Çekirdek paketlerde yüksek kapsam | `internal/` için ≥ %80 satır kapsamı |
| Gözlemlenebilirlik | Yapılandırılmış log | `--log-format json`, `-v` ile istek düzeyinde ayrıntı |
| Dokümantasyon | Her kuralın açıklaması ve düzeltme önerisi | `docs/rules/*.md`, raporda bağlantılı |

## 7. Sistem mimarisi

authdiff, tek yönlü bir boru hattıdır: girdiler bir istek planına dönüşür, her istek güvenlik katmanlarından geçer, yanıtlar karşılaştırılır ve bulgular tek bir modelden raporlanır.

&#91;embedded content: authdiff mimarisi · girdiden rapora veri akışı\]

Kapsam ve hız kontrolü motorlarda değil transport katmanında olduğu için, yeni yazılan bir kural bu korumaları atlayamaz.

### 7.1 Karşılaştırma algoritması (BOLA örneği)

1. **Sahip isteği:** Kaynağın sahibi (alice) `GET /orders/101` çağırır. 2xx değilse test geçersizdir (kaynak yok ya da config hatalı) ve atlanır.
2. **Kararlılık ölçümü:** Aynı istek sahip adına ikinci kez atılır. İki yanıt arasında değişen alanlar (zaman damgası, istek ID) "dinamik" işaretlenip maskelenir.
3. **Saldırgan isteği:** Aynı roldeki başka profil (bob) aynı isteği atır.
4. **Anonim baseline:** İstek kimliksiz de atılır. Anonim de aynı veriyi alıyorsa kaynak public kabul edilir; BOLA bulgusu üretilmez (gerekirse NOAUTH kuralı değerlendirir).
5. **Karar:** Saldırgan 2xx alır ve maskelenmiş yapısal benzerlik eşiğin (varsayılan 0,85) üzerindeyse aday bulgu oluşur.
6. **Güven seviyesi:** Saldırganın yanıtında sahibin tanımlayıcıları (user ID, e-posta) geçiyorsa güven "yüksek", geçmiyorsa "orta" olur.

**Benzerlik skoru:** İki JSON ağacı yaprak yollarına (`$.items[0].price`) düzleştirilir. Skor = ortak yol ve eşit değer sayısı / toplam benzersiz yol sayısı (Jaccard benzeri). JSON olmayan yanıtlarda gövde hash'i ve uzunluk oranı kullanılır.

## 8. Kullanılacak teknolojiler

Ana dil Go'dur: güvenlik araçları ekosisteminin fiili standardı (nuclei, ffuf, httpx, subfinder), tek statik binary üretir ve goroutine'ler eşzamanlı HTTP için idealdir. Sürümler, başlarken `go get` ile güncel kararlı olana sabitlenmelidir.

### 8.1 Araç (authdiff)

| Katman | Teknoloji | Neden |
| --- | --- | --- |
| Dil | Go 1.23+ | Tek binary, hızlı derleme, güçlü standart kütüphane (`net/http`, `crypto/tls`) |
| CLI | `spf13/cobra` | Alt komutlar, otomatik yardım ve shell completion |
| Yapılandırma | `spf13/viper` veya `gopkg.in/yaml.v3` + kendi şema doğrulaması | YAML config, ortam değişkeni enjeksiyonu |
| OpenAPI | `getkin/kin-openapi` | 3.0/3.1 ayrıştırma, `$ref` çözümleme, örnek üretimi için şema erişimi |
| HTTP | `net/http` + özel `RoundTripper` zinciri | Kapsam kontrolü, hız limiti, kayıt, maskeleme katmanları middleware olarak |
| Hız limiti | `golang.org/x/time/rate` | Token bucket, profil ve host başına limit |
| Eşzamanlılık | `golang.org/x/sync/errgroup` + worker pool | Sınırlı paralellik ve hata yayılımı |
| JSON diff | `tidwall/gjson` (yol sorgusu) + kendi yapısal diff algoritması | Benzerlik skoru ve dinamik alan maskeleme projenin çekirdeği; hazır kütüphaneye bırakılmaz |
| Kural motoru | YAML şablonlar + `expr-lang/expr` | Kurallarda `status == 200 && body.ownerId != self.id` gibi koşullar |
| Log | `log/slog` (standart) | Yapılandırılmış, JSON/metin çıktı |
| Terminal çıktısı | `charmbracelet/lipgloss` | Renkli özet tabloları |
| HTML rapor | `html/template` + `embed` | Tek dosya, dış bağımlılıksız, otomatik escape (rapor XSS'e karşı güvenli) |
| SARIF | Kendi struct'ları (SARIF 2.1.0 şeması) | Bağımlılığı az tutmak; şema testiyle doğrulama |

### 8.2 Demo laboratuvarı (vuln-lab)

| Katman | Teknoloji | Neden |
| --- | --- | --- |
| API | Python 3.12 + FastAPI | OpenAPI dosyasını otomatik üretir; açık eklemek kısa sürer |
| Veritabanı | SQLite (SQLModel) | Kurulumsuz, her başlatmada seed verisiyle sıfırlanır |
| Kimlik | JWT (`PyJWT`), sabit test kullanıcıları | Token'lar başlangıçta yazılır, authdiff config'ine kopyalanır |
| Çalıştırma | Docker + Docker Compose | `docker compose up` ile tek komut |

### 8.3 Kalite, CI/CD ve dağıtım

| Amaç | Araç |
| --- | --- |
| Test | `testing`, `net/http/httptest`, `stretchr/testify`, golden dosyalar |
| Lint | `golangci-lint` (gosec, errcheck, staticcheck dahil) |
| Bağımlılık güvenliği | `govulncheck`, Dependabot |
| Statik analiz | GitHub CodeQL (Go) |
| CI | GitHub Actions (test, lint, e2e, release) |
| Sürüm | GoReleaser (çoklu platform binary, checksum, Docker imajı) |
| Tedarik zinciri | Cosign ile imzalı release, SBOM (Syft) — P2 |
| Dokümantasyon | Markdown + MkDocs Material (GitHub Pages) — P2 |

## 9. Dosya yapısı

Tek bir monorepo kullanılır: araç, demo laboratuvarı ve GitHub Action aynı depoda durur. Go'nun `internal/` kuralı sayesinde çekirdek paketler dışarıdan import edilemez; dışa açık API yalnızca `pkg/` altındadır.

```text
authdiff/
├── cmd/
│   └── authdiff/
│       └── main.go                 # giriş noktası, cobra root komutu
├── internal/
│   ├── cli/                        # alt komutlar: scan, init, inventory, rules, report
│   │   ├── root.go
│   │   ├── scan.go
│   │   ├── init.go
│   │   └── inventory.go
│   ├── config/                     # YAML yükleme, ${env:X} çözümleme, şema doğrulama
│   │   ├── config.go
│   │   └── validate.go
│   ├── spec/                       # OpenAPI ayrıştırma ve endpoint envanteri
│   │   ├── loader.go
│   │   ├── inventory.go
│   │   └── example.go              # şemadan örnek değer üretimi
│   ├── identity/                   # kimlik profilleri, auth enjeksiyonu, sahiplik havuzu
│   │   ├── profile.go
│   │   ├── auth.go
│   │   └── ownership.go
│   ├── planner/                    # test planı: endpoint × profil × kural → istek listesi
│   │   └── planner.go
│   ├── transport/                  # RoundTripper zinciri
│   │   ├── scope.go                # kapsam dışı host engeli
│   │   ├── ratelimit.go
│   │   ├── safemode.go             # yıkıcı method engeli
│   │   ├── recorder.go             # istek/yanıt kanıt kaydı
│   │   └── redact.go               # token maskeleme
│   ├── engine/                     # test motorları
│   │   ├── engine.go               # ortak arayüz: Check interface
│   │   ├── bola.go
│   │   ├── bfla.go
│   │   ├── noauth.go
│   │   ├── massassign.go
│   │   └── methodswap.go
│   ├── compare/                    # karşılaştırma motoru
│   │   ├── structural.go           # yapısal JSON diff
│   │   ├── similarity.go           # benzerlik skoru
│   │   ├── dynamic.go              # dinamik alan tespiti ve maskeleme
│   │   └── evidence.go             # sahiplik kanıtı arama
│   ├── rules/                      # YAML kural şablonu yükleyici + expr değerlendirici
│   │   ├── loader.go
│   │   └── eval.go
│   ├── finding/                    # bulgu modeli, ID üretimi, önem/güven, baseline
│   │   ├── finding.go
│   │   ├── severity.go
│   │   └── baseline.go
│   └── report/                     # çıktı üreticiler
│       ├── json.go
│       ├── sarif.go
│       ├── html.go
│       ├── terminal.go
│       └── templates/
│           └── report.html.tmpl
├── pkg/
│   └── authdiff/                   # kütüphane olarak kullanım için ince dış API
│       └── authdiff.go
├── rules/                          # yerleşik YAML kural şablonları
│   ├── bola-read.yaml
│   ├── bola-write.yaml
│   ├── bfla-admin.yaml
│   ├── noauth.yaml
│   └── mass-assignment.yaml
├── vuln-lab/                       # bilerek açıklı demo API
│   ├── app/
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── auth.py
│   │   ├── seed.py
│   │   └── routers/
│   │       ├── users.py
│   │       ├── orders.py
│   │       ├── invoices.py
│   │       └── admin.py
│   ├── VULNERABILITIES.md          # açık listesi = e2e testlerin beklenen sonucu
│   ├── Dockerfile
│   └── requirements.txt
├── action/                         # GitHub Action tanımı
│   └── action.yml
├── examples/
│   ├── authdiff.yaml               # vuln-lab için hazır config
│   └── workflow.yml                # örnek CI kullanımı
├── test/
│   ├── e2e/                        # vuln-lab'a karşı uçtan uca testler
│   │   └── vulnlab_test.go
│   └── testdata/                   # örnek spec'ler, golden rapor çıktıları
├── docs/
│   ├── architecture.md
│   ├── configuration.md
│   ├── writing-rules.md
│   ├── adr/                        # mimari karar kayıtları (ADR)
│   │   ├── 0001-go-secimi.md
│   │   └── 0002-karsilastirma-algoritmasi.md
│   └── rules/                      # her kuralın açıklaması ve düzeltme önerisi
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # test + lint + govulncheck
│   │   ├── e2e.yml                 # docker compose + e2e
│   │   ├── codeql.yml
│   │   └── release.yml             # GoReleaser
│   ├── ISSUE_TEMPLATE/
│   └── dependabot.yml
├── docker-compose.yml              # vuln-lab + authdiff demo
├── .golangci.yml
├── .goreleaser.yml
├── Makefile                        # make test, make lint, make lab, make demo
├── go.mod
├── README.md
├── SECURITY.md                     # sorumlu bildirim politikası
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE
```

**Bağımlılık kuralı:** `engine` → `compare`, `finding`, `transport` kullanır; `report` yalnızca `finding`'i tanır. `cli` dışında hiçbir paket `cobra`'yı import etmez. Bu ayrım, motorların CLI olmadan birim test edilmesini sağlar.

## 10. CLI, yapılandırma ve kural formatı

### 10.1 Komutlar

| Komut | Ne yapar |
| --- | --- |
| `authdiff init` | Boş `authdiff.yaml` şablonu ve `.authdiff-ignore` oluşturur |
| `authdiff inventory -c authdiff.yaml` | Spec'ten çıkarılan endpoint listesini gösterir, istek atmaz |
| `authdiff scan -c authdiff.yaml` | Taramayı çalıştırır |
| `authdiff scan --dry-run` | Üretilecek istek planını tablo olarak basar |
| `authdiff rules list` / `rules validate <dosya>` | Kuralları listeler / özel kuralı doğrular |
| `authdiff report -i results.json -f html` | Kayıtlı sonuçtan yeni formatta rapor üretir |
| `authdiff version` | Sürüm, commit ve build tarihi |

**Sık kullanılan bayraklar:** `--rate 5`, `--concurrency 4`, `--allow-destructive`, `--fail-on high`, `--format json,sarif,html`, `--output ./out`, `--include "/orders/**"`, `-v`.

### 10.2 Yapılandırma dosyası (`authdiff.yaml`)

```yaml
version: 1
target:
  baseUrl: http://localhost:8000
  spec: ./openapi.json          # dosya yolu veya URL

scope:                          # zorunlu: bu liste dışına istek gitmez
  allowHosts: ["localhost:8000"]
  acknowledgeAuthorization: true  # "bu sisteme test izni var" beyanı

safety:
  rate: 5                       # istek/saniye
  concurrency: 4
  allowDestructive: false       # DELETE/PUT/PATCH kapalı
  timeout: 10s

profiles:
  admin:
    role: admin
    auth: { type: bearer, token: "${env:ADMIN_TOKEN}" }
  alice:
    role: user
    auth: { type: bearer, token: "${env:ALICE_TOKEN}" }
    owns: { userId: [2], orderId: [101, 102], invoiceId: [9001] }
  bob:
    role: user
    auth: { type: bearer, token: "${env:BOB_TOKEN}" }
    owns: { userId: [3], orderId: [201] }
  anonymous:
    role: none
    auth: { type: none }

harvest:                        # P1: profilin kendi yanıtlarından ID toplama
  - endpoint: GET /me/orders
    extract: { orderId: "$.items[*].id" }

matrix:                         # P1: beklenen yetki matrisi
  "GET /admin/**":   { allow: [admin] }
  "GET /orders/{orderId}": { allow: [admin, owner] }
  "POST /orders":    { allow: [admin, user] }

compare:
  ignoreFields: ["$.requestId", "$..updatedAt"]
  similarityThreshold: 0.85

output:
  formats: [terminal, json, sarif, html]
  dir: ./authdiff-out
  failOn: high
```

### 10.3 Kural şablonu formatı (`rules/bola-read.yaml`)

```yaml
id: AD-BOLA-001
name: Başka kullanıcının kaynağını okuma (BOLA)
owasp: API1:2023
cwe: CWE-639
severity: high
applies:
  methods: [GET]
  pathHasParam: true            # {id} benzeri parametre içeren yollar
steps:
  - name: owner
    as: "{{owner}}"             # kaynağın sahibi profil
    use: "{{owner.owns}}"
  - name: attacker
    as: "{{other_user}}"        # aynı rolde başka profil
    use: "{{owner.owns}}"       # sahibin ID'leri ile
match: >
  owner.status == 200 &&
  attacker.status == 200 &&
  similarity(owner.body, attacker.body) >= cfg.similarityThreshold
confidence:
  high: evidence(attacker.body, owner.identifiers)
  medium: true
remediation: docs/rules/AD-BOLA-001.md
```

Yerleşik kurallar: `AD-BOLA-001` (okuma), `AD-BOLA-002` (yazma), `AD-BFLA-001` (admin fonksiyonu), `AD-NOAUTH-001` (kimliksiz erişim), `AD-MASS-001` (mass assignment), `AD-METHOD-001` (method değiştirme).

## 11. Raporlama ve çıktı formatları

Her bulgu tek bir veri modelinden türetilir; tüm formatlar bu modelin farklı görünümleridir.

### 11.1 Bulgu veri modeli

```go
type Finding struct {
    ID          string     // sha256(kural|method|path|kurban|saldırgan)[:12]
    RuleID      string     // AD-BOLA-001
    Title       string
    OWASP       string     // API1:2023
    CWE         string     // CWE-639
    Severity    Severity   // critical | high | medium | low | info
    CVSS        float64    // tahmini 3.1 baz skoru
    Confidence  Confidence // high | medium | low
    Method      string
    Path        string     // /orders/{orderId}
    Victim      string     // alice
    Attacker    string     // bob
    Similarity  float64    // 0–1
    Evidence    []Exchange // maskelenmiş istek/yanıt çiftleri
    Remediation string
    Suppressed  bool       // .authdiff-ignore ile susturuldu mu
}
```

### 11.2 Çıktılar

| Format | Kime | İçerik |
| --- | --- | --- |
| Terminal | Aracı çalıştıran kişi | Önem sıralı özet tablo, toplam istek, süre |
| JSON | Otomasyon, başka araçlar | Tam bulgu listesi + tarama meta verisi; `report` komutunun girdisi |
| SARIF 2.1.0 | GitHub code scanning | `rules[]` = kural tanımları, `results[]` = bulgular; konum olarak spec dosyasındaki path satırı |
| HTML | Yönetici, rapor okuyucu | Tek dosya; özet kartı, endpoint × profil yetki ısı haritası, bulgu başına kanıt ve düzeltme önerisi |

**Endpoint × profil ısı haritası**, HTML raporun imza özelliğidir: satırlar endpoint, sütunlar profil, hücreler "izinli / reddedildi / beklenmedik erişim" durumunu gösterir. Yetki matrisinin gerçekte nasıl davrandığı tek bakışta görülür.

**Maskeleme kuralı:** `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key` başlıkları ve yapılandırmadaki tüm token değerleri her çıktıda `****` + son 4 karakter olarak yazılır.

## 12. Demo laboratuvarı (vuln-lab)

vuln-lab, bilerek açıklı bırakılmış küçük bir e-ticaret API'sidir. İki amacı vardır: aracı herkesin tek komutla denemesi ve uçtan uca testlerde "beklenen bulgu listesi" olarak kullanılması. Yalnızca `localhost`'a bağlanır ve README'de üretimde çalıştırılmaması uyarısı bulunur.

**Seed verisi:** admin (id 1), alice (id 2), bob (id 3); her kullanıcının 2 siparişi ve 1 faturası.

| # | Endpoint | Yerleştirilen açık | Beklenen kural |
| --- | --- | --- | --- |
| V1 | `GET /orders/{orderId}` | Sahiplik kontrolü yok | AD-BOLA-001 |
| V2 | `PATCH /orders/{orderId}` | Yazmada sahiplik kontrolü yok | AD-BOLA-002 |
| V3 | `GET /invoices/{invoiceId}/pdf` | Ardışık ID + kontrol yok | AD-BOLA-001 |
| V4 | `GET /admin/users` | Rol kontrolü yok, yalnızca giriş kontrolü var | AD-BFLA-001 |
| V5 | `DELETE /admin/users/{userId}` | Rol kontrolü yok (güvenli modda atlanır) | AD-BFLA-001 |
| V6 | `GET /users/{userId}/profile` | Kimlik doğrulaması unutulmuş | AD-NOAUTH-001 |
| V7 | `PUT /users/me` | Body'den `role` alanı kabul ediliyor | AD-MASS-001 |
| V8 | `GET /users/{userId}` | Yanıtta `passwordHash` sızıyor | F-19 (P2) |

**Negatif kontroller (yanlış pozitif tuzakları):** Doğru korunmuş endpoint'ler de bulunur. `GET /orders/{orderId}/status` yabancıya 404 döner. `GET /products/{id}` herkese açıktır ve bulgu üretmemelidir. `GET /me` her kullanıcıya farklı ama geçerli veri döner. Araç bunlarda sessiz kalmalıdır.

`VULNERABILITIES.md` dosyası bu tablonun makine okunur karşılığını (YAML front-matter) içerir; e2e testi bulgu setini bu listeyle karşılaştırır.

## 13. Etik kullanım ve aracın kendi güvenliği

authdiff yalnızca sahibi olunan veya yazılı test izni alınmış sistemlerde kullanılmak üzere tasarlanır. Türkiye'de izinsiz sisteme erişim TCK 243–244 kapsamında suçtur; bu yüzden güvenlik varsayılanları "kapalı" başlar.

**Araç içi korumalar:**

- Kapsam dosyası ve `acknowledgeAuthorization: true` beyanı olmadan tarama başlamaz.
- `allowHosts` dışına yönlendirme (redirect) dahil hiçbir istek gitmez; redirect'ler kapsam kontrolünden geçer.
- Varsayılan 5 istek/sn ve yıkıcı method'lar kapalı.
- `User-Agent: authdiff/<sürüm> (+repo-url)` ile kendini tanıtır; hedef sistem sahibi trafiği tanıyabilir.
- Kaba kuvvet, DoS veya kimlik bilgisi tahmini özelliği bilinçli olarak yoktur.

**Aracın kendi güvenliği:**

- Token'lar diske, log'a ve rapora açık yazılmaz (maskeleme testleri CI'da zorunlu).
- HTML rapor, hedeften gelen yanıtları gösterdiği için XSS riski taşır. `html/template` otomatik escape kullanılır ve rapora CSP meta etiketi eklenir.
- TLS doğrulaması varsayılan açıktır; `--insecure` yalnızca açık bayrakla.
- Yanıt boyutu sınırlıdır (varsayılan 5 MB) ve kural ifadeleri sandbox'lı `expr` ile değerlendirilir; kötü niyetli spec veya yanıt aracı çökertmemeli.
- `SECURITY.md` ile sorumlu bildirim kanalı tanımlanır; release'ler checksum'lı (P2: imzalı).

## 14. Test stratejisi ve CI/CD

Güvenlik aracının değeri güvenilirliğindedir; bu yüzden her kural hem "bulmalı" hem "bulmamalı" testiyle gelir.

| Seviye | Ne test edilir | Nasıl |
| --- | --- | --- |
| Birim | `compare` (diff, benzerlik, dinamik alan), `spec` (envanter), `config` (doğrulama), `finding` (ID kararlılığı) | Tablo tabanlı testler, `testdata/` girdileri |
| Güvenlik korumaları | Kapsam dışı host, redirect, güvenli mod, hız limiti, maskeleme | `httptest` sunucusu; kapsam dışı istek gelirse test başarısız |
| Motor | Her kural için açıklı ve düzgün korunan sahte endpoint | `httptest` ile mini API'ler |
| Golden | JSON, SARIF ve HTML çıktıları | `-update` bayrağıyla güncellenen golden dosyalar |
| Uçtan uca | vuln-lab'a karşı tam tarama | Bulgu seti == `VULNERABILITIES.md`; negatif kontrollerde bulgu yok |
| Fuzz | Spec ve yanıt ayrıştırıcılar | Go native fuzzing (`go test -fuzz`) — P2 |

**CI hatları (GitHub Actions):**

1. `ci.yml` — her push/PR: `go test -race ./...`, `golangci-lint`, `govulncheck`, kapsam raporu.
2. `e2e.yml` — her PR: `docker compose up -d vuln-lab`, `authdiff scan`, beklenen bulgu karşılaştırması, SARIF yüklemesi.
3. `codeql.yml` — haftalık ve PR'da Go için CodeQL.
4. `release.yml` — `v*` etiketi: GoReleaser ile binary'ler, checksum, Docker imajı, CHANGELOG.

## 15. Yol haritası ve kilometre taşları

Proje 10 haftada üç sürümle teslim edilir; her kapı, bir önceki fazın kabul kriterleri sağlanmadan geçilmez.

&#91;embedded content: yol haritası · 5 faz, 3 sürüm kapısı\]

v0.1 tek başına da gösterilebilir bir üründür: staj başvurusu erken gelirse 4. hafta sonundaki repo yeterli bir referanstır.

## 16. Başarı metrikleri

| Metrik | Hedef (v1.0) | Nasıl ölçülür |
| --- | --- | --- |
| Tespit oranı (recall) | vuln-lab P0/P1 açıklarının ≥ %90'ı | e2e testi |
| Yanlış pozitif oranı | < %10 | Negatif kontroller + 2 açık kaynak hedef |
| İkinci hedefte doğrulama | OWASP crAPI veya VAmPI üzerinde en az 3 gerçek bulgu | Yerel kurulumda tarama, sonuçlar `docs/benchmarks.md`'de |
| İlk sonuca süre | < 5 dakika | README akışını sıfırdan izleyen bir arkadaş |
| Kod kalitesi | `internal/` kapsamı ≥ %80, lint uyarısı 0 | CI rozetleri |
| Görünürlük | README demo GIF'i, 1 teknik blog yazısı, 1 kısa demo videosu | Yayınlanmış bağlantılar |
| Topluluk (isteğe bağlı) | ≥ 25 GitHub yıldızı, ≥ 1 dış katkı | GitHub istatistikleri |

## 17. Riskler, açık sorular ve sözlük

### 17.1 Riskler

| Risk | Etki | Azaltma |
| --- | --- | --- |
| Yüksek yanlış pozitif (public kaynaklar BOLA gibi görünür) | Araç güvenilmez görünür | Anonim baseline: anonim de aynı veriyi alıyorsa kaynak public sayılır; sahiplik kanıtı ile güven seviyesi |
| Gerçek API'lerde zayıf/eksik OpenAPI | Envanter eksik kalır | HAR içe aktarma (P2), `--include` ile elle endpoint ekleme |
| Geçerli istek gövdesi üretememe (karmaşık şemalar) | POST/PUT testleri başarısız | Şema `example` alanlarını öncelemek, config'de endpoint başına örnek body |
| Durum değiştiren testlerin veriyi bozması | Test ortamı kirlenir | Güvenli mod varsayılan, vuln-lab her başlatmada sıfırlanır, yazı testlerinde geri alma (P2) |
| Kapsam kaydırma (scope creep) | MVP gecikir | P2'ler v1.0 sonrasına; haftalık kilometre taşı kontrolü |
| Ders/sınav dönemiyle çakışma | Takvim kayar | 2 haftalık tampon; v0.1 tek başına da gösterilebilir bir sürüm |
| Kötüye kullanım algısı | İtibar | Etik bölümü, varsayılan korumalar, kendini tanıtan User-Agent |

### 17.2 Açık sorular

- [ ] Araç adı kesinleşsin mi (authdiff / alternatif)? GitHub ve Go modül adı müsait mi?
- [ ] v1.0'da HTML rapor mı, yoksa SARIF + JSON yeterli mi?
- [ ] İkinci doğrulama hedefi olarak crAPI mi VAmPI mi kullanılacak?
- [ ] Blog yazısı Türkçe mi, İngilizce mi, ikisi de mi?
- [ ] README İngilizce yazılıp Türkçe çevirisi eklenecek mi?

### 17.3 Sözlük

| Terim | Açıklama |
| --- | --- |
| BOLA / IDOR | Broken Object Level Authorization: kullanıcının ID değiştirerek başkasına ait nesneye erişmesi |
| BFLA | Broken Function Level Authorization: düşük yetkili rolün yetkili fonksiyonu çağırabilmesi |
| Mass assignment | İstemcinin gönderdiği fazladan alanların (`role`) doğrudan modele yazılması |
| OpenAPI | REST API'lerin makine okunur tanım formatı (eski adı Swagger) |
| SARIF | Static Analysis Results Interchange Format: güvenlik bulguları için standart JSON formatı |
| Profil | authdiff'te bir kimliğin (rol + token + sahip olduğu kaynaklar) tanımı |
| Yetki matrisi | Hangi rolün hangi endpoint'e erişebilmesi gerektiğinin tablosu |
| Kurban / saldırgan | Bir testte kaynağın sahibi profil / ona erişmeye çalışan profil |
