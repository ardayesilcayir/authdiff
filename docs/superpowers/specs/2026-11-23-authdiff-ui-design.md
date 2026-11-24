# authdiff UI — Tasarım Dokümanı

Tarih: 2026-11-23 · Durum: taslak (onay bekliyor; inşacı kontrolü yapıldı)

## 1. Amaç ve neden

authdiff v1.0 yalnızca komut satırından kullanılıyor. Kullanmak için YAML config yazmak, token'ları ortam değişkenine yüklemek, terminal çıktısını okumak ve HTML raporu ayrıca açmak gerekiyor. Proje sahibi aracı elle test ederken **akışın her adımında** zorlandı. Amaç, aynı motoru kullanan ve hiçbir adımda terminale, YAML'a ya da ortam değişkenine dönmeyi gerektirmeyen, uçtan uca bir **yerel web arayüzü** eklemek.

İki kullanıcı tipi var:
- **Tanıtım / deneme:** projeye GitHub'dan ya da görüşmede bakan kişi. Sıfır ayarla, dakikalar içinde sonuç görmeli. Bu, projenin portföy amacına (PRD §2) hizmet ediyor.
- **Gerçek kullanım:** geliştirici ya da pentester, kendi API'sini (staging, izinli bug bounty kapsamı) test ediyor.

Karar (Claude'un çağrısı, kullanıcı onayladı): demo ön kapı olacak, kendi API'ni test etme sihirbazı ana işlev olacak.

## 2. Hedefler

1. `authdiff ui` komutu: aynı binary, ek kurulum yok. Tarayıcıda `127.0.0.1` üzerinde açılır.
2. Uçtan uca akış: hedef → endpoint'ler → profiller → güvenlik ayarları → plan (dry-run) → canlı tarama → sonuçlar → yanlış pozitif susturma → dışa aktarma.
3. Demo modu: vuln-lab çalışıyorsa tek tıkla hazır ayarlarla tarama.
4. Projeler: yapılan ayarlar kaydedilip daha sonra yeniden açılabilir; geçmiş taramalar listelenir.
5. Arayüz CLI ile birebir uyumlu: arayüzde hazırlanan proje `authdiff.yaml` olarak indirilip CI'da `authdiff scan` ile aynı sonucu verir.
6. Arayüz Türkçe ve İngilizce; varsayılan dil tarayıcının `Accept-Language` değerinden seçilir, ekrandan değiştirilebilir.

## 3. Kapsam dışı

- İnternette barındırma, çok kullanıcılı kullanım, uzaktan erişim (arayüz yalnızca loopback'e bağlanır).
- Arayüzden Docker/Python süreçleri başlatmak (vuln-lab'ı başlatıp durdurmak). Arayüz yalnızca lab'ın çalışıp çalışmadığını kontrol eder ve başlatma komutunu gösterir.
- OAuth/SSO gibi otomatik oturum açma akışları (PRD §3 ile aynı; token'ı kullanıcı verir).
- Arayüzde YAML kural şablonu düzenleyici (özel kurallar dosyadan okunmaya devam eder).
- Telefon ekranına özel düzen. Hedef dizüstü/masaüstü genişliği; dar ekranda tablolar kendi içinde kaydırılır, sayfa yatay kaymaz.
- Node/npm tabanlı ön yüz derlemesi.

## 4. Anti-hedefler (çalışsa bile başarısızlık sayılanlar)

- Arayüzün CLI'daki güvenlik korumalarından birini zayıflatması: kapsam onayı (`acknowledgeAuthorization`) olmadan tarama, allowHosts dışına istek, yıkıcı modun sessizce açılması.
- Token'ların diske düz metin yazılması, log'a ya da tarayıcı depolamasına (localStorage) düşmesi.
- Aynı ağdaki başka bir makinenin ya da tarayıcıda açık başka bir sitenin arayüzü kullanabilmesi (CSRF, DNS rebinding).
- Hedef API'den gelen yanıtların arayüzde script çalıştırabilmesi (XSS).
- Motorun ikinci bir kopyasının yazılması: arayüz CLI ile aynı kod yolunu (`pkg/authdiff` → `engine`) kullanmalı, sonuçlar CLI ile aynı olmalı.

## 5. Kısıtlar

- Go, tek statik binary; ön yüz varlıkları `embed` ile gömülür. Yeni Go bağımlılığı eklenmez (standart kütüphane `net/http`, `html/template` yeterli). Ön yüzde harici CDN/kütüphane yok; JS el yazımı ve küçük.
- Bağımlılık kuralı (PRD §9): `cobra` yalnızca `internal/cli`'da. Yeni paket `internal/ui` yalnızca `pkg/authdiff`, `internal/config`, `internal/report`, `internal/finding`, `internal/spec` (envanter tipleri) kullanır; `internal/cli` `internal/ui`'ı çağırır.
- Mevcut CI kuralları geçerli: `internal/` kapsamı ≥ %80, golangci-lint temiz, govulncheck temiz, e2e oracle (recall 1.00 / FP 0.00) bozulmaz.
- Windows, macOS, Linux'ta çalışmalı (tarayıcı açma komutları platforma göre).

## 6. Yaklaşımlar

| | Yaklaşım | Artı | Eksi |
|---|---|---|---|
| **A (seçildi)** | Go `net/http` sunucusu + `html/template` ile sunucu tarafında çizilen sayfalar + küçük el yazımı JS (canlı ilerleme için Server-Sent Events) | Tek binary, yeni bağımlılık yok, CI/release değişmez, rapordaki ısı haritası şablonu yeniden kullanılır, saldırı yüzeyi küçük | Çok dinamik etkileşimler (ör. matris tablosu düzenleme) daha zahmetli |
| B | Go API + React/Vite SPA, derlenip gömülür | En zengin etkileşim | Node derleme adımı, yüzlerce npm bağımlılığı, tedarik zinciri riski, bir güvenlik aracı için kötü görüntü |
| C | Terminal arayüzü (bubbletea) | Kurulum yok | Kullanıcının asıl sorunu olan "her adımda zorlanma"yı çözmez; YAML/token girişi yine zor |

Elenenler: masaüstü uygulaması (Wails/Electron: platform başına paketleme), barındırılan web sitesi (token'ları sunucuya taşır, aracın güvenlik ilkesine ters).

Kullanıcı nasıl yapılacağı kararını Claude'a bıraktı; A seçildi.

## 7. Komut ve sunucu

```
authdiff ui [--port 7465] [--no-open] [--projects-dir <dizin>]
```

- Yalnızca `127.0.0.1:<port>` dinlenir; port meşgulse bir sonraki boş port denenir (en fazla 10). Loopback dışı adres kabul eden bir bayrak yoktur.
- Başlangıçta 32 baytlık rastgele bir **oturum anahtarı** üretilir. Terminale `http://127.0.0.1:7465/?key=<anahtar>` yazılır ve (`--no-open` yoksa) varsayılan tarayıcı bu adresle açılır. İlk istekte anahtar doğrulanır, `HttpOnly; SameSite=Strict; Path=/` çerez olarak yazılır ve anahtarsız adrese yönlendirilir.
- Varsayılan proje dizini: kullanıcının config dizini altında `authdiff/projects` (`os.UserConfigDir()`). `--projects-dir` ile değiştirilebilir.
- Ctrl-C / SIGTERM: çalışan tarama iptal edilir (kısmi sonuç kaydedilir), sunucu kapanır.

### Sunucu güvenlik kuralları (hepsi test edilir)

1. Her istekte geçerli oturum çerezi zorunlu; yoksa 401 ve "terminaldeki bağlantıyı kullanın" sayfası.
2. `Host` başlığı yalnızca `127.0.0.1:<port>` ya da `localhost:<port>` olabilir; değilse 421 (DNS rebinding koruması).
3. Durum değiştiren her istek `POST`; `Origin` (yoksa `Referer`) kendi adresimiz olmalı ve formda/başlıkta oturuma bağlı bir CSRF token'ı bulunmalı.
4. Tüm yanıtlarda `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` (`no-referrer` değil: o politikada tarayıcı form POST'larında `Origin: null` gönderir ve Referer göndermez, Origin kontrolü her formu reddeder; `same-origin` başka origin'lere yine hiçbir şey göndermez), `Cache-Control: no-store`.
5. Hedef API'den gelen her içerik (yanıt gövdeleri, başlıklar, spec'teki path/operationId) yalnızca `html/template` otomatik kaçışıyla basılır; JS'e veri yalnızca JSON uç noktalarıyla ve `textContent` üzerinden aktarılır (`innerHTML` yok).
6. Yüklenen spec dosyası en fazla 10 MiB (motorla aynı sınır).
7. Aynı anda tek tarama; ikinci başlatma isteği reddedilir.

## 8. Ekranlar ve akış

```
Ana sayfa ─┬─ Demo lab ile dene ──────────────▶ Plan ▶ Tarama ▶ Sonuçlar
           ├─ Kendi API'mi test et ─▶ 1 Hedef ▶ 2 Endpoint'ler ▶ 3 Profiller ▶ 4 Ayarlar ▶ Plan ▶ Tarama ▶ Sonuçlar
           └─ Projeler (liste) ─▶ proje ▶ ayarları düzenle / yeniden tara / geçmiş sonuçlar
```

Sihirbaz adımları arasında geri dönülebilir; her adım projeyi otomatik kaydeder (token'lar hariç, bkz. §9).

### 8.1 Ana sayfa
```
┌─ authdiff ─────────────────────────────── [TR | EN] ─┐
│  ▶ Demo lab ile dene      ● vuln-lab çalışıyor        │
│  ＋ Kendi API'mi test et                              │
│  Son projeler: vuln-lab-demo · staging-api · ...      │
└───────────────────────────────────────────────────────┘
```
- Lab kontrolü: `http://127.0.0.1:8000/openapi.json` 2 sn zaman aşımıyla; erişilemezse "çalışmıyor" ve kopyalanabilir başlatma komutları (Docker ve Python).
- Etik notu (kısa, kalıcı alt bilgi): yalnızca izinli sistemler; TCK 243–244 bağlantısı.

### 8.2 Demo
- Binary'ye gömülü `examples/authdiff.yaml` ve `examples/vuln-lab.env` ile "vuln-lab-demo" projesi oluşturulur (varsa açılır). Lab token'ları sahte ve depoda zaten herkese açık; demo projesinde bu token'ların diske yazılmasına izin verilir (projede `demo: true` işareti).
- Varsayılan güvenli mod. "Yazma açıklarını da bul" anahtarı yıkıcı modu açar ve "lab verisi değişir, ardından lab'ı yeniden başlatın" uyarısı gösterir.
- Doğrudan Plan ekranına gider.

### 8.3 Sihirbaz 1 — Hedef
- Base URL alanı.
- Spec: dosya yükle **ya da** URL gir. URL ise indirme, motorun kapsam zincirinden geçer (önce allowHosts belirlenir).
- allowHosts: base URL'den otomatik türetilir (host:port), düzenlenebilir liste.
- **Kapsam onayı** onay kutusu, açıklamasıyla: "Bu sisteme test izni var (sahibiyim ya da yazılı iznim var)". İşaretlenmeden ileri gidilmez. Bu `acknowledgeAuthorization` değerine yazılır.

### 8.4 Sihirbaz 2 — Endpoint'ler
- "Endpoint'leri yükle" envanteri getirir: tablo (method, path, operationId, secured, parametreler, etiketler).
- Satır başı onay kutuları ve etiket filtreleri → config'teki `filter.include/exclude/tags`'e çevrilir. Varsayılan: hepsi seçili.

### 8.5 Sihirbaz 3 — Profiller
- Kart başına: ad, rol (`admin` / `user` / `none`), kimlik türü (bearer, cookie, apikey, basic, none) ve türe göre alanlar (token/parola alanları `type=password`).
- Sahip olunan ID'ler: envanterdeki path parametrelerinden öneri listesi (`orderId`, `userId`...), her biri için virgülle ID girişi.
- Tanımlayıcılar (e-posta vb.).
- Hazır şablon düğmesi: "admin + 2 kullanıcı + anonim" dört kartı tek seferde ekler.
- İsteğe bağlı ID hasadı: yıkıcı olmayan bir GET endpoint seç + JSONPath (örn. `$.items[*].id`) + hangi parametreye yazılacağı.
- Doğrulama: en az bir profil; en az iki aynı rollü kullanıcı yoksa "BOLA testleri için aynı rolde iki kullanıcı gerekir" uyarısı (engel değil).

### 8.6 Sihirbaz 4 — Ayarlar
- Hız (istek/sn, varsayılan 5), eşzamanlılık (4), zaman aşımı.
- **Yıkıcı mod** anahtarı: varsayılan kapalı. Açılınca kırmızı onay penceresi: plandaki yıkıcı istek sayısı ve örnekleri; "gerçek veri silinebilir/değişebilir" metni; kullanıcı "anladım" yazmadan açılmaz.
- Gelişmiş (katlanır): benzerlik eşiği, yok sayılan alanlar, proxy, TLS doğrulamasını kapat (kırmızı uyarılı), yetki matrisi düzenleyici (satır: endpoint deseni, sütun: rol/profil adları + `owner`, hücre: izinli onay kutusu).

### 8.7 Plan (dry-run)
- `PlanContext` sonucu: kural başına gruplanmış tablo (kural, adım, profil, method, path, yıkıcı mı), toplam istek sayısı, tahmini süre (istek sayısı / hız).
- Yıkıcı satırlar kırmızı etiketli. "Taramayı başlat" düğmesi.

### 8.8 Tarama (canlı)
```
Taranıyor · Faz 2/4 (PUT/PATCH) ███████░░░░ 96 / 168 istek
Bulgular: 9  (HIGH 8 · MEDIUM 1)       engellenen: 0 · hata: 0
[Durdur]
  14:02:11  HIGH  AD-BOLA-001  GET /orders/{orderId}  bob→alice
  ...
```
- İlerleme Server-Sent Events ile akar (`/api/runs/<id>/events`): faz değişimi, istek sayacı, yeni bulgu, bitiş.
- "Durdur" iptal eder; kısmi sonuç kaydedilir ve Sonuçlar'a gidilir (CLI'daki kısmi rapor davranışıyla aynı).

### 8.9 Sonuçlar
- Özet kartları (önem başına sayı, istek, engellenen, hata, süre) ve `Notes` (ör. TLS kapalı, hiç yanıt alınamadı).
- Isı haritası (endpoint × profil), mevcut rapor şablonundaki görünümle aynı.
- Bulgu listesi: önem/kural filtresi; satıra tıklayınca ayrıntı: açıklama, benzerlik, güven, düzeltme önerisi (docs/rules bağlantısı), kanıt istek/yanıtları (maskeli).
- **Yanlış pozitif olarak işaretle:** gerekçe ister, projenin `.authdiff-ignore` dosyasına `<id> # gerekçe` ekler; bulgu "susturuldu" bölümüne geçer (sonraki taramalarda da susturulur).
- Dışa aktar: `results.json`, `results.sarif`, `report.html` indirme düğmeleri ve CI için zip paketi (bkz. §13 karar 2).
- Geçmiş: aynı projenin önceki taramaları, tarih ve bulgu sayısıyla; iki taramayı karşılaştırma kapsam dışı.

## 9. Projeler ve token'lar (veri modeli)

Proje dizini: `<projects-dir>/<proje-adı>/`
```
project.json        # arayüz meta verisi: ad, oluşturulma, demo bayrağı, sihirbaz durumu
authdiff.yaml       # motorun okuduğu config; token alanları ${env:AUTHDIFF_<PROFİL>_TOKEN} vb.
spec.<yaml|json>    # yüklenen spec dosyası (URL verildiyse saklanmaz, URL config'te kalır)
.authdiff-ignore    # susturulan bulgular
runs/<zaman>/results.json, report.html
```
- Dosya izinleri: dizinler 0700, dosyalar 0600 (motorun rapor yazma kuralıyla aynı).
- **Token'lar diske yazılmaz** (demo projesi hariç). Config'te yer tutucu kalır; asıl değerler sunucu belleğinde, oturum boyunca tutulur. Sunucu yeniden başlarsa proje açılırken eksik token'lar istenir; ortam değişkeninde varsa oradan okunur ve "ortamdan alındı" diye gösterilir.
- Tarayıcıya token geri gönderilmez: form alanları "kayıtlı (•••• son 4)" gösterir, boş bırakılırsa mevcut değer korunur.
- Proje adı yalnızca `[a-z0-9-]` (path traversal yok).

## 10. Motor ve API değişiklikleri (pkg/authdiff)

Arayüz CLI ile aynı kod yolunu kullanır; bunun için küçük eklemeler gerekir:
1. **Bellekteki config ile çalışma:** `ScanOptions`'a `Config *config.Config` (ConfigPath yerine geçer; ikisi birden verilirse hata) ve `BaseDir string` (göreli spec/kural yollarını çözmek için). Aynısı `PlanContext` ve `LoadInventory` için. Mevcut dosya tabanlı davranış ve imzalar korunur.
2. **Token sağlama:** arayüz bellekteki token'ları config'e yerleştirip `config.Validate` çağırır; `${env:...}` genişletmesi yalnızca dosyadan okumada çalışmaya devam eder.
3. **İlerleme kancası:** `ScanOptions.OnProgress func(authdiff.Progress)`; `Progress{Phase int, PhaseName string, Sent, Planned, Blocked, Errors int, Finding *Finding /* yeni bulgu olduğunda */, Done bool}`. Motor her istek sonrası ve faz değişiminde çağırır; `Planned` dry-run plan sayısından gelir. Kanca motor goroutine'lerinden çağrılır; eşzamanlı güvenli olmalı ve tarama hızını etkilememeli (kanalı dolu ise olay düşürülebilir, sayaçlar kümülatif olduğu için kayıp sorun değil).
4. **Bulgunun anlık bildirimi:** bulgular şu an tarama sonunda birleştiriliyor; canlı ekranda gösterim için check sonuçlandığında bulgu olayı yayınlanır (son sonuç yine birleştirilmiş/sıralı listedir).
5. `config` paketine YAML'a yazma (`Marshal`) eklenir: arayüzün kaydettiği `authdiff.yaml` CLI ile `config.Load` üzerinden aynen okunabilmeli (gidiş-dönüş testi).

## 11. Test ve doğrulama

- `internal/ui` handler testleri (`httptest`): her ekranın 200 döndüğü, form doğrulamaları, proje kaydetme/yükleme, token'ların diske yazılmadığı (dosyalarda token değeri aranır), ignore ekleme.
- Güvenlik testleri: çerezsiz istek 401; yanlış `Host` 421; yabancı `Origin` veya eksik CSRF ile POST 403; CSP ve diğer başlıklar her yanıtta; hedef yanıtındaki `<script>` kaçışlı basılıyor; loopback dışı bağlanma imkânı yok; proje adında `../` reddediliyor.
- `pkg/authdiff` için bellek config'i ve ilerleme kancası testleri (dosya tabanlı ile aynı sonuç; kanca sayaçları plan sayısıyla tutarlı).
- Uçtan uca: vuln-lab'a karşı arayüz API'si üzerinden demo taraması → bulunan (kural, method, path) kümesi CLI e2e oracle'ı ile aynı (`-tags e2e`).
- Koordinatör, bitişte uygulamayı tarayıcıda açıp demo akışını baştan sona dener ve ekran görüntüsü alır.
- Kapsam ≥ %80, golangci-lint ve govulncheck temiz.

## 12. Dokümantasyon

- README (TR + EN): "Arayüz ile kullanım" bölümü, ekran görüntüsü/GIF.
- `docs/ui.md`: güvenlik modeli (loopback, oturum anahtarı, token'ların saklanmaması), proje dizini, demo modu.
- CHANGELOG `[Unreleased]`: Added — `authdiff ui`. Sürüm v1.1.0 olarak çıkar.

## 13. Kararlar ve inşacıya kalanlar

Claude'un çağrısı olarak verilen kararlar: demo ön kapı + sihirbaz ana işlev; yaklaşım A; lab süreç yönetimi yok; arayüz TR/EN; token'lar diske yazılmaz (demo hariç); port 7465; proje dizini kullanıcı config dizini altında; yıkıcı mod "anladım" yazılarak açılır; tek eşzamanlı tarama.

### İnşacı kontrolünden sonra verilen kararlar (Claude'un çağrısı)

1. **Yıkıcı mod tek kapıdan açılır.** Demo dahil her yerde aynı sunucu tarafı kontrol: "anladım" yazılmadan `allowDestructive` true olamaz. Demo penceresi ek olarak "lab verisi değişir, ardından lab'ı yeniden başlatın" uyarısını gösterir. Güvenlik testi istisnasız her proje için yazılır.
2. **Dışa aktarma bir zip paketidir:** `authdiff.yaml` + spec dosyası (yüklendiyse; config'teki yol paket içi göreli `spec.<ext>`) + `.authdiff-ignore` + `.env.example` (gereken değişken adları, değersiz). README'de "zip'i aç, değişkenleri ayarla, `authdiff scan -c authdiff.yaml`" yazar. Ortam değişkeni adı: `AUTHDIFF_<PROFİL>_<ALAN>`; profil adı büyük harfe çevrilir, `[^A-Z0-9]` karakterleri `_` olur (`staging-admin` → `AUTHDIFF_STAGING_ADMIN_TOKEN`; basic için `_USERNAME`/`_PASSWORD`). Demo projesi istisna: örnek config'teki adlar (`ADMIN_TOKEN`...) korunur ve dışa aktarımda sahte lab token'ları `vuln-lab.env` olarak pakete eklenir.
3. **Projenin doğruluk kaynağı `project.json`'dır.** Sihirbaz durumu (yarım ayarlar dahil) orada tutulur; `config` paketine yeni bir ayrıştırma API'si gerekmez. `authdiff.yaml` yalnızca config `Validate`'ten geçtiğinde (token'lar yer tutucuyla) üretilir ve dışa aktarma/CLI içindir. Proje dizinindeki `authdiff.yaml`'ı elle düzenlemek arayüze yansımaz; bu `docs/ui.md`'de yazılır. Var olan bir `authdiff.yaml`'ı arayüze içe aktarma kapsam dışıdır (v1.1). Tarama, `project.json`'dan bellekte kurulan `*config.Config` ve bellekteki token'larla `ScanOptions.Config` üzerinden yapılır.
4. **Canlı sayaçlar ve bulgular geçicidir, son sonuç esastır.** `Planned` dry-run plan sayısından gelen bir **tahmindir**: hasat istekleri, hasattan gelen ek ID'ler ve yeniden denemeler sayılmaz. İlerleme çubuğu `min(Sent/Planned, 99%)` gösterir ve %100'e yalnızca `Done` olayıyla ulaşır. Canlı bulgu listesi "ön sonuç" diye etiketlenir; tarama bitince birleştirilmiş, sıralı son liste (matris bulguları dahil) onun yerine geçer. §11'deki "plan sayısıyla tutarlı" şu demektir: `Done` anında `Sent` = transport istek sayacı, ve plan yalnızca hasat ve yeniden deneme olmadığında `Sent`'e eşittir (testte bu koşul kurulur).
5. **Arayüz yalnızca yerleşik kurallarla çalışır.** `rules.dirs` ve `rules.disable` arayüzde yoktur ve üretilen config'e yazılmaz; özel kural isteyen CLI kullanır. Bu yüzden `ScanOptions.BaseDir` yalnızca proje dizinindeki spec dosyasını çözmek için kullanılır.

İnşacıya kalanlar: sayfa düzeni ve görsel stil (mevcut HTML raporun sade, ölçülü görünümüyle tutarlı; açık/koyu tema), JS dosya organizasyonu, SSE olay biçiminin ayrıntıları, i18n metin anahtarlarının yapısı, tahmini süre hesabının ayrıntısı.
