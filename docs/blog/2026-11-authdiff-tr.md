---
title: "authdiff: Yetki açıklarını kimlik farkıyla bulmak"
date: 2026-11-21
lang: tr
tags: [güvenlik, api, bola, owasp, go, açık-kaynak]
description: "İmza tabanlı tarayıcıların göremediği BOLA/BFLA açıklarını, aynı isteği farklı kimliklerle atıp yanıtları karşılaştırarak bulan açık kaynak bir CLI aracını nasıl tasarladım."
---

# authdiff: Yetki açıklarını kimlik farkıyla bulmak

`GET /orders/42` geçerli bir istektir. Sözdizimi doğru, başlıklar doğru, yanıt
`200 OK`. Bir SQL injection tarayıcısı burada yakalayacak hiçbir şey bulamaz;
çünkü ortada bir "kötü girdi" yok. İsteği atan kişi 42 numaralı siparişin
sahibi değilse ve yine de siparişi alıyorsa, sorun girdide değil, **kimin
sorduğunda**.

OWASP API Security Top 10 (2023) listesinin birinci maddesi tam olarak bu:
API1 Broken Object Level Authorization (BOLA, eski adıyla IDOR). Beşinci madde
de akrabası: API5 Broken Function Level Authorization (BFLA), yani sıradan bir
kullanıcının `GET /admin/users` çağırabilmesi. Bu açıkların ortak noktası
imzasız olmaları. Payload listesiyle, regex'le, yanıtta hata mesajı aramakla
bulunamazlar. Bulmanın tek yolu aynı isteği farklı kimliklerle atıp sonuçları
karşılaştırmak.

Bu yazıda bunu otomatik yapan açık kaynak CLI aracım
[authdiff](https://github.com/ardayesilcayir/authdiff)'i nasıl tasarladığımı,
karşılaştırma algoritmasını, aracın kendisini nasıl güvenli hale getirdiğimi ve
geliştirme sırasında incelemede çıkan birkaç utandırıcı hatayı anlatıyorum.

## Temel fikir: kimlik farkı (identity diffing)

authdiff bir OpenAPI 3.0/3.1 spec'i okur, endpoint envanterini çıkarır ve her
isteği yapılandırmadaki profillerle tekrar tekrar atar. Profil dediğim şey bir
kimlik ve onun sahip olduğu nesneler:

```yaml
profiles:
  alice:
    role: user
    auth: { type: bearer, token: "${env:ALICE_TOKEN}" }
    owns: { userId: [2], orderId: [101, 102], invoiceId: [9001] }
    identifiers: [alice@vuln.lab]
  bob:
    role: user
    auth: { type: bearer, token: "${env:BOB_TOKEN}" }
    owns: { userId: [3], orderId: [201, 202], invoiceId: [9002] }
  anonymous:
    role: none
    auth: { type: none }
```

Üç rol yeterince çok şey söyler:

- **Sahip (owner):** alice kendi siparişini ister. Referans yanıt budur.
- **Yabancı (stranger):** aynı roldeki bob, alice'in ID'siyle aynı isteği atar.
- **Anonim:** istek hiç kimlik bilgisi olmadan atılır.

Bob, alice'in yanıtını alıyorsa BOLA vardır. Anonim de aynı yanıtı alıyorsa
kaynak zaten herkese açıktır ve bu bir BOLA değildir.

`owns` listelerini elle yazmak zorunda değilsiniz; `harvest` ile her profilin
kendi yanıtlarından ID toplanabilir (`GET /me/orders` → `$.items[*].id`).

İsterseniz beklentiyi açıkça da yazabilirsiniz. Bu, PRD'de "yetki matrisi"
dediğim şey:

```yaml
matrix:
  "GET /admin/**":         { allow: [admin] }
  "GET /orders/{orderId}": { allow: [admin, owner] }
  "POST /orders":          { allow: [admin, user] }
```

Matrisin izin vermediği her 2xx yanıt bir `AD-MATRIX-001` bulgusudur. Matris
opsiyonel; yoksa authdiff sahip ile yabancıyı karşılaştırarak çıkarım yapar.
HTML raporun imza özelliği de bu matrisin gerçekte nasıl davrandığını gösteren
endpoint × profil ısı haritası.

## Karşılaştırma nasıl çalışıyor

Asıl zor kısım "bob, alice'in verisini aldı mı?" sorusunu her endpoint için
elle beklenti yazmadan cevaplamak. Sadece durum koduna bakmak işe yaramıyor:
birçok API yetkisiz çağırana `200` ile boş liste ya da hata gövdesi döner.
Gövdelerin hash'ini karşılaştırmak da işe yaramıyor: tek bir `requestId` veya
zaman damgası eşitliği bozar. Seçtiğim yöntem ([ADR-0002](https://github.com/ardayesilcayir/authdiff/blob/main/docs/adr/0002-karsilastirma-algoritmasi.md))
altı adımdan oluşuyor:

1. **Sahip isteği.** alice `GET /orders/101` atar. 2xx değilse ya da gövde
   boşsa test geçersizdir ve atlanır, raporlanmaz.
2. **Kararlılık ölçümü.** Aynı istek alice adına ikinci kez atılır. İki yanıt
   arasında değeri değişen yaprak yolları "dinamik" işaretlenir ve
   karşılaştırmadan çıkarılır. Yapılandırmadaki `compare.ignoreFields` de
   maskelenir.
3. **Saldırgan isteği.** bob aynı isteği alice'in ID'siyle atar.
4. **Anonim baseline.** İstek kimliksiz atılır. Anonim yanıt da sahibinkine
   benziyorsa kaynak public kabul edilir ve BOLA bulgusu üretilmez.
5. **Karar.** bob 2xx aldıysa ve maskelenmiş benzerlik eşiğin (varsayılan
   `0.85`) üzerindeyse bulgu oluşur.
6. **Güven.** bob'un yanıtında alice'in tanımlayıcıları (e-posta, sahip olduğu
   `userId`) geçiyorsa güven `high`, geçmiyorsa `medium`.

### Benzerlik skoru

Her iki JSON gövdesi yaprak yollarına düzleştirilir; her yaprağın kanonik JSON
değeri tutulur (`$.items[0].price` → `12.5`). Maskelenen yollar iki taraftan da
silinir, sonra:

```
similarity = |iki tarafta da olan ve değeri eşit yollar| / |yolların birleşimi|
```

Bu Jaccard benzeri bir skor. Anahtar sırasından ve biçimlendirmeden bağımsız,
deterministik ve raporda açıklanabilir ("alanların 0.88'i aynı"). Çekirdeği
birkaç satır:

```go
for p, va := range fa {
    if o.masked(p) {
        continue
    }
    union++
    if vb, ok := fb[p]; ok && vb == va {
        equal++
    }
}
for p := range fb {
    if !o.masked(p) {
        if _, ok := fa[p]; !ok {
            union++
        }
    }
}
```

JSON olmayan gövdelerde byte'lar birebir aynıysa skor `1.0`, değilse
`0.8 × min(len)/max(len)`; yani varsayılan eşiğe asla ulaşamaz. JSON ile
JSON olmayanın skoru `0`.

### Küçük bir örnek

alice'in iki yanıtı (adım 1 ve 2):

```json
{"id": 101, "owner": {"id": 2, "email": "alice@vuln.lab"},
 "items": [{"sku": "KB-01", "qty": 1}], "total": 49.9, "status": "paid",
 "viewerCanEdit": true, "requestId": "a1f3", "updatedAt": "2026-11-21T10:00:00Z"}
```

İkinci yanıtta yalnızca `requestId` farklı (`"9c2e"`). Dolayısıyla
`$.requestId` dinamik; `$..updatedAt` zaten `ignoreFields` içinde. bob'un
aldığı yanıt:

```json
{"id": 101, "owner": {"id": 2, "email": "alice@vuln.lab"},
 "items": [{"sku": "KB-01", "qty": 1}], "total": 49.9, "status": "paid",
 "viewerCanEdit": false, "requestId": "77b0", "updatedAt": "2026-11-21T10:00:05Z"}
```

Maskeden sonra kalan yollar: `$.id`, `$.owner.id`, `$.owner.email`,
`$.items[0].sku`, `$.items[0].qty`, `$.total`, `$.status`, `$.viewerCanEdit`.
Birleşim 8, değeri eşit olan 7 (`viewerCanEdit` farklı). Skor
`7/8 = 0.875 ≥ 0.85`: bulgu. Anonim istek `401` aldığı için public değil.
bob'un yanıtında `alice@vuln.lab` geçtiği için güven `high`.

Karşılaştırma için: bob `200` ile `{"detail": "Not found"}` alsaydı, ortak
eşit yol olmadığı için skor `0` olurdu. Eşiğin `0.85` olması, birkaç
izleyiciye özel alanı (`viewerCanEdit` gibi) tolere edip genel bir hata
nesnesinin çok üstünde kalmak için.

Kanıt eşleşmesinde de bir tuzak var: `2` gibi kısa bir ID her yerde geçebilir.
Bu yüzden 6 karakterden kısa ID'ler, ancak yaprağın son anahtarı `owner`,
`user`, `email`, `account` veya `customer` içeriyorsa kanıt sayılıyor.

## Kurallar: YAML + expr

Bu adımları koda gömmek yerine YAML şablonu olarak yazdım; koşullar
[expr](https://github.com/expr-lang/expr) ile değerlendiriliyor. Aynı mekanizma
BOLA, BFLA, NOAUTH ve özel kurallara hizmet ediyor. `rules/bola-read.yaml`
dosyasının tamamı:

```yaml
id: AD-BOLA-001
name: Broken object level authorization (read)
owasp: "API1:2023"
cwe: CWE-639
severity: high
description: >
  A user can read an object owned by another user by supplying its identifier.
  The response served to the non-owner matches the owner's response.
remediation: docs/rules/AD-BOLA-001.md
applies:
  methods: [GET]
  pathHasParam: true
  adminFunction: false
steps:
  - name: owner
    as: owner
    use: owner
    repeat: 2
  - name: attacker
    as: other_user
    use: owner
  - name: anon
    as: anonymous
    use: owner
victim: owner
attacker: attacker
match: >
  owner.ok && len(owner.body) > 0 && attacker.ok &&
  !(anon.ok && similarity(owner.body, anon.body) >= cfg.similarityThreshold) &&
  similarity(owner.body, attacker.body) >= cfg.similarityThreshold
confidence:
  high: evidence(attacker.body, owner.identifiers)
  medium: "true"
```

`as` isteği kimin attığını, `use` ID'lerin kimden geldiğini söylüyor.
`repeat: 2` kararlılık ölçümü. `len(owner.body) > 0` şartı, boş birleşimin
`1.0` skor vermesi yüzünden orada. v1.0.0 sekiz yerleşik kuralla geliyor:
`AD-BOLA-001`, `AD-BOLA-002`, `AD-BFLA-001`, `AD-NOAUTH-001`, `AD-MASS-001`,
`AD-METHOD-001`, `AD-MATRIX-001`, `AD-LEAK-001`.

## Kendisi güvenli bir araç yazmak

Başkasının kimliğiyle istek atan bir aracın yanlış hedefe, yanlış metodla ya
da sızdıran bir yönlendirmeyle istek atması kabul edilemez. Bu yüzden tüm
güvenlik kontrolleri motorlarda değil, transport katmanında bir `RoundTripper`
zinciri olarak duruyor: scope → safe mode → rate limit → base. Yeni yazılan bir
kural bu korumaları atlayamaz.

- **Scope allow-list.** `scope.allowHosts` zorunlu. Eşleşme normalize edilmiş
  `host:port` üzerinde birebir; parse edilemeyen bir girdi kapsamı sadece
  daraltabilir. Yönlendirmeler ve spec indirme de aynı kontrolden geçer.
  Ayrıca `scope.acknowledgeAuthorization: true` olmadan tarama başlamaz.
- **Safe mode.** `DELETE`, `PUT`, `PATCH` varsayılan olarak engelli;
  `--allow-destructive` gerekir. `X-HTTP-Method-Override` gibi başlıklar ve
  `_method` sorgu parametresi de kontrol ediliyor, yani bir `POST` yıkıcı bir
  metodu kaçıramaz.
- **Rate limit.** Varsayılan 5 istek/saniye, normalize edilmiş hedefe göre.
- **Redaction.** Token'lar, cookie'ler, basic-auth kimlik bilgisi ve JWT
  biçimindeki dizgiler her çıktıda maskeleniyor; rapor dosyaları `0600`
  yazılıyor ve sembolik bağlantı üzerinden asla yazılmıyor.
- **HTML rapor.** Tek dosya, `html/template` ile kaçışlanıyor ve şu CSP ile
  geliyor: `default-src 'none'; style-src 'unsafe-inline'; img-src data:`.
  Raporda hedefin döndürdüğü içerik var; o içeriğin bir script çalıştırma şansı
  olmamalı.

Bunları tasarlamak kolaydı. Asıl ders, inceleme sırasında çıkan hatalardan
geldi.

### Savaş hikâyesi 1: tek yavaş endpoint taramanın tamamını öldürüyordu

Motor, iptal sinyalini `errors.Is(err, context.DeadlineExceeded)` ile
algılıyordu. Ama `http.Client` zaman aşımları da bu kontrolden `true` döner.
Sonuç: tek bir yavaş endpoint istek zaman aşımına uğradığında motor bunu
"kullanıcı taramayı iptal etti" sanıp her şeyi durduruyordu. Düzeltme
(`aec9be7`): istek başına zaman aşımları başarısız probe olarak kaydediliyor;
taramayı yalnızca çağıranın kendi context'inin iptali durduruyor. İptalde de
kısmi sonuç döndürülüyor. Ardından (`7ae0ba9`) her denemeyi
`http.Client.Timeout` yerine kendi `context.WithTimeout`'u altında çalıştırdım
ve rate limiter beklemesini zaman aşımının dışına aldım; düşük `--rate`
değerlerinde sahte zaman aşımları buradan geliyordu.

### Savaş hikâyesi 2: `..` ID'leri başka endpoint'lere gidiyordu

ID'lerin bir kısmı hedefin kendi yanıtlarından toplanıyor, yani hedefin
kontrolünde. `url.PathEscape("..")` yine `..` döndürür; `.` ve `..` geçerli yol
karakterleri. `/orders/{orderId}` şablonuna `..` girdiğinde
`/orders/..` oluşuyor ve sunucu bunu normalize edip bambaşka bir kaynağa
gidiyor; `--allow-destructive` açıkken bu bir `DELETE` olabilir. Düzeltme
(`2637509`) küçük:

```go
func escapeSegment(v string) string {
    switch v {
    case ".":
        return "%2E"
    case "..":
        return "%2E%2E"
    }
    return url.PathEscape(v)
}
```

### Savaş hikâyesi 3: NOAUTH kuralı admin'i siliyordu

`AD-NOAUTH-001` önce kimlikli bir referans isteği, sonra anonim bir istek
atıyor. `--allow-destructive` açıkken `DELETE /admin/users/{userId}` için
referans adımı admin profiliyle, admin'in kendi `userId`'siyle atılıyordu:
admin kendini siliyordu ve ardından gelen anonim probe her zaman `404`
alıyordu. Düzeltme (`259a372`): referans adımı `skipDestructive: true` ile
yıkıcı metotları hiç göndermiyor. Aynı committe yıkıcı isteklerin, yoldaki
ID'lerin hepsi yapılandırılmış bir profile ait değilse planlanmaması ve
`DELETE` fazının sıralı (concurrency 1) çalışması da geldi.

### Savaş hikâyesi 4: https → http yönlendirmesi Authorization sızdırıyordu

Go'nun `http.Client`'ı yönlendirmede `Authorization` ve cookie'leri yalnızca
farklı bir alan adına giderken düşürüyor; aynı host'a `https`'ten `http`'ye
düşüşte koruyor, `X-API-Key` gibi özel başlıkları ise her yönlendirmede
kopyalıyor. Yani kapsam içi ama kötü niyetli bir yanıt token'ı düz metin
kanala taşıyabiliyordu. Düzeltme (`e492eae`): `CheckRedirect`, `https → http`
düşüşlerini ve farklı `host:port`'a giden yönlendirmeleri reddediyor.
Aynı committe `HTTP_PROXY`/`HTTPS_PROXY` da yok sayılıyor; proxy yalnızca
`--proxy` ile açıkça verilirse kullanılıyor ve loglanıyor. Ağ hataları da
artık yalnızca `GET`/`HEAD`/`OPTIONS` için yeniden deneniyor.

## Test stratejisi: kasıtlı açıklı lab bir oracle

Bir güvenlik tarayıcısını "çalışıyor gibi görünüyor" diye yayınlamak
istemedim. Repoda `vuln-lab/` altında kasıtlı olarak açıklı bir FastAPI
e-ticaret API'si var. `VULNERABILITIES.md` dosyasının front-matter'ı
makinece okunabilir bir oracle:

```yaml
expected:
  - id: V1
    rule: AD-BOLA-001
    method: GET
    path: /orders/{orderId}
    destructive: false
  # ... V2-V8
negatives:
  - method: GET
    path: /orders/{orderId}/status
  - method: GET
    path: /products/{id}
  # ...
```

Sekiz beklenen bulgu var (BOLA okuma/yazma, PDF fatura, iki BFLA, NOAUTH, mass
assignment, `passwordHash` sızıntısı) ve doğru korunan negatif kontroller:
public ürünler, `/me`, `/admin/stats` gibi. Negatifler en az pozitifler kadar
önemli; yanlış pozitifler bu tür bir aracın benimsenmesini öldürür.

`test/e2e` altındaki test lab'i tarıyor, her `(rule, method, path)` üçlüsünü
oracle ile karşılaştırıyor ve negatif bir endpoint'te tek bir bulgu bile testi
düşürüyor. Yıkıcı kontrollerle birlikte sonuç: **recall 1.00 (8/8), yanlış
pozitif oranı 0.00**. E2E workflow'u ayrıca SARIF çıktısında bulgu olduğunu
doğruluyor (boş bir SARIF bozuk bir tarama demek) ve onu GitHub code
scanning'e yüklüyor; bulgular **Security → Code scanning** altında görünüyor.

Kendi yazdığım lab'de %100 almak elbette iyimser bir ölçüm. Bu yüzden ikinci
bir hedef üzerinde benchmark ayrı bir dokümanda:
[docs/benchmarks.md](https://github.com/ardayesilcayir/authdiff/blob/main/docs/benchmarks.md).

## Etik ve hukuk

authdiff yalnızca sahibi olduğunuz ya da yazılı test izniniz olan sistemlerde
kullanılmak üzere tasarlandı. Türkiye'de izinsiz bir bilişim sistemine erişmek,
sistemi engellemek veya verileri bozmak TCK 243 ve 244 kapsamında suçtur. Bu
yüzden varsayılanlar "kapalı" başlıyor: `acknowledgeAuthorization` zorunlu,
kapsam listesi zorunlu, yıkıcı metotlar kapalı ve User-Agent aracı açıkça
tanıtıyor (`authdiff (+https://github.com/ardayesilcayir/authdiff)`). Bir bug
bounty programında bile kapsamı ve kuralları okuyun; "başka bir kullanıcının
siparişini okuyabiliyorum" testinin kendisi, izin yoksa, başka birinin verisine
erişmektir.

## Deneyin

Kurulum:

```sh
go install github.com/ardayesilcayir/authdiff/cmd/authdiff@v1.0.0
```

ya da [v1.0.0 release](https://github.com/ardayesilcayir/authdiff/releases/tag/v1.0.0)
sayfasından Linux, macOS veya Windows (amd64/arm64) binary'si
(`checksums.txt` ile). Docker imajı: `ghcr.io/ardayesilcayir/authdiff`.

Beş dakikalık lab akışı:

```sh
git clone https://github.com/ardayesilcayir/authdiff && cd authdiff
go install ./cmd/authdiff
make lab                                         # vuln-lab'i Docker ile başlatır
set -a; source examples/vuln-lab.env; set +a     # lab'in SAHTE token'ları
authdiff scan -c examples/authdiff.yaml
```

Tarama bulguları terminale yazar ve `authdiff-out/` altına `results.json`,
`results.sarif` ve `report.html` üretir. Bulgular `failOn: high` eşiğine
ulaştığı için çıkış kodu `1`. Yıkıcı açıkları (V2, V5, V7) görmek için
`--allow-destructive` ekleyin ve ardından lab'i yeniden başlatın; tarama lab'i
değiştirir.

Kendi API'niz için `authdiff init` bir başlangıç yapılandırması yazar, `authdiff
scan --dry-run` endpoint'lere istek atmadan istek planını gösterir. CI için
`uses: ardayesilcayir/authdiff/action@v1` SARIF'i code scanning'e yükler ve
`fail-on` eşiğinde işi kırmızıya çevirir.

## Sınırlar ve yol haritası

- Benzerlik JSON'a göre tasarlandı. PDF gibi JSON olmayan kaynaklar ancak
  byte'lar birebir aynıysa yakalanıyor; lab'deki fatura PDF'inde öyle ama her
  yerde öyle olmak zorunda değil.
- İzleyiciye göre değişen alanları çok olan endpoint'ler `ignoreFields`
  gerektirebilir; eşik ayarı da ikinci hedef ölçümüne göre yeniden ele
  alınacak.
- Araç OpenAPI spec'ine bağımlı; spec eksikse envanter de eksik.
- Token yenileme yok; uzun taramalarda süresi dolan token'ı siz
  yenilemelisiniz.

v1.0 sonrası (PRD'deki P2 maddeleri): Swagger 2.0 desteği (3.0'a otomatik
dönüşüm), spec olmayan API'ler için HAR / Burp XML içe aktarma, login
endpoint'iyle token yenileme ve GraphQL desteği.

Kod, kurallar ve lab: [github.com/ardayesilcayir/authdiff](https://github.com/ardayesilcayir/authdiff).
Yeni bir kural şablonu, yanlış pozitif raporu ya da ikinci bir hedefte ölçüm
sonucu en çok işime yarayacak katkılar.
