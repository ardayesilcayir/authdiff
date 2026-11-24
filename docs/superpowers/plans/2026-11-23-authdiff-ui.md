# authdiff UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `authdiff ui` — yalnızca loopback'te çalışan, motoru CLI ile aynı kod yolundan kullanan, demo + sihirbaz + canlı tarama + sonuç/triage sunan yerel web arayüzü (v1.1.0).

**Architecture:** Yeni `internal/ui` paketi: `net/http` sunucusu, `html/template` ile sunucu tarafında çizilen sayfalar, `embed` ile gömülü küçük CSS/JS, canlı ilerleme için Server-Sent Events. Proje durumu `project.json`'da, token'lar yalnızca bellekte. Tarama `pkg/authdiff.Scan`'e bellekteki `*config.Config` ve ilerleme kancası verilerek yapılır.

**Tech Stack:** Go standart kütüphanesi (`net/http`, `html/template`, `embed`, `archive/zip`, `crypto/rand`), mevcut paketler. Yeni Go bağımlılığı ve Node/npm yok.

**Spec:** `docs/superpowers/specs/2026-11-23-authdiff-ui-design.md` (bağlayıcı; §13'teki kararlar dahil).

## Global Constraints

- Yeni üçüncü taraf Go modülü eklenmez; ön yüzde CDN/harici kütüphane yok, JS el yazımı.
- `cobra` yalnızca `internal/cli`; `internal/ui` yalnızca `pkg/authdiff`, `internal/config`, `internal/report`, `internal/finding`, `internal/spec`, `internal/engine` (yalnızca `PlannedRequest`/`Progress` tipleri), `examples` (embed) import eder.
- Sunucu yalnızca `127.0.0.1` dinler. Varsayılan port `7465`; meşgulse sıradaki port, en fazla 10 deneme.
- Oturum anahtarı 32 bayt `crypto/rand`, hex; çerez adı `authdiff_session`, `HttpOnly; SameSite=Strict; Path=/`.
- Her yanıtta: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` (`no-referrer` değil: o politikada tarayıcı form POST'larında `Origin: null` gönderir ve Referer göndermez, Origin kontrolü her formu reddeder; `same-origin` başka origin'lere yine hiçbir şey göndermez), `Cache-Control: no-store`.
- `Host` yalnızca `127.0.0.1:<port>` veya `localhost:<port>`; aksi 421. Çerezsiz istek 401. POST'ta `Origin` (yoksa `Referer`) kendi origin'imiz + oturuma bağlı CSRF token'ı (`csrf` form alanı veya `X-CSRF-Token` başlığı); aksi 403.
- Token/parola değerleri diske, log'a, tarayıcı depolamasına ve sunucudan tarayıcıya dönen HTML/JSON'a yazılmaz (yalnızca `•••• ` + son 4). Tek istisna `Demo: true` projesi.
- Proje dizini: `os.UserConfigDir()/authdiff/projects` (değiştirilebilir); dizinler 0700, dosyalar 0600; proje adı `^[a-z0-9][a-z0-9-]{0,62}$`.
- Yüklenen spec ≤ 10 MiB. Aynı anda tek tarama (ikinci istek 409).
- Yıkıcı mod yalnızca `confirm` alanı `anladım` veya `I understand` (büyük/küçük harf duyarsız, baştaki/sondaki boşluk kırpılır) ise açılır; demo dahil istisna yok.
- Ortam değişkeni adı: `AUTHDIFF_` + upper(profil) (`[^A-Z0-9]` → `_`) + `_TOKEN` | `_USERNAME` | `_PASSWORD`. Demo projesi örnek config'teki adları korur.
- Arayüz TR/EN; dil seçimi `lang` çerezi > `Accept-Language` > `en`.
- `internal/` kapsamı ≥ %80, golangci-lint temiz, mevcut testler ve vuln-lab e2e (recall 1.00 / FP 0.00) bozulmaz.
- Commit mesajları `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` ile biter.

## Review Focus

1. **Sunucu yeniden başlatıldıktan sonra token'ların gitmesi** — kayıtlı bir projeyle "Planla"/"Tara" denenince 500 değil, eksik token'ları soran profil sayfasına yönlendirme (ortamda `AUTHDIFF_*` varsa oradan alınır). Test: Task 3 `TestBuildConfigMissingSecrets`, Task 5 `TestScanRedirectsWhenSecretsMissing`.
2. **Bozuk/erişilemeyen spec** — geçersiz YAML yükleme veya erişilemeyen spec URL'si Endpoint'ler sayfasında okunur bir hata mesajı (redakte edilmiş URL) ile 200/422 döner, 500 değil. Test: Task 4 `TestEndpointsBadSpec`.
3. **Tarayıcı tarama sırasında kapanırsa** — tarama SSE istemcisinden bağımsız sürer, sonuç `runs/` altına yazılır, sonra açılan sayfada görünür. Test: Task 5 `TestRunContinuesWithoutClient`.
4. **İki sekmeden aynı anda tarama** — ikinci istek 409 ve "zaten bir tarama çalışıyor" bağlantısı. Test: Task 5 `TestSecondScanConflict`.
5. **Port meşgul** — sıradaki port seçilir, terminale doğru anahtarlı URL basılır. Test: Task 2 `TestListenFallsBackToNextPort`.

---

### Task 1: Motor ve pkg API — bellekteki config ve ilerleme kancası

**Files:**
- Modify: `internal/engine/runner.go`, `internal/engine/engine.go` (ilerleme tipi), `internal/engine/sender.go` (sayaç sarmalayıcı), `pkg/authdiff/authdiff.go`, `internal/config/config.go` (Marshal)
- Create: `internal/engine/progress.go`, `internal/config/marshal.go`
- Test: `internal/engine/progress_test.go`, `pkg/authdiff/config_object_test.go`, `internal/config/marshal_test.go`

**Interfaces:**
- Produces (`internal/engine`):
  - `type Progress struct { Phase int; PhaseName string; Sent, Planned, Blocked, Errors int; Finding *finding.Finding; Done bool }` — PhaseName: `harvest`, `read`, `write`, `swap`, `delete`, `finish`.
  - `RunOptions.OnProgress func(Progress)` ve `RunOptions.Planned int`. Kanca: faz başlangıcında, her gönderilen/engellenen/hatalı istekten sonra (kümülatif sayaçlar), bir check bulgu ürettiğinde (`Finding` dolu, her bulgu için bir olay; tekrar eden ID'ler için de olay gelebilir), en sonda `Done: true` ile bir kez (sonuç birleştirildikten sonra). Kanca motor goroutine'lerinden eşzamanlı çağrılabilir; motor çağrıyı engellemez (kancanın kendisi hızlı olmalı — sözleşme yorumda yazılır).
- Produces (`pkg/authdiff`):
  - `type Progress = engine.Progress`.
  - `ScanOptions` alanları: `Config *config.Config` (ConfigPath ile birlikte verilirse hata `"authdiff: set ConfigPath or Config, not both"`), `BaseDir string` (Config verildiğinde göreli `target.spec` bu dizine göre çözülür; boşsa CWD), `OnProgress func(Progress)`.
  - `Scan`, `PlanContext` her iki yolu destekler; `Config` yolunda `Overrides` yine uygulanır ve `config.Validate` çağrılır (config kopyası üzerinde; çağıranın config'i değişmez).
  - `Scan`, `OnProgress` verildiyse önce plan sayısını (`engine.DryRun`) hesaplayıp `Planned` olarak geçirir.
  - `func LoadInventoryConfig(ctx context.Context, cfg *config.Config, baseDir, version string) (*spec.Inventory, error)` — mevcut `LoadInventory`'nin config nesnesi sürümü (kapsam zincirli istemci, redakte hatalar).
- Produces (`internal/config`): `func Marshal(c *Config) ([]byte, error)` — `Load`'un okuyabileceği YAML; `Timeout` `"10s"` biçiminde; boş alanlar yazılmaz; `Profile.Name` yazılmaz (map anahtarı).

- [ ] **Step 1: Failing testler**
  - `TestProgressEvents` (engine, httptest mini API, 2 endpoint): olaylar faz sırasıyla gelir; son olay `Done==true` ve yalnızca bir kez; son olayda `Sent == res.Stats.Requests`, `Blocked`/`Errors` Stats ile eşit; hasat yokken `Planned == Sent`; en az bir `Finding` olayı; olay sayaçları azalmaz.
  - `TestProgressNilHookIsNoop`.
  - `TestScanWithConfigObjectMatchesFile` (pkg): aynı config'in dosya ve nesne yolları aynı bulgu ID kümesini verir; çağıranın `*config.Config`'i tarama sonrası değişmemiştir (`reflect.DeepEqual` kopya ile).
  - `TestScanBothConfigSourcesError`, `TestConfigObjectRelativeSpecUsesBaseDir`, `TestLoadInventoryConfigOutOfScopeURL` (kapsam dışı spec URL'si reddedilir).
  - `TestMarshalRoundTrip` (config): PRD §10.2 örneği `Parse` → `Marshal` → `Parse` → eşit; `${env:ALICE_TOKEN}` yer tutucusu Marshal çıktısında aynen durur (ortamda tanımlıyken `Load` ile okunabilir).
- [ ] **Step 2:** `go test ./internal/engine/... ./pkg/... ./internal/config/...` → FAIL.
- [ ] **Step 3:** Uygula. Sayaçları `clientSender`'ı saran bir sayaç ile ya da transport istatistiklerinden türet; faz geçişleri `Run` döngüsünde; bulgu olayı check sonucu `outs[i]`'ye yazılırken.
- [ ] **Step 4:** `go test ./...` → PASS; `golangci-lint run ./...` temiz.
- [ ] **Step 5:** Commit.

---

### Task 2: `internal/ui` sunucu iskeleti, güvenlik katmanı, i18n, ana sayfa, `authdiff ui` komutu

**Files:**
- Create: `internal/ui/server.go` (Options, New, Listen/Serve, yönlendirme), `internal/ui/security.go` (oturum, Host, CSRF, başlıklar), `internal/ui/i18n.go` (+ `internal/ui/i18n/tr.json`, `en.json`), `internal/ui/render.go` (şablon yükleme, ortak sayfa verisi), `internal/ui/templates/layout.html.tmpl`, `home.html.tmpl`, `error.html.tmpl`, `internal/ui/static/app.css`, `app.js`, `internal/ui/labcheck.go`, `internal/cli/ui.go`, `internal/cli/browser.go`, `examples/embed.go` (package `examplesfs`, `//go:embed authdiff.yaml vuln-lab.env`)
- Test: `internal/ui/security_test.go`, `internal/ui/server_test.go`, `internal/cli/ui_test.go`

**Interfaces:**
- Produces:
  - `type Options struct { Port int; ProjectsDir string; Version string; LabURL string /* varsayılan http://127.0.0.1:8000 */; Log *slog.Logger }`
  - `func New(o Options) (*Server, error)`; `func (s *Server) Listen() (url string, err error)` (anahtarlı URL döner); `func (s *Server) Serve(ctx context.Context) error` (ctx iptalinde çalışan taramayı iptal eder, kısmi sonucu yazdırır, sunucuyu kapatır); `func (s *Server) Handler() http.Handler` (testler için).
  - Ortak sayfa verisi `pageData{ T func(key string, args ...any) string; Lang string; CSRF string; Title string; Flash string; ... }`; `T` eksik anahtar için anahtarın kendisini döner ve testte eksik anahtar yakalanır (`TestI18nKeysComplete`: tr ve en anahtar kümeleri eşit, şablonlarda kullanılan her anahtar ikisinde de var).
  - Rotalar (bu task): `GET /` (ana sayfa), `GET /static/*`, `POST /lang`, `GET /healthz` (oturumsuz değil — o da oturum ister).
  - `func CheckLab(ctx context.Context, labURL string) bool` — `GET <labURL>/openapi.json`, 2 sn, yalnızca loopback host'lara izin verir.
  - CLI: `authdiff ui [--port 7465] [--no-open] [--projects-dir dir]`; anahtarlı URL'yi stdout'a basar; `--no-open` yoksa tarayıcı açar (`browser.go`: windows `rundll32 url.dll,FileProtocolHandler`, darwin `open`, diğer `xdg-open`; hata sadece uyarı logu).
- Tasarım: sade, ölçülü, mevcut HTML raporla aynı renk dili; açık/koyu tema `prefers-color-scheme`; sayfa ≥ 960px için iki sütunlu sihirbaz düzeni, dar ekranda tek sütun, tablolar kendi kapsayıcısında kayar. Bu task'ın uygulayıcısı `frontend-design:frontend-design` skill'ini kullanır. JS yalnızca `textContent`/`createElement` kullanır, `innerHTML` yasak (lint için `grep` testi: `TestNoInnerHTML`).

- [ ] **Step 1: Failing testler** — `TestNoSessionIs401`, `TestKeyLoginSetsCookieAndRedirects` (yanlış anahtar 401, doğru anahtar → çerez + anahtarsız URL'ye 303), `TestBadHostIs421` (`Host: evil.com:7465`, `Host: 127.0.0.1.nip.io:7465`), `TestPostWithoutCSRFIs403`, `TestPostForeignOriginIs403`, `TestSecurityHeadersOnEveryResponse` (statik dosya, 401 ve 404 yanıtları dahil, tam CSP metni), `TestListenFallsBackToNextPort`, `TestListenOnlyLoopback` (dinlenen adres `127.0.0.1`), `TestHomeShowsLabStatus` (httptest lab sahte sunucusuyla çalışıyor/çalışmıyor), `TestLanguageNegotiation` (Accept-Language `tr-TR` → Türkçe, `lang=en` çerezi baskın), `TestI18nKeysComplete`, `TestNoInnerHTML`, CLI: `TestUICommandFlags` (`--no-open` ile tarayıcı açılmaz; URL stdout'ta).
- [ ] **Step 2:** FAIL. **Step 3:** Uygula. **Step 4:** `go test -cover ./internal/ui/... ./internal/cli/...` PASS, ≥ %80. **Step 5:** Commit.

---

### Task 3: Proje deposu, bellek içi gizli bilgiler, config üretimi, demo projesi, dışa aktarma paketi

**Files:**
- Create: `internal/ui/project.go`, `internal/ui/store.go`, `internal/ui/secrets.go`, `internal/ui/buildconfig.go`, `internal/ui/demo.go`, `internal/ui/export.go`
- Test: `internal/ui/store_test.go`, `internal/ui/buildconfig_test.go`, `internal/ui/export_test.go`

**Interfaces:**
- Consumes: `config.Marshal`, `config.Validate` (Task 1), `examplesfs` (Task 2).
- Produces:
  - `type Project struct { Name string; Demo bool; CreatedAt, UpdatedAt time.Time; BaseURL, SpecURL, SpecFile string /* proje dizinindeki dosya adı */; AllowHosts []string; Acknowledged bool; Exclude []string /* "METHOD /path" */; Tags []string; Profiles []ProfileDef; Harvest []config.HarvestRule; Safety SafetyDef; Matrix map[string][]string; IgnoreFields []string; Threshold float64; Step string /* sihirbazın kaldığı adım */ }` (json camelCase).
  - `type ProfileDef struct { Name, Role, AuthType, AuthName, AuthIn string; Owns map[string][]string; Identifiers []string }` — gizli alan YOK.
  - `type SafetyDef struct { Rate float64; Concurrency int; TimeoutSec int; AllowDestructive bool; Insecure bool; Proxy string }`.
  - `type Store struct`; `func NewStore(dir string) (*Store, error)`; `List() ([]Project, error)` (UpdatedAt azalan); `Get(name) (*Project, error)`; `Save(p *Project) error` (atomik yaz: temp + rename, 0600); `Dir(name) string`; `SaveSpec(name string, r io.Reader, ext string) (string, error)` (≤ 10 MiB, aksi hata); `AppendIgnore(name, id, reason string) error`; `RunsDir(name) string`; `ValidName(string) bool`.
  - `type Secrets struct` (mutex'li, `map[proje]map[profil]Secret`); `type Secret struct { Token, Username, Password string }`; `Set`, `Get`, `Masked(project, profile) map[string]string` (`•••• ` + son 4, 8 karakterden kısa ise `••••`), `Missing(p *Project) []string` (ortamdaki `AUTHDIFF_*` değerleri de dikkate alınır).
  - `func EnvName(profile, field string) string` (Global Constraints kuralı).
  - `func BuildConfig(p *Project, sec *Secrets, projectDir string) (*config.Config, error)` — gizli değerleri yerleştirilmiş, `ApplyDefaults` + `Validate` geçmiş config; eksik gizli bilgi için `ErrMissingSecrets{Profiles []string}`.
  - `func PlaceholderConfig(p *Project) (*config.Config, error)` — token alanları `${env:EnvName(...)}`; demo projesinde örnek adlar.
  - `func EnsureDemo(st *Store, sec *Secrets, labURL string) (*Project, error)` — gömülü `authdiff.yaml`'daki `${env:X}`'i gömülü `vuln-lab.env` değerleriyle değiştirip `config.Parse`; Project'e çevirir; `Demo:true`; token'ları `Secrets`'a koyar ve demo için `demo-secrets.json` (0600) dosyasına yazar (tek disk istisnası); baseUrl/spec `labURL`'e göre.
  - `func WriteExportZip(w io.Writer, st *Store, p *Project) error` — `authdiff.yaml` (PlaceholderConfig + `config.Marshal`, spec yolu `spec.<ext>` ya da URL), varsa spec dosyası, `.authdiff-ignore`, `.env.example` (her değişken `NAME=` satırı, sıralı), demo ise `vuln-lab.env`; zip içinde dizin yok.

- [ ] **Step 1: Failing testler** — `TestValidName` (`../x`, `A`, `-a`, 64+ karakter reddedilir), `TestSaveLoadRoundTrip`, `TestFilePermissions` (Windows'ta atlanır), `TestNoSecretOnDisk` (Set'ten sonra proje dizinindeki tüm dosyalarda token değeri geçmez; demo hariç), `TestSaveSpecTooLarge`, `TestEnvName` (`staging-admin`+`token` → `AUTHDIFF_STAGING_ADMIN_TOKEN`, `alice`+`password` → `AUTHDIFF_ALICE_PASSWORD`), `TestBuildConfigMissingSecrets` (`ErrMissingSecrets` profil adlarıyla; ortamda `AUTHDIFF_ALICE_TOKEN` varsa alice eksik sayılmaz), `TestBuildConfigValid` (Validate geçer, `Exclude` → `Filter.Exclude`, `Acknowledged` → `AcknowledgeAuthorization`), `TestEnsureDemoMatchesExample` (demo config'i `examples/authdiff.yaml` + env ile `config.Load` sonucuyla eşdeğer), `TestExportZipRoundTrip` (zip açılır, `.env.example` değerleri ortama verilince `config.Load(authdiff.yaml)` hatasız; zip'te token değeri yok — demo hariç), `TestAppendIgnore` (`finding.LoadBaseline` okuyabiliyor).
- [ ] **Step 2:** FAIL. **Step 3:** Uygula. **Step 4:** PASS, kapsam ≥ %80. **Step 5:** Commit.

---

### Task 4: Sihirbaz ekranları — Hedef, Endpoint'ler, Profiller, Ayarlar

**Files:**
- Create: `internal/ui/wizard.go` (handler'lar), `internal/ui/forms.go` (form ayrıştırma/doğrulama), `internal/ui/templates/wizard_target.html.tmpl`, `wizard_endpoints.html.tmpl`, `wizard_profiles.html.tmpl`, `wizard_settings.html.tmpl`, `projects.html.tmpl`
- Modify: `internal/ui/server.go` (rotalar), i18n dosyaları, `static/app.js` (profil kartı ekleme, matris tablosu, yıkıcı onay penceresi — JS yoksa da formlar çalışır)
- Test: `internal/ui/wizard_test.go`

**Interfaces:**
- Consumes: Task 2 (render, güvenlik), Task 3 (Store, Secrets, BuildConfig), Task 1 (`LoadInventoryConfig`).
- Produces rotalar: `GET/POST /projects/new`, `GET /projects`, `GET/POST /p/{name}/target`, `GET/POST /p/{name}/endpoints`, `GET/POST /p/{name}/profiles`, `GET/POST /p/{name}/settings`, `POST /p/{name}/delete`. Her POST kaydeder ve sıradaki adıma 303 yapar; doğrulama hatasında aynı sayfa 422 + alan hataları.
- Davranış (spec §8.3–8.6):
  - Hedef: base URL zorunlu (http/https, userinfo yok); spec dosyası (multipart, ≤ 10 MiB, .yaml/.yml/.json) **ya da** URL; allowHosts boşsa base URL'den `host:port`; `Acknowledged` işaretlenmeden ileri gidilmez.
  - Endpoint'ler: envanteri yükler (tablo: method, path, operationId, secured, parametreler, etiketler), satır onay kutuları; seçilmeyenler `Exclude` = `"METHOD /path"`. Uygulayıcı `spec.Inventory.Filter`'ın method önekli exclude desenlerini desteklediğini test eder; desteklemiyorsa `Filter`'ı genişletir (test ile).
  - Profiller: kart alanları; "admin + 2 kullanıcı + anonim" şablon düğmesi; sahip olunan ID önerileri envanterdeki path parametrelerinden; token alanı boş gönderilirse mevcut gizli değer korunur; maskeli gösterim; aynı rolde iki kullanıcı yoksa uyarı.
  - Ayarlar: hız, eşzamanlılık, zaman aşımı; yıkıcı mod yalnızca `confirm` kuralıyla (Global Constraints); gelişmiş: eşik, ignoreFields, proxy, insecure (uyarılı), matris (desen satırları × `admin`/`user`/`none`/`owner`/profil adları).

- [ ] **Step 1: Failing testler** — `TestNewProjectFlow` (tam akış POST'larla, sonunda `BuildConfig` geçerli), `TestTargetRequiresAck`, `TestTargetRejectsUserinfo`, `TestEndpointsBadSpec` (bozuk YAML → 422 ve hata metni; erişilemeyen URL → 422, URL'de query varsa redakte), `TestEndpointsExcludeApplied`, `TestProfilesKeepSecretWhenBlank`, `TestProfilesNeverEchoSecret` (yanıt gövdesinde token yok, yalnızca maske), `TestDestructiveRequiresConfirm` (`confirm` yok/yanlış → 422 ve `AllowDestructive` false kalır; `anladım` ve `I understand` kabul), `TestDemoAlsoRequiresConfirm`, `TestTargetEscapesHostileSpec` (path'i `<script>` içeren spec yüklenince sayfada kaçışlı).
- [ ] **Step 2:** FAIL. **Step 3:** Uygula. **Step 4:** PASS, kapsam ≥ %80. **Step 5:** Commit.

---

### Task 5: Plan, canlı tarama (SSE), durdurma, çalıştırma kaydı

**Files:**
- Create: `internal/ui/runs.go` (tarama yöneticisi), `internal/ui/sse.go`, `internal/ui/templates/plan.html.tmpl`, `run.html.tmpl`
- Modify: `server.go`, `static/app.js` (EventSource istemcisi), i18n
- Test: `internal/ui/runs_test.go`

**Interfaces:**
- Consumes: `pkg/authdiff.PlanContext/Scan` (Task 1, `ScanOptions{Config, BaseDir, OnProgress, IgnoreFile: <proje>/.authdiff-ignore}`), `report.Write`.
- Produces:
  - `type RunManager struct` (tek aktif tarama); `func (m *RunManager) Start(p *Project, cfg *config.Config, projectDir string) (runID string, err error)` — aktif varsa `ErrBusy`; tarama `Server`'ın ömrüne bağlı arka plan context'inde koşar (HTTP isteğine değil).
  - `runID` = `20061102-150405` (yerel zaman) ; sonuç `RunsDir/<runID>/` altına `results.json`, `results.sarif`, `report.html` (`report.Write`, terminal formatı yok).
  - `func (m *RunManager) Subscribe(runID string) (<-chan Event, func())` — geç bağlanan istemci önce son durumu alır; `Event{Type: "progress"|"finding"|"done"|"error", Data any}`; abone yavaşsa olay düşürülür (sayaçlar kümülatif).
  - `func (m *RunManager) Stop(runID string) error` — iptal; kısmi sonuç yazılır.
  - Rotalar: `GET /p/{name}/plan` (PlanContext tablosu: kurala göre grup, yıkıcı etiket, toplam, tahmini süre = plan/hız), `POST /p/{name}/scan` (eksik gizli bilgi → profillere 303; meşgul → 409 sayfası), `GET /p/{name}/runs/{id}` (canlı sayfa; bitmişse sonuçlara 303), `GET /api/runs/{id}/events` (SSE, `text/event-stream`), `POST /api/runs/{id}/stop`.
  - İlerleme çubuğu `min(Sent/Planned, 0.99)`, `done` ile %100; canlı bulgular "ön sonuç" etiketiyle.

- [ ] **Step 1: Failing testler** (httptest mini API hedefiyle) — `TestPlanPage` (yıkıcı satırlar işaretli, toplam doğru), `TestScanRedirectsWhenSecretsMissing`, `TestSecondScanConflict` (409), `TestSSEStream` (progress olayları, en az bir finding, son olay done; done'da Sent == results.json Stats.Requests), `TestRunContinuesWithoutClient` (SSE bağlantısı kapatılır, tarama biter, `runs/<id>/results.json` var), `TestStopWritesPartial`, `TestServeCancelStopsRun` (Serve ctx iptali → kısmi sonuç yazılmış), `TestRunFilesNoSecrets` (çıktı dosyalarında token yok).
- [ ] **Step 2:** FAIL. **Step 3:** Uygula. **Step 4:** PASS, kapsam ≥ %80. **Step 5:** Commit.

---

### Task 6: Sonuçlar, triage, dışa aktarma, geçmiş

**Files:**
- Create: `internal/ui/results.go`, `internal/ui/templates/results.html.tmpl`, `finding.html.tmpl`
- Modify: `internal/report/html.go` + `internal/report/templates/report.html.tmpl` (ısı haritasını adlandırılmış şablona ayır), `server.go`, i18n
- Test: `internal/ui/results_test.go`, `internal/report/heatmap_test.go`

**Interfaces:**
- Produces (`internal/report`): `func Heatmap(r *finding.Result) (template.HTML, error)` — rapordaki ısı haritasıyla aynı markup (ortak adlandırılmış şablon); rapor golden testleri değişmez (golden güncellemesi gerekmez).
- Rotalar: `GET /p/{name}/runs/{id}/results` (özet kartları, `Notes`, ısı haritası, önem/kural filtresi `?sev=high&rule=AD-BOLA-001`, susturulanlar ayrı bölüm), `GET /p/{name}/runs/{id}/findings/{fid}` (ayrıntı + kanıt, docs/rules bağlantısı `https://github.com/ardayesilcayir/authdiff/blob/main/docs/rules/<ID>.md`), `POST /p/{name}/runs/{id}/findings/{fid}/ignore` (gerekçe zorunlu; `Store.AppendIgnore`; görüntülenen sonuçta da susturulmuş işaretlenir), `GET /p/{name}/runs/{id}/download/{results.json|results.sarif|report.html}`, `GET /p/{name}/export.zip` (`WriteExportZip`), `GET /p/{name}` (proje sayfası: ayarlara git, yeniden tara, geçmiş taramalar tarih + bulgu sayısı).
- İndirmeler `Content-Disposition: attachment`; `fid`/`id` yalnızca beklenen biçimler (`^[0-9a-f]{12}$`, `^\d{8}-\d{6}$`), aksi 404.

- [ ] **Step 1: Failing testler** — `TestHeatmapMatchesReport` (WriteHTML çıktısı Heatmap çıktısını içerir), `TestResultsPage` (sayılar results.json ile tutarlı), `TestResultsFilter`, `TestFindingEvidenceEscaped` (`<script>` içeren yanıt gövdesi kaçışlı), `TestIgnoreRequiresReason`, `TestIgnorePersists` (sonraki taramada `Suppressed`), `TestDownloadPathTraversal` (`../` ve geçersiz id → 404), `TestExportZipEndpoint`, `TestProjectHistory`.
- [ ] **Step 2:** FAIL. **Step 3:** Uygula. **Step 4:** PASS, kapsam ≥ %80. **Step 5:** Commit.

---

### Task 7: Uçtan uca doğrulama, dokümantasyon, sürüm

**Files:**
- Create: `test/e2e/ui_test.go` (`//go:build e2e`), `docs/ui.md`
- Modify: `README.md`, `README.en.md`, `CHANGELOG.md` (`[Unreleased]` → Added: `authdiff ui`), `docs/architecture.md` (ui paketi), `Makefile` (`ui` hedefi: `go run ./cmd/authdiff ui`)

**Interfaces:**
- Consumes: tüm `internal/ui` rotaları (`Server.Handler()` + oturum çerezi ile).

- [ ] **Step 1:** `TestUIDemoMatchesOracle` — taze lab'a karşı: sunucu `Handler()` ile başlatılır, oturum açılır, demo projesi oluşturulur, ayarlarda yıkıcı mod `anladım` ile açılır, tarama başlatılır, `done` beklenir; sonuçtaki (rule, method, path) kümesi `vuln-lab/VULNERABILITIES.md` `expected` kümesine eşit, negatiflerde bulgu yok (CLI e2e oracle mantığı paylaşılan yardımcıya çıkarılır).
- [ ] **Step 2:** Lab'ı başlat (`cd vuln-lab && .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`), `go test -tags e2e -count=1 ./test/e2e/...` → iki test de PASS; lab'ı durdur.
- [ ] **Step 3:** `docs/ui.md` (güvenlik modeli, proje dizini, token'ların saklanmaması ve sunucu yeniden başlarsa yeniden girilmesi, demo, dışa aktarma, `authdiff.yaml`'ı elle düzenlemenin yansımaması); README TR/EN "Arayüz ile kullanım" bölümü (komut, ekran akışı); CHANGELOG.
- [ ] **Step 4:** `go test ./...`, `go vet ./...`, `golangci-lint run ./...`, `govulncheck ./...` temiz.
- [ ] **Step 5:** Commit.
