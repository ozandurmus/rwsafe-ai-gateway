<!-- Fable council seat 'offensive-security', 2026-10-30T09:26:44, exit 0; unaltered output -->

Kısa cevap: brief'in en büyük açığı, rakibin "gateway'i nasıl aşar" ve "gateway'in kendisi nasıl saldırı yüzeyi olur" sorularını hiç sormamasıdır. Aşağıda kırmızı takım koltuğundan tespitler.

## 1. Eksikler

**P0 (bunlar olmadan tasarım yanlış veya güvensiz olur)**

- **ICAP'in göremediği trafik listesi.** ProxySG ICAP'e WebSocket upgrade sonrası veriyi, HTTP/2 push'u ve "ICAP max file size" üstündeki gövdeyi vermez; varsayılan davranış fail-open'dır. Brief'e eklenecek: platform başına "ProxySG bunu ICAP'e verebilir mi?" sütunu. Fable'ın sorusu: hangi platform akışı REQMOD ile zorlanabilir, hangisi yalnızca loglanabilir, hangisi hiç görülmez ve bu kör noktalar nasıl kapanır?
- **Bulut tarafında çalışan ajanlar proxy'den geçmez.** Devin, Codex cloud, Copilot coding agent, Claude Code web ve Gemini bulut ajanları kodu GitHub'dan kendi bulutlarına çeker. Proxy yalnızca kullanıcının konsol trafiğini görür. Brief'e eklenecek: bu ürünler için enforcement noktası GitHub/Google/Anthropic tenant ayarlarıdır, gateway değil. Soru: hangi platformlar "kapsam dışı, tenant politikasıyla yönetilir" olarak işaretlenecek?
- **DLP'nin yakaladığı sırları depolamamak.** Prompt yakalama açık olduğunda gateway, tespit ettiği API anahtarlarını ve parolaları prompt deposuna yazar. Depo, kurumun en zengin sır arşivi olur. Soru: tespit edilen sır ve PII, kalıcı yazımdan önce nasıl redakte edilir, yalnızca parmak izi ve sınıf mı saklanır?
- **ICAP kimlik iddiası sahteleme.** X-Authenticated-User başlığı ProxySG'nin iddiasıdır; ICAP portuna erişen herhangi bir istemci kimlik ve log kaydı enjekte edebilir. IP surrogate ile kimlik doğrulayan proxy'de VDI, terminal sunucu ve NAT arkasındaki kullanıcılar birbirine karışır. Soru: Secure ICAP ile mTLS, kaynak IP kısıtı ve "proxy tarafından iddia edildi" güven etiketi nasıl tasarlanır?
- **Kodlama ve parçalama ile DLP aşımı.** Base64, zero-width, homoglif, Unicode tag karakterleri, sıkıştırılmış dosya yükleme, görsel içinde metin, çok sayıda küçük prompta bölme. Soru: normalizasyon ve iç içe kod çözme derinliği, dosya yükleme kanalları, görsel OCR'ın MVP'de olup olmadığı, kullanıcı başına hacim bazlı eşik.
- **Depolanan prompt düşman girdidir.** İnceleme ekranı stored XSS, CSV formül enjeksiyonu, syslog CR/LF ve ANSI enjeksiyonu, ve en önemlisi maskeli görünümü okuyan yapay zeka ajanına yönelik prompt injection taşır. Soru: içerik nasıl inert render edilir, AI tüketicilerine "güvenilmez içerik" çerçevesi nasıl verilir?
- **ReDoS ve parser DoS.** Java regex geri izlemelidir; tek kötü prompt bütün ICAP işçilerini kilitler ve ya tüm AI trafiğini keser ya da fail-open'a düşürür. Olgun Java ICAP kütüphanesi yoktur, parser elle yazılacaktır. Soru: lineer regex motoru, gövde ve sıkıştırma sınırı, zaman aşımı, CI'da fuzz harness.
- **Kapsama metriği.** rwsafe kendi kör noktasını göremez. ProxySG'nin AI alanlarına gördüğü istek sayısı ile gateway'in gördüğü sayı sürekli karşılaştırılmalı; ProxySG fail-open olayları SIEM'e gitmeli. Soru: bu oran nasıl ölçülür ve hangi eşik alarm üretir?
- **SSL interception muafiyet denetimi.** Mevcut bypass listeleri genelde googleapis, github ve M365 alanlarını içerir; bu Gemini, Copilot ve M365 Copilot'u kör bırakır. Kategorilenmemiş yeni AI alanı varsayılan olarak incelenmeli. Soru: phase 0'da salt okunur muafiyet denetimi ve "uncategorised → inspect" kuralı.

**P1**

- **Sertifika güven matrisi istemci başına.** Claude Code NODE_EXTRA_CA_CERTS, JetBrains eklentileri JVM cacerts, Codex CLI Rust kök deposu, Electron masaüstü uygulamaları, mobil uygulamalar. Her satır için CA dağıtım yöntemi ve "pinli, kırılamaz" işareti.
- **Tenant başlığı yetmez.** Başlık yalnızca yeni login'i kısıtlar; önceden alınmış kişisel oturum ve refresh token çalışır. Kişisel API anahtarı ile Claude Code, Bedrock veya Vertex yönlendirmesi, kişisel ANTHROPIC_BASE_URL relay'i org login'i tamamen atlar. Soru: oturum çerezi ve Authorization başlığı seviyesinde tenant doğrulaması, bilinen relay ve toplayıcıların engel listesi.
- **Masked rolde yeniden tanımlama.** Kararlı pseudonym ve sayımlar frekans analizine açıktır; ham değerle filtre izni "üyelik oracle"ı olur. Soru: arama yalnızca maskeli türetilmiş alanlar üzerinde, rwsafe HMAC anahtarı neXus'tan ayrı.
- **Paylaşılan ingress.** Aynı Traefik, ortak üst alan adı. Üst alan adına yazılan çerez diğer ürüne sızar; tanınmayan Host ve ham IP isteği hangi ürüne düşer? Soru: `__Host-` önekli çerez, katı host eşleşmesi, açık 404 default backend, ingress snippet anotasyonları kapalı.
- **LLM gateway açık relay riski.** Kurumsal anahtarı tutan uç nokta en değerli hedeftir. Soru: paylaşılan URL değil, kullanıcı ve cihaza bağlı kısa ömürlü istemci kimliği; SSRF'e kapalı sabit upstream listesi; prompt cache izolasyonu.
- **Ajan kanalı yeni internet yüzüdür.** Cihaz attestation, MDM sertifikasıyla mTLS, imzalı güncelleme, root ayrıcalığının yerel yetki yükseltme riski. Tarayıcı eklentisi için Manifest V3 gövde okuyamaz; yalnızca content script ile fetch kancası mümkündür ve kırılgandır. Soru: MV3 fizibilite spike'ı tasarım teslimatı olmalı.
- **Model ve kural paketi tedarik zinciri.** Hugging Face modelleri pickle taşıyabilir. Soru: safetensors zorunluluğu, imzalı paket, lisans ve köken kaydı.
- **k3s secret şifrelemesi.** Varsayılan k3s, etcd/SQLite'ta secret'ı düz tutar; prompt deposu anahtarı neXus secret'larının yanında durur. Soru: encryption-at-rest açık mı, PSA restricted, hostPath yok, CAP_NET_RAW düşürülmüş.
- **Yanıt tarafı tehdit.** Ajanların çektiği web içeriği ve MCP sunucuları komut çalıştırma yolu açar. Soru: RESPMOD'da injection tespiti yalnızca log mu, blok mu?

**P2**

- Düşük ve yavaş sızdırma için oturum bazlı toplama ve istatistik.
- Kullanıcı başına "AI platformu değiştirme" davranış analizi.
- OpenShift taşınabilirliği; ajan güncellemesi için SBOM.

**Mühendislik oturumunun aday maddeleri**

- Onay: QUIC engeli, yerel sınıflandırıcı, blue/green ICAP, canary prompt, politika simülasyon modu, çift onay ham erişim.
- Keskinleştir: kimlik maddesine sahteleme ve surrogate; shadow-AI maddesine toplayıcı ve relay engeli; tarayıcı eklentisi maddesine MV3 kısıtı; "protocol drift" maddesine "parse hatası sessiz allow değil, karar üretir" kuralı; fail-open maddesine ProxySG tarafında loglama şartı.
- Red: yok. OpenShift P2'ye iner.

## 2. Alınmış kararlardaki riskler ve istenecek önlemler

- **Aynı sunucu.** Container kaçışı iki ürünü de düşürür; ICAP seli CPU'yu neXus'tan çalar. İstenecek: sıkı quota, PSA restricted, ayrı service account ve RBAC denetimi, dedicated IngressRoute, secret şifrelemesi, cross-namespace NetworkPolicy testi CI'da.
- **ICAP inline.** Tek arıza noktası ve şifresi çözülmüş promptların düz metin aktarımı. İstenecek: Secure ICAP, iki replika ve PodDisruptionBudget, ProxySG tarafında ICAP service group, REQMOD zorlama ve RESPMOD yalnızca asenkron yakalama önerisi, boyut aşımı ve zaman aşımında kategori başına açık karar.
- **Gün birden prompt yakalama.** Honeypot etkisi ve içeriden tehdit. İstenecek: sır redaksiyonu yazımdan önce, zarf şifreleme, hash zinciri, KVKK çalışan aydınlatması, BDDK için verinin yurt içinde kaldığının belgelenmesi.
- **Java inline.** GC duraklaması, ReDoS, bellek. İstenecek: lineer regex, Netty veya sanal iş parçacığı, gecikme SLO'su yük testi, Jazzer fuzz CI'da.
- **Reverse proxy değişikliği.** Host karışıklığı ve çerez sızıntısı. İstenecek: `__Host-` çerez, host-only CSP, default backend 404, HSTS, neXus değişikliğinin önce preview'da kanıtı.

## 3. Eksik teslimatlar ve kabul kriterleri

- **Bypass kataloğu.** Her aşma tekniği için beklenen sonuç ve test; pilot kabulü bu testlerin geçmesine bağlı.
- **Kapsama oranı.** Proxy'nin gördüğü / gateway'in gördüğü AI isteği; eşik altı alarm.
- **ICAP fuzz raporu ve parser sağlamlık kriteri.** Chunked, Encapsulated offset, preview, 204 ve boyut uyumsuzluğu vakaları.
- **Tespit değerlendirme raporu.** Kodlama ve parçalama paketi üzerinde yanlış negatif oranı; hedef sayı belirlenmiş.
- **Phase 0 muafiyet denetimi.** ProxySG SSL bypass listesinde AI alanları; salt okunur.
- **Kapsam dışı beyanı.** Bulut ajanları ve pinli istemciler için "gateway bunu göremez" listesi, telafi kontrolüyle.
- **Tehdit modeli ek kapsamı.** "Depolanan prompt düşman girdi" ve "maskeli AI inceleyici hedef" senaryoları STRIDE'a girer.
- **Platform matrisi ek sütunları.** HTTP sürümü, streaming tipi, pinleme, CA güven yöntemi, dosya yükleme kanalı, bulut tarafı çalışma.
- **Pilot öncesi bağımsız sızma testi.** Haftalık ZAP ICAP ve ajan kanalını kapsamaz; protokol fuzz ve ajan tamper testi ayrı teslimat.

