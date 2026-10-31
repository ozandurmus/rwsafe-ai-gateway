# Pilot adımları: size kalanlar (kısa kontrol listesi)

**Durum:** TASLAK (31 Ekim 2026). Ayrıntı, gerekçe ve hata durumları İngilizce `PILOT_RUNBOOK.md` belgesindedir; adım
numaraları ikisinde aynıdır. Bu liste Türkçedir, çünkü Ürün Sahibi ile çalışma dili Türkçedir (AGENTS.md madde 3).

**Kapsam:** Tek bir test kullanıcısının yapay zekâ kategorisindeki istekleri, kurumsal vekil sunucudan (ProxySG) düz
ICAP ile 1344 numaralı kapıya, HOST-A üzerindeki ICAP motoruna gider. Düz ICAP en çok 30 gün sürer (karar Q-28, istisna
H-2). Motor erişilemezse test kullanıcısının isteği reddedilir (kapalı kalma). neXus'a ait hiçbir şeye dokunulmaz.

**Yer tutucular:** Gerçek değerler bu belgeye, sohbete veya depoya hiçbir zaman yazılmaz. `<vekil-adresi-1>`,
`<vekil-adresi-2>`, `<vekil-adresi-3>` üç ProxySG cihazının adresi, `<sunucu-adresi>` HOST-A'nın adresi,
`<ALAN>\<test-kullanıcısı>` test kullanıcısı, `<yapay zekâ kategorisi>` konsolda görünen kategori adıdır.

## Şu ana kadar yapılanlar (düzenleyici ajan)

1-9 arası adımlar yapıldı: ad alanları, görüntüler, gizli anahtarlar, veritabanı ve denetim düzlemi; ICAP motoru küme
içinde çalışıyor. Ajan güvenlik duvarından önce sentetik yoklamayı da kurar (9b adımı, onayınızla): yoklama her 15
dakikada bir küme içinden ICAP motoruna altı uydurma istek gönderir ve bir sonuç beklenenden farklıysa başarısız olur.
Sunucunun 1344 numaralı kapısı henüz kapalıdır.

Acil durum hesabının parolasını (10. adım) henüz almadıysanız kendi terminalinizde `tools/pilot/fetch_break_glass.sh`
komutunu çalıştırın. Ajan bu adımı hiçbir zaman çalıştırmaz ve dosyayı hiçbir zaman okumaz.

## A. Güvenlik duvarı (11. adım, kök yetkisiyle, yalnızca siz)

Sunucuda çalıştırın. Aşağıdaki bloğu olduğu gibi kopyalayın; yalnızca üç `<vekil-adresi-N>` yer tutucusunu gerçek
ProxySG adresleriyle değiştirin (köşeli ayraçlar dahil silinir, adresler virgülle ayrılır). Başka hiçbir şeyi
değiştirmeyin. Blok ürün adını kendisi `~/rwsafe/deploy/rwsafe/product.env` dosyasından okur; `~/rwsafe` klasörü ya da
ürün adı yoksa hiçbir şey yapmadan durur ve ilk hatada kendiliğinden durur. Ayraçlar `(` ve `)` bloğu ayrı bir kabukta
çalıştırır; bir hata olsa da terminaliniz kapanmaz.

```bash
(
set -euo pipefail
cd ~/rwsafe
PRODUCT="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"
case "${PRODUCT}" in
  ""|*[!a-z0-9-]*) echo "durduruldu: ~/rwsafe/deploy/rwsafe/product.env içinde geçerli bir ürün adı yok"; exit 1 ;;
esac
T="${PRODUCT//-/_}_pilot"
sudo nft -f - <<EOF
table inet ${T} {}
flush table inet ${T}
table inet ${T} {
  set icap_clients {
    type ipv4_addr
    flags interval
    elements = { <vekil-adresi-1>, <vekil-adresi-2>, <vekil-adresi-3> }
  }
  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    fib daddr type local tcp dport 1344 ct state new ip saddr != @icap_clients drop
    fib daddr type local meta nfproto ipv6 tcp dport 1344 drop
  }
}
EOF
echo "table ${T} written"
)
```

Bu blok yalnızca `table rwsafe_pilot written` yazar. Ardından tek satırlık denetim (yalnızca okur; istediğiniz zaman
yeniden çalıştırabilirsiniz):

```bash
(set -euo pipefail; cd ~/rwsafe; P="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"; test -n "${P}"; sudo nft -j list table inet "${P//-/_}_pilot" | tools/pilot/verify_firewall.sh --table)
```

Görmeniz gereken: `3 element(s)`, `IPv4 1, IPv6 1, other 0` ve en sonda `result: PASS`. Bu çıktıda hiçbir adres
görünmez. Denetim yalnızca yukarıdaki tablonun birebir aynısını kabul eder: tam üç tek adres (adres aralığı ya da alt ağ
değil), tek zincir ve her alanı ve işleciyle birebir aynı iki kural; fazladan bir kural, zincir ya da ifade de
başarısız sayılır. `FAIL` görürseniz durun, kuralı denetime uydurmak için değiştirmeyin ve yalnızca `FAIL` yazan satırı
iletin. Bloğu ikinci kez çalıştırmak kuralları çoğaltmaz, yalnızca yeniler.

İsterseniz ek olarak kendi bilgisayarınızdan (vekil olmayan bir makineden) `nc -vz -w 3 <sunucu-adresi> 1344` deneyin:
zaman aşımına uğramalıdır. "Connection refused" görürseniz kural bu sunucuda işlemiyor demektir; durun.

Kural kalıcı değildir: sunucu yeniden başlarsa vekil trafik göndermeden önce bu bloğu tekrar çalıştırın.

Geri alma (tek satır, ürün adını aynı biçimde kendisi okur):

```bash
(set -euo pipefail; cd ~/rwsafe; P="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"; test -n "${P}"; sudo nft delete table inet "${P//-/_}_pilot")
```

**Ajana söyleyin:** "Güvenlik duvarı kuruldu: result PASS, 3 element." (Adres yazmayın.) Ajan bunun üzerine
`tools/pilot/verify_firewall.sh` ile küme içi trafiğin hâlâ geçtiğini ve 1344'ün hâlâ kapalı olduğunu doğrular (11.3.
adım), onayınızı alarak 1344'ü açan hizmeti kurar (12. adım) ve pilot denetimini çalıştırır (13. adım). Vekil konsoluna
ancak ajan "1344 açıldı, pilot denetimi PASS" dedikten sonra geçin.

## B. Yönetim arayüzü (14. adım, yalnızca siz girersiniz)

Arayüze, sunucudaki diğer ürüne ulaştığınız yoldan ulaşırsınız: sunucunun Traefik'i üzerinden, bir ad kuralıyla. Henüz
DNS adı yoktur; ad uydurma ve ayrılmış bir addır: `ui.<ürün>.local` (bugün `ui.rwsafe.local`; ürün adı değişirse
kendiliğinden değişir). Sertifika pilotun kendisinindir: sunucuda küçük bir sertifika yetkilisi (CA) üretilir, siz onun
sertifikasına kendi bilgisayarınızda güvenirsiniz. Diğer ürünün Ingress'ine ve sertifikasına dokunulmaz.

Ajan önce (onayınızla) sertifikayı üretir ve Ingress'i uygular (`PILOT_RUNBOOK.md` 14.1-14.3). Size iki satır iletir:
CA sertifikasının yolu (`~/.config/<ürün>/admin-ca/ca.crt`, gizli değildir) ve parmak izi (`CA SHA-256 fingerprint:
AB:CD:...`, 32 çift). CA'nın anahtarı yalnızca sunucuda, yalnızca sizin hesabınızın okuyabileceği bir dosyadadır; kümeye
hiç girmez. Bu CA yalnızca `ui.<ürün>.local` adına sertifika verebilir; ona güvenmeniz başka hiçbir siteye güven vermez.

**1. CA sertifikasını bilgisayarınıza alın** ve parmak izini karşılaştırın:

```bash
scp <yönetici-hesabı>@<sunucu-adresi>:.config/<ürün>/admin-ca/ca.crt ~/Downloads/<ürün>-admin-ca.crt
openssl x509 -in ~/Downloads/<ürün>-admin-ca.crt -noout -fingerprint -sha256      # macOS
```

Windows'ta PowerShell'de önce `cd $HOME/Downloads`, sonra aynı `scp` komutu (hedef `./<ürün>-admin-ca.crt`); parmak
izi için aynı klasörde `certutil -dump .\<ürün>-admin-ca.crt | findstr /i sha256` (`Cert Hash(sha256)` satırı; sertifika
penceresindeki "Thumbprint" SHA-1'dir, bu değer değildir). Parmak izi ajanın ilettiğinden farklıysa durun ve bildirin.

**2. Sertifikaya güvenin.**

- macOS: Anahtar Zinciri Erişimi'ni (Keychain Access) açın, Dosya > Öğeleri İçe Aktar, dosyayı seçin, anahtar zinciri
  **Sistem** (System). İçe aktarılan `<ürün> pilot admin CA` öğesine çift tıklayın, **Güven** (Trust) bölümünde
  **Güvenli Yuva Katmanı (SSL)** için **Her Zaman Güven** (Always Trust) seçin, pencereyi kapatıp parolanızla onaylayın.
  Terminalden aynısı:
  `sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain ~/Downloads/<ürün>-admin-ca.crt`
- Windows: dosyaya çift tıklayın, Sertifika Yükle, **Yerel Makine**, "Tüm sertifikaları aşağıdaki depolama alanına
  yerleştir", Gözat, **Güvenilen Kök Sertifika Yetkilileri** (Trusted Root Certification Authorities), Son. Yönetici
  PowerShell'inden, İndirilenler klasöründe aynısı: `certutil -addstore -f Root .\<ürün>-admin-ca.crt`
- Chrome, Edge ve Safari işletim sisteminin deposunu kullanır. Firefox kendi deposunu kullanır: Ayarlar > Gizlilik ve
  Güvenlik > Sertifikalar > Sertifikaları Göster > Yetkililer > İçe Aktar, "Web sitelerini tanımlamak için bu CA'ya güven"
  kutusunu işaretleyin.

**3. Hosts dosyasına tek satır ekleyin:** `<sunucu-adresi> ui.<ürün>.local`

- macOS: `sudo sh -c 'echo "<sunucu-adresi> ui.<ürün>.local" >> /etc/hosts'`, ardından
  `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
- Windows: Not Defteri'ni **yönetici olarak** açın, `C:\Windows\System32\drivers\etc\hosts` dosyasını açıp satırı ekleyin,
  kaydedin, ardından `ipconfig /flushdns`
- `.local` aynı zamanda çok noktaya yayın DNS'in (Bonjour) alanıdır: macOS'ta `.local` bir adın ilk çözümlemesi birkaç
  saniye bekleyebilir. Hosts satırı yine de kullanılır; ilk açılışın yavaş olması bundandır, üründen değil.

**4. Tarayıcıda `https://ui.<ürün>.local` adresini açın** (Chrome, Edge, Safari ya da Firefox) ve `breakglass` ile,
10. adımdaki parolayla girin. Asma kilitte uyarı olmamalıdır. `http://` ile açarsanız Traefik sizi `https://` adresine
yönlendirir.

Sertifika uyarısı **beklenmez** ve uyarı hiçbir zaman "yine de devam et" ile geçilmez: durun ve yalnızca uyarının sınıfını
bildirin. `NET::ERR_CERT_AUTHORITY_INVALID` (Safari'de "güvenilir değil") CA'ya bu bilgisayarda güvenilmediği anlamına
gelir (2. madde yapılmamış ya da Firefox kendi deposunu kullanıyor). Uyarı başka bir ad gösteriyorsa Traefik kendi
varsayılan (diğer ürünün) sertifikasını sunmuştur; ajan sertifika adımını yeniden çalıştırır. Sayfa güvenilir bağlantıyla
bir kez açıldıktan sonra tarayıcı bu ad için bir yıl boyunca yalnızca güvenilir `https://` kabul eder (HSTS); CA'yı
güven deposundan sonradan silerseniz sayfa o tarayıcıda açılmaz.

**Maskeli rol:** Arayüze yalnızca siz girersiniz. Hiçbir ajan arayüzü açmaz, ekran görüntüsünü görmez, oradan bir değer
almaz. Acil durum oturumu bir operatör oturumudur; ekranların gösterdiği gerçek adları gösterir. Maskeli rol
(`replay_viewer`) pilotta kullanılmaz: kurum sözlüğünde yalnızca bir yer tutucu terim vardır (7. adım), maskeli bir oturum
kurum adlarını henüz maskelemez. Bu rolü biri kullanmadan önce sözlük gerçek terimlerle değiştirilir.

Görmeniz gereken: Politikalar ekranında tohum kuralları (gizli anahtar engelle; kimlik numarası, IBAN ve kart numarası
maskele; zorlama kipi) ve Sağlık ekranında bileşenlerin çalıştığı. `GET /` yalnızca `NOT_FOUND` içeren bir JSON
döndürürse denetim düzlemi görüntüsünde arayüz yoktur; giriş sayfası kendine dönüyorsa da durun ve bildirin.

Sentetik yoklamanın takma adını bir kez bulun: Trafik ekranında son bir saat, platform `gemini`, karar `BLOCK`; her
:00, :15, :30 ve :45'ten sonraki bir dakika içinde bir olay görünür ve kullanıcı sütunu yoklamanın `USR-...` takma adını
gösterir. Bu takma adı not edin (yalnızca kendinize; gerçek bir kişiyi göstermez). Yoklama 15 dakikada bir altı olay
yazar: ikişer izin, maskeleme ve engelleme.

**Yedek yol:** Ingress kullanılamazsa eski yol sunucuda hiçbir şeyi değiştirmeden çalışır: sunucuda
`kubectl -n "${PRODUCT}" port-forward "svc/${PRODUCT}-control" 18080:8080 --address 127.0.0.1`, kendi bilgisayarınızda
`ssh -N -L 18080:127.0.0.1:18080 <yönetici-hesabı>@<sunucu-adresi>`, sonra Chrome, Edge ya da Firefox ile
`http://localhost:18080` (Safari `localhost` üzerinde `Secure` çerezi tutmaz). `ssh -L` "administratively prohibited"
derse durun ve bildirin: sunucuda başka bir aktarma yolu kurulmaz.

**Sonra:** Gerçek bir DNS adı ve kurumsal sertifika ayrı ve küçük bir değişikliktir (`PILOT_RUNBOOK.md` 14. adım,
"Later"); o zaman hosts satırını ve pilot CA'yı güven deponuzdan silersiniz (macOS: Anahtar Zinciri Erişimi, Sistem,
`<ürün> pilot admin CA`, Sil; Windows: `certlm.msc`, Güvenilen Kök Sertifika Yetkilileri).

**Ajana söyleyin:** "Arayüze girildi, politikalar ve sağlık tamam." Bir şey ters giderse yalnızca ekrandaki hata
sınıfını söyleyin (örnek metin, adres ya da ekran görüntüsü değil; örneğin "ERR_CERT_AUTHORITY_INVALID", "NOT_FOUND",
"giriş sayfasına dönüyor" ya da "parmak izi farklı").

## C. Vekil konsolu (15, 16 ve 17. adımlar, yalnızca siz)

Menü yolları ve seçenek adları SGOS 7.4 için doğrulanmadı; ekran farklıysa en yakın karşılığı kullanın ve farkı not edin.

### C1. ICAP hizmeti (15. adım)

Configuration > Content Analysis > ICAP > ICAP Services altında yeni bir hizmet açın:

| Alan | Değer |
|---|---|
| Ad (Name) | `rwsafe-pilot-reqmod` |
| Hizmet adresi (Service URL) | `icap://<sunucu-adresi>:1344/reqmod-ai` |
| Yöntem (Method) | yalnızca istek değiştirme (REQMOD) |
| Güvenli ICAP (Secure ICAP) | kapalı |
| Ön izleme (Preview) | açık, 4096 bayt ("Sense settings" bu değeri motordan okur) |
| Gönderilecek bilgiler | istemci adresi (X-Client-IP) ve kimliği doğrulanmış kullanıcı (X-Authenticated-User); gruplar gönderilmez |
| En çok bağlantı sayısı | 20 |
| En büyük nesne boyutu | 4 mebibayttan büyük; aşılırsa isteği reddet (deny) |
| Sağlık denetimi (Health check) | açık, 5 saniyede bir |

Görmeniz gereken: hizmetin sağlık denetimi "sağlıklı" (healthy). Bu adımda henüz hiçbir kullanıcının trafiği gönderilmez.

**Ajana söyleyin:** "ICAP hizmeti kuruldu, sağlık denetimi sağlıklı." Sağlıksızsa: "ICAP hizmeti sağlıksız" deyin ve
16. adıma geçmeyin.

### C2. Test kullanıcısının tek kuralı, kapalı kalma (16. adım)

Ön koşul: test kullanıcısı için yapay zekâ kategorisinde şifreli bağlantıların araya girilerek açılması (SSL
interception) açıktır; açık değilse vekil isteğin içeriğini ICAP'e veremez.

Visual Policy Manager'da `rwsafe pilot` adlı yeni bir Web Access katmanı ekleyin; içine yalnızca şu kural girer:

| Sütun | Değer |
|---|---|
| Kaynak (Source) | yalnızca kullanıcı nesnesi `<ALAN>\<test-kullanıcısı>` |
| Hedef (Destination) | kategori `<yapay zekâ kategorisi>` |
| Eylem (Action) | "Set ICAP Request Service": `rwsafe-pilot-reqmod`; hizmet erişilemezse ya da hata verirse "Deny the client request" (kapalı kalma) |
| İz (Track) | yok |

İlkeyi yükleyin (Install Policy). Başka hiçbir kullanıcı bu kurala uymaz; onların trafiği değişmez. Düz ICAP'in 30
günlük süresi ilk trafikle başlar.

**Ajana söyleyin:** "Kural yüklendi, tarih: <gün.ay.yıl>." (Kullanıcı adı yazmayın.)

### C3. Deneme (17. adım)

1. Uydurma bir kimlik numarası üretin (gerçek değildir, hiçbir yere kaydedilmez):
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_tckn(random.SystemRandom()))'`.
   Test kullanıcısı bunu içeren bir istemi `chatgpt.com` ya da `claude.ai` sitesine gönderir ve numarayı tekrarlamasını
   ister. Başarı: site numara yerine `[REDACTED:TCKN]` almıştır.
2. Uydurma bir bulut anahtarı üretin:
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_cloud_key(random.SystemRandom()))'`.
   Test kullanıcısı bunu içeren bir istem gönderir. Başarı: tarayıcıda Türkçe engelleme sayfası çıkar, istek siteye
   ulaşmaz.

3. Yönetim arayüzünün Trafik ekranında (B bölümü) denemenin bir `REDACT` ve bir `BLOCK` olayını bulun. Bu iki olayın
   kullanıcı sütunundaki `USR-...` takma adı test kullanıcısınınki olmalıdır, B bölümünde not ettiğiniz yoklamanınki
   değil: yoklama da her 15 dakikada `claude` sitesine maskeleme ve `openai` sitesine engelleme olayı yazar.

**Ajana söyleyin:** "Kimlik numarası maskelendi: evet ya da hayır. Anahtar engellendi: evet ya da hayır. İki olay
yoklamanınkinden farklı bir takma adın altında: evet ya da hayır." (Takma adı yazmanız gerekmez.) Ajan sentetik
yoklamanın sonuçlarını ve olay sayılarını denetler.

### Tek adımda geri alma

Bir sorun görürseniz önce bunu yapın: 16. adımdaki kuralı kapatın (ya da silin) ve ilkeyi yükleyin. Test kullanıcısının
yapay zekâ trafiği hemen eskisi gibi doğrudan gider. Kural açıkken motor çalışmazsa test kullanıcısının yapay zekâ
istekleri reddedilir; bu tasarım gereğidir.

**Ajana söyleyin:** "Kural kapatıldı." Pilotun tamamını kaldırmak (18. adım) ayrıca konuşulur; her silme ayrıca
onaylanır ve güvenlik duvarı tablosunu yalnızca siz silersiniz.
