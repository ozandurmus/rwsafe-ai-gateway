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

Sunucuda, diğer adımlarda kullanılan `~/rwsafe` klasöründe çalıştırın. Aşağıdaki bloğu olduğu gibi kopyalayın; yalnızca
üç `<vekil-adresi-N>` yer tutucusunu gerçek ProxySG adresleriyle değiştirin (köşeli ayraçlar dahil silinir, adresler
virgülle ayrılır). Başka hiçbir şeyi değiştirmeyin.

```bash
cd ~/rwsafe
PRODUCT="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"
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
```

Bu blok hiçbir şey yazmadan biter. Ardından tek satırlık denetim:

```bash
sudo nft -j list table inet "${T}" | tools/pilot/verify_firewall.sh --table
```

Görmeniz gereken: `3 element(s)` ve en sonda `result: PASS`. Bu çıktıda hiçbir adres görünmez. `FAIL` görürseniz durun ve
yalnızca `FAIL` yazan satırı iletin. Bloğu ikinci kez çalıştırmak kuralları çoğaltmaz, yalnızca yeniler.

İsterseniz ek olarak kendi bilgisayarınızdan (vekil olmayan bir makineden) `nc -vz -w 3 <sunucu-adresi> 1344` deneyin:
zaman aşımına uğramalıdır. "Connection refused" görürseniz kural bu sunucuda işlemiyor demektir; durun.

Kural kalıcı değildir: sunucu yeniden başlarsa vekil trafik göndermeden önce bu bloğu tekrar çalıştırın.

Geri alma (tek satır): `sudo nft delete table inet "${T}"`

**Ajana söyleyin:** "Güvenlik duvarı kuruldu: result PASS, 3 element." (Adres yazmayın.) Ajan bunun üzerine
`tools/pilot/verify_firewall.sh` ile küme içi trafiğin hâlâ geçtiğini ve 1344'ün hâlâ kapalı olduğunu doğrular (11.3.
adım), onayınızı alarak 1344'ü açan hizmeti kurar (12. adım) ve pilot denetimini çalıştırır (13. adım). Vekil konsoluna
ancak ajan "1344 açıldı, pilot denetimi PASS" dedikten sonra geçin.

## B. Vekil konsolu (15, 16 ve 17. adımlar, yalnızca siz)

Menü yolları ve seçenek adları SGOS 7.4 için doğrulanmadı; ekran farklıysa en yakın karşılığı kullanın ve farkı not edin.

### B1. ICAP hizmeti (15. adım)

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

### B2. Test kullanıcısının tek kuralı, kapalı kalma (16. adım)

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

### B3. Deneme (17. adım)

1. Uydurma bir kimlik numarası üretin (gerçek değildir, hiçbir yere kaydedilmez):
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_tckn(random.SystemRandom()))'`.
   Test kullanıcısı bunu içeren bir istemi `chatgpt.com` ya da `claude.ai` sitesine gönderir ve numarayı tekrarlamasını
   ister. Başarı: site numara yerine `[REDACTED:TCKN]` almıştır.
2. Uydurma bir bulut anahtarı üretin:
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_cloud_key(random.SystemRandom()))'`.
   Test kullanıcısı bunu içeren bir istem gönderir. Başarı: tarayıcıda Türkçe engelleme sayfası çıkar, istek siteye
   ulaşmaz.

**Ajana söyleyin:** "Kimlik numarası maskelendi: evet ya da hayır. Anahtar engellendi: evet ya da hayır." Ajan yönetim
arayüzündeki olayları ve sentetik yoklamanın sonuçlarını denetler. Yoklamanın olayları Trafik ekranında tek bir sabit
`USR-...` takma adı altında görünür; test kullanıcısının olayları başka bir takma adın altındadır.

### Tek adımda geri alma

Bir sorun görürseniz önce bunu yapın: 16. adımdaki kuralı kapatın (ya da silin) ve ilkeyi yükleyin. Test kullanıcısının
yapay zekâ trafiği hemen eskisi gibi doğrudan gider. Kural açıkken motor çalışmazsa test kullanıcısının yapay zekâ
istekleri reddedilir; bu tasarım gereğidir.

**Ajana söyleyin:** "Kural kapatıldı." Pilotun tamamını kaldırmak (18. adım) ayrıca konuşulur; her silme ayrıca
onaylanır ve güvenlik duvarı tablosunu yalnızca siz silersiniz.
