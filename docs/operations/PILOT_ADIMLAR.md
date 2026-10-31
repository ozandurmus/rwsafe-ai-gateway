# Pilot adımları (kısa kontrol listesi)

**Durum:** TASLAK (31 Ekim 2026). Ayrıntı, gerekçe ve hata durumları İngilizce `PILOT_RUNBOOK.md` belgesindedir; adım
numaraları ikisinde aynıdır. Bu liste Türkçedir, çünkü Ürün Sahibi ile çalışma dili Türkçedir (AGENTS.md madde 3).

**Kapsam:** Tek bir test kullanıcısının yapay zekâ kategorisindeki istekleri, kurumsal vekil sunucudan (ProxySG) düz
ICAP ile 1344 numaralı kapıya, HOST-A üzerindeki ICAP motoruna gider. Düz ICAP en çok 30 gün sürer (karar Q-28, istisna
H-2) ve istek değiştirme hizmeti erişilemezse istek reddedilir (kapalı kalma). neXus'a ait hiçbir şeye dokunulmaz.

**Yer tutucular:** Gerçek değerler bu belgeye, sohbete veya depoya hiçbir zaman yazılmaz. `<sunucu-adresi>` HOST-A'nın
adresi, `<vekil-adresi-1>` ile `<vekil-adresi-3>` arası üç ProxySG cihazının adresi, `<ALAN>\<test-kullanıcısı>` test
kullanıcısı, `<yapay zekâ kategorisi>` konsolda görünen kategori adı, `<yönetici-hesabı>` sizin SSH hesabınızdır.

**Kim çalıştırır** (karar Q-45, `PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md`, onaylı): "SUNUCU DEĞİŞİKLİĞİ"
yazan her adımı siz ya da düzenleyici ajan çalıştırır. Ajan her adımdan önce adımı sohbette tek satırla söyler ve sizin o
adım için onayınızı bekler; iki değişikliği tek onayla yapmaz, silme adımlarını ayrıca sorar ve yalnızca maskelenmiş
sonucu bildirir. Her `kubectl` sunucudaki kullanıcının kendi yetkisiyle çalışır, hiçbir zaman `sudo` ile değil; betikler
`sudo` içeren bir `KUBECTL` değerini reddeder. **Yalnızca siz:** 10. adım (acil durum parolası: ajan bu adımı hiç
çalıştırmaz ve dosyasını hiç okumaz), kök yetkisi isteyen 11. adım ve vekil konsolu adımları (15, 16, 17). "OKUMA" yazan
adımları herkes onaysız çalıştırabilir.

**Her adımdan önce:** Kilit dosyası `~/.locks/hosta-build.lock` alınmış olsun; 00:00-00:20, 06:00-06:20, 12:00-12:20,
18:00-18:20 ve 02:00-02:59 (İstanbul saati) arasında çalışmayın; `df -h /` kök dosya sisteminin yüzde 85'in altında
olduğunu göstersin.

## 1. Hazırlık (OKUMA)

```bash
cd ~/rwsafe && git fetch -q && git checkout --detach origin/main && git log --oneline -1
export PRODUCT="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"; echo "urun ${PRODUCT}"
mkdir -p ~/pilot && chmod 0700 ~/pilot
kubectl get namespace "${PRODUCT}" "${PRODUCT}-build" "${PRODUCT}-security" 2>&1 | grep -c NotFound
ss -ltn 'sport = :1344' | tail -n +2 | wc -l
python3 -B tools/deploy/test_manifest_check.py 2>&1 | tail -1
python3 -B tools/pilot/test_render.py 2>&1 | tail -1
python3 -B tools/deploy/manifest_check.py --overlay deploy/rwsafe/overlays/pilot --product "${PRODUCT}" | tail -1
```

Görmeniz gereken: `urun rwsafe`, `3`, `0`, `OK`, `OK`, `manifest check PASS`. `kubectl` komutlarının başına hiçbir
zaman `sudo` yazılmaz.

## 2. SUNUCU DEĞİŞİKLİĞİ: ad alanları ve yalıtım nesneleri

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" \
  --kinds Namespace,PriorityClass,ResourceQuota,LimitRange --output ~/pilot/isolation.json
kubectl apply --server-side -f ~/pilot/isolation.json
```

Görmeniz gereken: 12 nesne için `serverside-applied` (üç ad alanı, üç öncelik sınıfı, üç kota, üç sınır).

## 3. SUNUCU DEĞİŞİKLİĞİ: derleme ayarları

Önce `~/.config/${PRODUCT}/build-proxy.env` dosyasına vekil ayarlarını dört satır olarak yazın (`HTTP_PROXY`,
`HTTPS_PROXY`, `NO_PROXY`, `GRADLE_OPTS`; ayrıntı kılavuzun 3. adımında) ve izinlerini `chmod 0600` yapın. Dosyada hiçbir
zaman kullanıcı adı ya da parola bulunmaz (`kullanıcı:parola@` biçimi, `proxyUser`, `proxyPassword`); betik bunları
reddeder. Vekil yoksa dört anahtar boş değerle yazılır. Dosyayı ekrana basmayın.

```bash
tools/pilot/build_config.sh --check
tools/pilot/build_config.sh
```

Görmeniz gereken: `proxy settings: valid (values not shown)` ve üç `stored configmap` satırı. Bir ret yalnızca kuralın ve
anahtarın adını söyler, değeri asla göstermez.

## 4. SUNUCU DEĞİŞİKLİĞİ: derleme bağlamı

```bash
python3 -B tools/pilot/render.py --target build --product "${PRODUCT}" --output ~/pilot/build.json
kubectl apply --server-side -f ~/pilot/build.json -l "app.kubernetes.io/name in (${PRODUCT}-build-context,${PRODUCT}-build-context-loader)"
kubectl -n "${PRODUCT}-build" wait --for=condition=Ready "pod/${PRODUCT}-build-context-loader" --timeout=180s
git archive --format=tar HEAD java deploy/images | kubectl -n "${PRODUCT}-build" exec -i "${PRODUCT}-build-context-loader" -- sh -c 'rm -rf /workspace/src && mkdir /workspace/src && tar -xf - -C /workspace/src --no-same-owner'
kubectl -n "${PRODUCT}-build" exec -i "${PRODUCT}-build-context-loader" -- sh -c 'cat > /workspace/src/deploy/images/ca/host-bundle.pem' < /etc/ssl/certs/ca-certificates.crt
kubectl -n "${PRODUCT}-build" delete pod "${PRODUCT}-build-context-loader" --wait=true
```

Görmeniz gereken: `4 objects`, `condition met`, en sonda `pod ... deleted`.

## 5. SUNUCU DEĞİŞİKLİĞİ: veri düzlemi görüntüsünü derleme

```bash
kubectl apply --server-side -f ~/pilot/build.json -l "app.kubernetes.io/name=${PRODUCT}-build-dataplane"
kubectl -n "${PRODUCT}-build" wait --for=condition=complete "job/${PRODUCT}-build-dataplane" --timeout=45m
kubectl -n "${PRODUCT}-build" get pod -l "job-name=${PRODUCT}-build-dataplane" -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.message}' > ~/pilot/dataplane.digest
grep -cE '^sha256:[0-9a-f]{64}$' ~/pilot/dataplane.digest
```

Görmeniz gereken: 5 ile 15 dakika sonra `condition met`, ardından `1`. Başarısız olursa ajan ham günlüğü okumaz,
yalnızca hata sınıflarını sayar (kılavuzun 5. adımındaki komut); ham günlüğü yalnızca siz okursunuz.

## 6. SUNUCU DEĞİŞİKLİĞİ: denetim düzlemi görüntüsünü derleme

```bash
kubectl apply --server-side -f ~/pilot/build.json -l "app.kubernetes.io/name=${PRODUCT}-build-control"
kubectl -n "${PRODUCT}-build" wait --for=condition=complete "job/${PRODUCT}-build-control" --timeout=45m
kubectl -n "${PRODUCT}-build" get pod -l "job-name=${PRODUCT}-build-control" -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.message}' > ~/pilot/control.digest
grep -cE '^sha256:[0-9a-f]{64}$' ~/pilot/control.digest
```

Görmeniz gereken: `condition met`, ardından `1`.

## 7. SUNUCU DEĞİŞİKLİĞİ: gizli anahtarlar ve yerel ayarlar

```bash
tools/pilot/bootstrap_secrets.sh --plan
tools/pilot/bootstrap_secrets.sh
```

Görmeniz gereken: önce "5 to create", sonra beş `created` satırı ve `no value was printed`. Hiçbir değer ekrana basılmaz.
Kurum sözlüğünde yalnızca uydurma bir yer tutucu terim vardır; maskeli rol kullanılmadan önce gerçek terimlerle
değiştirilir (kılavuzun 7. adımı).

## 8. İş yüklerini hazırlama ve denetleme (OKUMA)

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" --dataplane-digest "$(cat ~/pilot/dataplane.digest)" --control-digest "$(cat ~/pilot/control.digest)" --output ~/pilot/app.json
python3 -B tools/deploy/manifest_check.py --rendered ~/pilot/app.json --release --product "${PRODUCT}" | tail -1
```

Görmeniz gereken: `38 objects` ve `manifest check PASS: 38 objects, 3 workloads, 0 failure(s)`.

## 9. SUNUCU DEĞİŞİKLİĞİ: veritabanı ve denetim düzlemi

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" --phase control --dataplane-digest "$(cat ~/pilot/dataplane.digest)" --control-digest "$(cat ~/pilot/control.digest)" --output ~/pilot/app-control.json
kubectl apply --server-side -f ~/pilot/app-control.json
kubectl -n "${PRODUCT}" rollout status "statefulset/${PRODUCT}-db" --timeout=10m
kubectl -n "${PRODUCT}" rollout status "deploy/${PRODUCT}-control" --timeout=10m
```

Görmeniz gereken: iki kez `successfully rolled out`. ICAP motoru ve sunucuda 1344'ü açan hizmet bu adımda kurulmaz;
ayrımı hazırlama aracı yapar ve sınamalar bunu kanıtlar.

## 10. YALNIZCA SİZ: acil durum hesabının parolası

Ajan bu adımı hiçbir zaman çalıştırmaz ve yazdığı dosyayı hiçbir zaman okumaz. Betik etkileşimli bir terminal olmadan
çalışmayı reddeder; kendi terminalinizde çalıştırın.

```bash
tools/pilot/fetch_break_glass.sh
```

Görmeniz gereken: `written: ~/.config/rwsafe/pilot/break-glass-initial-password (mode 0600)` ve `removed the copy in the
control plane's PVC` (kapsayıcıdaki kopya silinir, tek kopya sizin ev dizininizde kalır). Hesap adı `breakglass`'tır.
Parolayı yalnızca kendi terminalinizde okuyun, hiçbir yere yapıştırmayın.

## 11. SUNUCU DEĞİŞİKLİĞİ (kök yetkisi, yalnızca siz): 1344 için güvenlik duvarı

Üç vekil adresini yalnızca sunucuda yazın. Kural ayrı bir tabloya eklenir; neXus'un tablosuna dokunulmaz.

```bash
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
sudo nft list table inet "${T}" | sh tools/hosta/mask.sh | grep -c '<ip>'
```

Görmeniz gereken: ilk komut sessiz biter, ikincisi `3` yazar. Yeniden çalıştırmak kuralları çoğaltmaz. Kural yalnızca
sunucunun kendi adreslerine gelen yeni bağlantıları süzer (`fib daddr type local`): kapsayıcılar arasındaki trafik, ICAP
motoruna giden iç yönlendirme dahil, hiç etkilenmez; 13. adım bunu iki yönden kanıtlar. Kural kalıcı değildir: sunucu
yeniden başlarsa vekil trafik göndermeden önce bu adımı tekrarlayın.

## 12. SUNUCU DEĞİŞİKLİĞİ: ICAP motoru (sunucuda 1344 açılır)

```bash
kubectl apply --server-side -f ~/pilot/app.json
kubectl -n "${PRODUCT}" rollout status "deploy/${PRODUCT}-icap" --timeout=10m
```

Görmeniz gereken: `successfully rolled out`.

## 13. Pilot denetimi (OKUMA)

```bash
tools/pilot/check_pilot.sh
```

Görmeniz gereken: her satırda `ok`, `icap options ok status 200, Methods REQMOD, Preview 4096, Allow 204` ve en sonda
`result: PASS`. Ardından güvenlik duvarını iki yönden doğrulayın:

1. Vekil olmayan bir makineden (kendi bilgisayarınız) `nc -vz -w 3 <sunucu-adresi> 1344` zaman aşımına uğramalıdır.
   "Connection refused" ya da "succeeded" görürseniz kural bu sunucuda eşleşmiyor demektir; durun.
2. ICAP kapsülleri `/ready 200` gösterir ve 15. adımdan sonra vekilin sağlık denetimi "sağlıklı"dır. Kapsüller hazırken
   sağlık denetimi başarısızsa tabloyu silin (`sudo nft delete table inet "${T}"`) ve bildirin: kural iç trafiği
   yakalamıştır.

## 14. Yönetim arayüzü (OKUMA)

Sunucuda (açık bırakın):

```bash
kubectl -n "${PRODUCT}" port-forward "svc/${PRODUCT}-control" 18080:8080 --address 127.0.0.1
```

Kendi bilgisayarınızda: `ssh -N -L 18080:127.0.0.1:18080 <yönetici-hesabı>@<sunucu-adresi>`, sonra tarayıcıda
`http://localhost:18080` adresini açıp `breakglass` ile girin. Görmeniz gereken: Politikalar ekranında tohum kuralları
(gizli anahtar engelle; kimlik numarası, IBAN ve kart numarası maskele; zorlama kipi) ve Sağlık ekranında bileşenlerin
çalıştığı.

## 15. VEKİL DEĞİŞİKLİĞİ (yalnızca siz, ProxySG konsolu): ICAP hizmeti

Configuration > Content Analysis > ICAP > ICAP Services altında yeni hizmet (menü yolları SGOS 7.4 için doğrulanmadı):
ad `rwsafe-pilot-reqmod`; adres `icap://<sunucu-adresi>:1344/reqmod-ai`; yalnızca istek değiştirme; güvenli ICAP kapalı;
ön izleme açık ve 4096 bayt ("Sense settings" bunu motordan okur); istemci adresi ve kimliği doğrulanmış kullanıcı
gönderilsin, gruplar gönderilmesin; en çok 20 bağlantı; en büyük nesne 4 MiB'tan büyük ve aşılırsa reddet; sağlık
denetimi 5 saniyede bir.

Görmeniz gereken: hizmetin sağlık denetimi "sağlıklı" görünür. Bu adımda henüz hiçbir kullanıcının trafiği gönderilmez.
Düz ICAP'in 30 günlük süresi ilk trafikle başlar; o tarihi not edin.

## 16. VEKİL DEĞİŞİKLİĞİ (yalnızca siz, ProxySG konsolu): test kullanıcısının kuralı

Ön koşul: test kullanıcısı için yapay zekâ kategorisinde SSL araya girme açıktır. Visual Policy Manager'da `rwsafe pilot`
adlı tek bir Web Access katmanı ve içinde tek bir kural ekleyin: kaynak yalnızca `<ALAN>\<test-kullanıcısı>`, hedef
`<yapay zekâ kategorisi>`, eylem "Set ICAP Request Service: rwsafe-pilot-reqmod" ve hizmet erişilemezse "Deny the client
request" (kapalı kalma). İlkeyi yükleyin.

Görmeniz gereken: başka hiçbir kullanıcının trafiği değişmez.

## 17. Vekilde doğrulama ve başarı ölçütleri

1. Test kullanıcısıyla sınırlı ilke izlemesinde, bir yapay zekâ isteğine `rwsafe-pilot-reqmod` hizmetinin uygulandığı
   görünür; başka bir kullanıcının isteğinde görünmez.
2. Uydurma bir kimlik numarası üretin (gerçek değildir, hiçbir yere kaydedilmez):
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_tckn(random.SystemRandom()))'`.
   Test kullanıcısı bunu içeren bir istemi tohum listesindeki bir siteye (örneğin `chatgpt.com`) gönderir ve numarayı
   tekrarlamasını ister. Başarı: site numara yerine `[REDACTED:TCKN]` almıştır.
3. Uydurma bir bulut anahtarı üretin:
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_cloud_key(random.SystemRandom()))'`.
   Test kullanıcısı bunu içeren bir istem gönderir. Başarı: tarayıcıda Türkçe engelleme sayfası çıkar, istek siteye
   ulaşmaz.
4. Yönetim arayüzünün Trafik ekranında bir `REDACT` ve bir `BLOCK` olayı görünür; kullanıcı adı değil `USR-...` takma adı
   görünür. `tools/pilot/check_pilot.sh` artık olayları sayar.
5. neXus'a dokunulmadı: bütün nesneler ürünün üç ad alanında ya da `rwsafe-` ile başlayan öncelik sınıflarındadır; tek
   sunucu değişikliği `rwsafe_pilot` güvenlik duvarı tablosudur; neXus arayüzü her zamanki gibi çalışır.
6. Vekil tarafını tek adımda geri almak için 16. adımdaki kuralı kapatın (ya da silin) ve ilkeyi yükleyin. Bir sorun
   görürseniz önce bunu yapın. Kural açıkken motor çalışmazsa test kullanıcısının yapay zekâ istekleri reddedilir; bu
   tasarım gereğidir.

## 18. Pilotun tamamını geri alma

```bash
kubectl delete namespace "${PRODUCT}" "${PRODUCT}-build" "${PRODUCT}-security" --ignore-not-found=true --wait=true
kubectl delete priorityclass "${PRODUCT}-dataplane" "${PRODUCT}-control" "${PRODUCT}-batch" --ignore-not-found=true
sudo nft delete table inet "${PRODUCT//-/_}_pilot" 2>/dev/null || echo "guvenlik duvari tablosu zaten yok"
find ~/pilot -type f -exec shred -u {} + 2>/dev/null; rmdir ~/pilot 2>/dev/null
find "${HOME}/.config/${PRODUCT}/pilot" -type f -exec shred -u {} + 2>/dev/null; true
```

Önce vekildeki kuralı ve ICAP hizmetini konsoldan kaldırın. Her silme satırı ayrıca onaylanır; hangi adımlar yapılmış
olursa olsun hata vermeden çalışır. Güvenlik duvarı satırını ve parola dosyasını yalnızca siz silersiniz. Görmeniz gereken: ad alanları ve öncelik sınıfları silinir,
`ss -ltn 'sport = :1344'` hiçbir şey göstermez. Paylaşılan iç kayıt defterinde iki görüntü deposu
(`rwsafe-dataplane`, `rwsafe-control`) kalır; neXus'un hiçbir şeyine dokunulmaz.
