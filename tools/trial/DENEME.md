# rwsafe yerel deneme: adım adım

Bu deneme, ürünün çalıştığını kendi bilgisayarınızda görmeniz içindir. Her şey yalnızca bu bilgisayarda (127.0.0.1)
çalışır; gerçek bir yapay zekâ sağlayıcısına, kurum ağına ya da internete hiçbir şey gönderilmez. Örneklerdeki kimlik
numarası, banka hesap numarası ve gizli anahtar her başlatmada yeniden üretilen sahte değerlerdir.

## 1. Başlatma

Depo klasöründe bir terminal açıp şunu çalıştırın:

```bash
tools/trial/run_trial.sh
```

Komut altı adımı sırayla yazar (derleme, denetim merkezi, denetim motoru, yönetim arayüzü, sahte sağlayıcı, sohbet
sayfası). İlk çalıştırma birkaç dakika sürebilir. Sonunda "Deneme hazır." ve iki adres görünür:

- Sohbet sayfası: http://127.0.0.1:8765/
- Yönetim arayüzü: http://127.0.0.1:5173/

Bir adım başarısız olursa komut hangi adımın durduğunu, hangi günlük dosyasına bakılacağını ve günlüğün son satırlarını
yazar. Günlükler `tools/trial/.run/` klasöründedir.

## 2. Sohbet sayfasında dört deneme

Sohbet sayfasını tarayıcıda açın. "Örnekler" satırındaki bir düğmeye basınca metin kutuya yazılır; "Gönder" ile
gönderin. Kutuya kendi metninizi de yazabilirsiniz. Her gönderimde sayfanın üstüne üç sütunlu yeni bir kart eklenir:
"Sizin yazdığınız", "Karar" ve "Sağlayıcıya ulaşan".

| Örnek | "Karar" sütununda | "Sağlayıcıya ulaşan" sütununda |
|---|---|---|
| Sade bir soru | yeşil "İzin verildi": metinde hassas bilgi bulunmadı | "Sağlayıcıya ulaşan metin:" ve ardından yazdığınız metnin aynısı |
| Kimlik numarası içeren soru | turuncu "Maskelendi": kimlik numarası maskelendi | aynı metin, yalnızca kimlik numarasının yerinde `[REDACTED:TCKN]` |
| Banka hesap numarası içeren soru | turuncu "Maskelendi": banka hesap numarası maskelendi | aynı metin, hesap numarasının yerinde `[REDACTED:IBAN]` |
| Gizli anahtar içeren soru | kırmızı "Engellendi": gerekçe gizli anahtar veya parola, bir kayıt numarası ve "Bu kararı yönetim arayüzünde aç" bağlantısı | "Sağlayıcıya hiçbir şey gönderilmedi." |

Engellenen istekte kartın altında, kullanıcının göreceği engelleme yanıtı da gösterilir. Programlama arayüzü
istemcisine giden yanıt kısa bir metindir. "Tarayıcı isteği gibi gönder" kutusunu işaretleyip yeniden gönderirseniz
çalışanın tarayıcısında açılacak Türkçe engelleme sayfasını görürsünüz.

"Sizin yazdığınız" sütunundaki "Sağlayıcıya gidecek istek" bölümünü açarsanız vekil sunucunun denetim motoruna verdiği
isteği (sağlayıcının sohbet adresi ve gövdesi) görürsünüz. "Sağlayıcıya ulaşan" sütunundaki açılır bölüm, sahte
sağlayıcının aldığı gövdenin kendisidir.

## 3. Kararı yönetim arayüzünde bulma

1. Yönetim arayüzünü açın. Kullanıcı adı `synthetic-admin`; parolası `java/control/build/dev/credentials.txt`
   dosyasında, aynı satırdadır (her başlatmada yenilenir).
2. Sol menüden "Trafik" ekranına geçin. "Platform" süzgecinde "OpenAI / ChatGPT" seçin. Gönderdiğiniz dört istek en
   üstte, en yenisi başta olmak üzere görünür: "Engellendi", "Maskelendi", "Maskelendi", "İzin verildi". Alttaki
   satırlar, denetim merkezinin başlangıçta ürettiği örnek olaylardır.
3. "Bulgular" sütununda yalnızca bulunan bilgi türü ve sayısı görünür (kimlik numarası için `TCKN ×1`, hesap numarası için `TR IBAN ×1`, gizli anahtar için
   `Gizli anahtar ×1`);
   metnin kendisi hiçbir yerde saklanmaz ve gösterilmez.
4. Bir satıra basınca olay ayrıntısı açılır: karar, gerekçe, kullanıcı takma adı (`USR-` ile başlar; gerçek ad değil),
   maskeli istemci alt ağı (127.0.0.1 değil, maskelenmiş bir etiket), karar süresi, gövde boyutu, politika anlık
   görüntüsünün sürümü ve olay kimliği. Engellenen istekte "Olay kimliği", sohbet sayfasındaki kayıt numarasıyla
   aynıdır; sohbet sayfasındaki bağlantı doğrudan bu ayrıntıyı açar.

## 4. Aynı olayı maskeli kullanıcıyla görme

1. Sağ üstteki kullanıcı menüsünden "Çıkış yap" ile çıkın (ya da başka bir tarayıcı profili kullanın).
2. `synthetic-aiview` kullanıcısıyla, parolası yine `credentials.txt` dosyasında olmak üzere giriş yapın.
3. Her sayfanın üstünde "Maskeli görünüm" etiketi görünür: bu oturumun her yanıtı sunucudaki maskeleme hunisinden
   geçer. Yapay zekâ ajanları ve denetçiler ürünü bu rolle görür.
4. "Trafik" ekranında aynı dört olay aynı kararlarla görünür. Kullanıcı yalnızca `USR-` takma adıyla, istemci yalnızca
   maskeli alt ağ etiketiyle görünür; gerçek bir ad ya da adres bu rolde hiçbir zaman gösterilmez.

## 5. Durdurma

```bash
tools/trial/stop_trial.sh
```

Komut her bileşeni sırayla durdurur ve hangisinin durduğunu yazar. Denetim motoru son olaylarını denetim merkezine
gönderdikten sonra kapanır. Yeniden başlatmak için `tools/trial/run_trial.sh` yeterlidir; veritabanı korunur, giriş
parolaları yenilenir.
