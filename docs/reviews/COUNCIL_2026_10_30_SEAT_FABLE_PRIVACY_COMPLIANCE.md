<!-- Fable council seat 'privacy-compliance', 2026-10-30T09:25:48, exit 0; unaltered output -->

**Koltuk: privacy-compliance.** Brief'i KVKK, BDDK ve maskeleme modeli açısından okudum; aşağıda eksikler, kararlardaki riskler ve istenen teslimatlar var.

## 1. Boşluklar

**P0**

- **Hukuki dayanak sınıf bazında yazılmamış.** "KVKK onayı var" tek cümle. Her veri sınıfı için dayanak gerekir: metadata (meşru menfaat, m.5/2-f), içerik (ölçülülük testi; AYM işyeri izleme içtihadı: önceden bildirim, amaçla sınırlılık, daha hafif araç yoksa), özel nitelikli veri (m.6: prompt içinde sağlık, sendika, din verisi çıkar). Fable'ın cevaplaması gereken soru: hangi veri sınıfı hangi dayanakla, hangi amaçla, ne kadar süre işlenir ve bu kayıt VERBİS envanteriyle nasıl eşleşir?
- **Aydınlatma yükümlülüğü ürünün bir parçası olmalı (m.10).** Delil geçerliliği de buna bağlı. Soru: bildirim metni nerede gösterilir (giriş banner'ı, coaching/block sayfası, IDE ilk kullanım), kabul kaydı nerede tutulur ve içerik yakalama bu kayıt olmadan açılabilir mi? Önerim: açılamaz.
- **Yurt dışı aktarım (m.9) ürünün asıl işi, brief'te yok.** Gateway, prompt'ların Anthropic/OpenAI/Google'a gitmesini yöneten noktadır. Platform matrisine eklenmeli: veri bölgesi, enterprise DPA ve zero-retention durumu (kanıtla), taahhütname/standart sözleşme var mı. "Onaylı model/bölge allowlist" P2 değil, uyum kontrolü. Soru: hangi veri sınıfı hangi platforma hiç çıkamaz ve bu politika motorunda birinci sınıf kural mı?
- **Bankacılık sırrı ve BDDK.** Bankacılık Kanunu m.73 ve Sır Niteliğindeki Bilgilerin Paylaşılması Yönetmeliği (2021): müşteri sırrının yurt dışı üçüncü tarafa çıkması talimat/rıza ister. "Müşteri verisi" DLP sınıfı bu yüzden zorunlu ve fail-open olamaz. Bilgi Sistemleri Yönetmeliği (2020): birincil sistem/log yurt içinde, iz kayıtları, erişim yetkilendirmesi. Soru: rwsafe birincil sistem midir, denetim izi saklama süresi ve yeri nedir, dış hizmet alımı bildirimi gerekir mi?
- **Veri sınıfı ve saklama matrisi yok.** En az: metadata, verdict, redakte içerik, ham içerik, DLP bulguları, audit log, SIEM kopyası, export, yedek, test/eval korpusu. Her biri için süre, legal hold, silme kanıtı. Soru: silme yedeklere, SIEM'e ve export'lara nasıl yayılır; ham içerik için anahtar imha (crypto-shredding) mı?
- **İlgili kişi hakları (m.11) ile "sadece maskeli arama" çelişiyor.** Çalışan veya prompt'ta adı geçen müşteri başvurduğunda kayıt bulunabilmeli. Soru: yetkili, denetlenen, gerekçeli DSAR arama yolu nasıl ayrılır; itiraz hakkı için izleme dışı bırakma mümkün mü?
- **Maskeleme = anonimleştirme sanılıyor.** Estate'e sabit pseudonym, KVKK'ya göre hâlâ kişisel veridir. Prompt gövdesi serbest doğal dildir; cihaz logundan çok daha zengin (kişi adları, proje kod adları, kaynak kod, müşteri numarası). Heuristik maskeleme kaçırır. Soru: dış incelemecilere (Fable, Codex, Argon) ve maskeli role prompt gövdesi varsayılan olarak hiç gitmesin, sadece türetilmiş özellikler mi; gövde gerekiyorsa hangi kalıntı risk PO imzasıyla kabul ediliyor?
- **Bulgular değerleri saklamamalı.** DLP "PII bulundu" kaydı eşleşen değeri değil offset, sınıf ve digest tutmalı. Soru: bulgu şeması ve redaksiyon sonrası vendor'a gidenin kullanıcıya gösterimi.
- **İkincil kullanım yasağı yazılmalı.** Yakalanan içerik model eğitimi, verimlilik analitiği veya başka ürün için kullanılamaz; sınıflandırıcılar yakalanan veriyle eğitilmez.
- **Ham erişimde görev ayrılığı.** security_admin ham içeriği tek başına açamamalı: JIT, dört göz, gerekçe kodu, süre sınırı, veri sahibine/DPO'ya bildirim, audit'in band dışı SIEM'e anlık kopyası. Soru: `privacy_officer` ayrı rol mü; saklama ve maske kurallarını kim değiştirebilir?

**P1**

- **Veri koruma etki değerlendirmesi** ayrı belge (KVKK zorunlu kılmasa da savunulabilirlik için).
- **İhlal bildirimi:** Kurul'a 72 saat; prompt deposu için runbook ve etkilenen kişi tespiti.
- **5651 toplu kullanım sağlayıcı** yükümlülüğü: zaman damgalı erişim logu, bu rwsafe'de mi ProxySG'de mi, çakışan süreler.
- **Son kullanıcı metinleri Türkçe** olmalı (aydınlatma geçerliliği); repo İngilizce kalır, i18n ile çözülür. Brief'e istisna olarak yazılsın.
- **Kapsam dışı kişiler:** yükleniciler, BYOD, kişisel profil. Agent ve eklenti yalnızca yönetilen cihaz/profil ve allowlist AI origin'lerde çalışsın.
- **Engellenen kişisel girişlerde içerik saklanmasın,** sadece olay. Kişisel kullanım tamamen yasak mı, yoksa "izin var ama yakalama yok" mu: PO kararı.
- **Yedekler:** şifreli, aynı saklama, restore testi süresi dolmuş veriyi geri getirmemeli.
- **Erişim gözden geçirme** periyodu (çeyreklik) ve export audit'i.
- **Test korpusu:** prompt gövdeleri sentetik üretilsin; "sanitize edilmiş kayıtlı trafik" yalnızca protokol çerçevesi için.
- **Küçük takım analitiği:** takım başı maliyet ve DLP sayıları 1-2 kişilik takımlarda kişiyi ifşa eder; eşik altı toplulaştırma.

**P2**

- ISO 27001 A.5.34, ISO 42001, NIST AI RMF eşlemesi.
- Denetçi export'larına filigran ve indiren kimliği.
- Shadow-AI keşfi yalnızca toplulaştırılmış metadata ile.

## 2. Kararlardaki riskler ve istenecek önlem

- **neXus ile aynı sunucu:** cluster-admin ve host root iki ürünün de PVC ve Secret'ını okur; k3s Secret'ları varsayılan şifresiz. İstenecekler: k3s secrets-encryption açık, k8s audit log'da Secret/PVC erişimi, rwsafe anahtar Secret'ına neXus operatör kimliklerinin erişmemesi, ayrı yedek hedefi, HSM yokluğunun kalıntı riski olarak PO'ya imzalatılması.
- **ICAP inline:** ProxySG tüm kesilen trafiği gönderirse rwsafe banka, sağlık ve kişisel siteleri de görür; kapsam patlaması. İstenecekler: ICAP yalnızca AI domain allowlist'i için, preview ile eşleşmeyen gövdelerin hiç gelmemesi, kategori bazlı fail davranışı (müşteri sırrı ve secret sınıfı fail-closed), fail-open olayının audit'e "denetlenmeden çıktı" diye düşmesi.
- **İlk günden içerik yakalama:** bildirim, saklama ayarı, ham erişim rolleri ve DPO onayı olmadan açılmamalı. İstenecek: MVP "metadata + verdict + redakte içerik" modunda başlasın, ham içerik ayrı anahtarla ve onay kaydıyla açılsın.
- **Java inline yol:** heap dump, stack trace ve hata logları prompt içerir. İstenecek: gövde hiçbir log'a yazılmaz, heap dump kapalı veya şifreli, log tarayıcı testi.
- **Reverse proxy değişikliği:** ingress access log'u her iki ürünün URL ve kullanıcı izini tutar; saklama ve maskeleme kuralı, çerez adları ve domain'leri ayrı.

## 3. Eksik teslimatlar ve kabul kriterleri

- `docs/security/PRIVACY_IMPACT_ASSESSMENT.md`: veri envanteri, sınıf başına dayanak, aktarım haritası, kalıntı risk.
- `docs/security/DATA_CLASSES_AND_RETENTION.md`: matris ve silme kanıtı yolu.
- `docs/security/RAW_CONTENT_ACCESS.md`: JIT, dört göz, gerekçe kodları, bildirim.
- `docs/compliance/REGULATORY_MAPPING.md`: KVKK maddeleri, BDDK BS Yönetmeliği, Sır Yönetmeliği, 5651, ISO 27001.
- Türkçe son kullanıcı metin şablonları (aydınlatma, block, coaching) i18n altında.
- Kabul kriterleri: canary probe'a Türk formatları eklenir (TCKN checksum'lı, TR IBAN, telefon, müşteri no, Türkçe ad soyad) ve prompt gövdesi ekranları dahil; gerekçesiz ham okuma 403 ve audit; maske sözlüğü yokken 503; export maskeleme testi; log tarayıcı gövde bulamaz; DSAR arama testi; silme sonrası yedek ve SIEM'de kayıt yok kanıtı; dış inceleme scriptlerinin içerik göndermediğinin kanıtı; aydınlatma kabul kaydı olmayan kullanıcı için içerik saklanmadığı testi.
- OPEN_QUESTIONS'a: MVP yakalama modu, ham erişim onaycısı, sınıf başına gün sayıları, BYOD kapsamı, kişisel kullanım politikası, bölge/model allowlist, DPO kimliği.

**Aday eklemeler:** "data protection of captured prompts", "insider risk", "local classifiers" onay; "search only over masked features" DSAR ve olay incelemesi için ikinci yetkili yolla keskinleştirilmeli; "regulatory mapping" yukarıdaki somut mevzuatla; "browser extension paste/upload capture" yalnızca yönetilen profil ve allowlist origin ile; "per-team cost" küçük grup eşiğiyle; "production canary prompts" sentetik ve saklama istatistiklerinden hariç.

