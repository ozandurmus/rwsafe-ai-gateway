# Aydınlatma metni (ilk kullanım)

**Veri sorumlusu:** {{controller_name}}. Bu kurumun ağından yapay zeka asistanlarına ve kodlama ajanlarına erişiminiz,
kurumsal güvenlik ve bilgi sistemleri mevzuatı gereği rwsafe güvenlik geçidi üzerinden geçer.

**Nasıl toplanır?** Veriler, kurumsal internet vekil sunucusu (proxy) üzerinden geçen trafiğin güvenlik geçidi tarafından
otomatik olarak incelenmesiyle toplanır; ayrıca bir form doldurmanız gerekmez.

**Ne işlenir?** Hangi platformu, hangi araçla, hangi kurumsal hesapla ve ne zaman kullandığınız (üst veri); güvenlik
kurallarının verdiği karar; gönderdiğiniz ve aldığınız içeriğin, kişisel veri ve sırların maskelenmiş (redakte edilmiş)
hâli. Ham içerik yalnızca doğrulanmış bir güvenlik olayında, iki yetkilinin onayı ve kayıt altında incelenebilir.

**Neden?** Kurumsal hesap kullanımını sağlamak, müşteri sırrı ve kişisel verilerin dışarıya çıkmasını engellemek,
güvenlik olaylarını incelemek. Hukuki dayanak: 6698 sayılı KVKK madde 5/2-ç (hukuki yükümlülük) ve 5/2-f (meşru menfaat);
sektörel bilgi sistemleri düzenlemeleri. Bu bildirim bir rıza talebi değildir; işleme bu dayanaklara göre yapılır.

**Kime aktarılır?** Kullandığınız yapay zeka platformunun sağlayıcısına, yalnızca kurumsal politikanın o veri sınıfı için
izin verdiği içerik iletilir; bu sağlayıcılar **yurt dışında** bulunabilir ve aktarım ancak KVKK madde 9 kapsamındaki bir
aktarım aracının kayıtlı olduğu sağlayıcılara yapılır. Üst veri ve karar kayıtları kurumun güvenlik olay yönetim sistemine
(SIEM) aktarılır; içerik SIEM'e aktarılmaz.

**Ne kadar saklanır?** Üst veri ve karar kayıtları {{retention_metadata}} gün; maskelenmiş içerik {{retention_redacted}}
gün; ham içerik, saklanması gerekiyorsa {{retention_raw}} gün. Süresi dolan veri silinir; silme kayıt altına alınır.

**Haklarınız:** KVKK madde 11 kapsamındaki haklarınız için {{dpo_contact}} adresine başvurabilirsiniz. İtiraz hakkınızı
kullanırsanız içeriğiniz saklanmaz; güvenlik incelemesi ve kurumsal hesap zorunluluğu uygulanmaya devam eder. Kişisel
hesaplarla yapılan kullanım bu ağda engellenir; engelleme olayının kendisi kaydedilir, içeriği ve kişisel hesap bilgisi
kaydedilmez.

Devam etmeniz bu bildirimi okuduğunuzu kaydeder (sürüm {{notice_version}}). Bu kayıt bir onay değil, bilgilendirildiğinizin
kanıtıdır.
