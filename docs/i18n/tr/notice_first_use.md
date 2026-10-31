# First-use notice (KVKK article 10)

Shown at the first use of an AI platform through the gateway (web banner, IDE first-run notification) and rendered by `EndUserPages.noticeHtml`. Section order: introduction, then each heading with its text, then `page.policy`, then `notice.acknowledge.text`.

Review copy of the product catalogue `java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties`; `EndUserCatalogueDocsTest` fails when the two differ. Each heading is the key; the text below it is the Turkish text.

## `notice.title`

Yapay zeka araçlarının kullanımına ilişkin aydınlatma metni

## `notice.intro`

Bu metin, 6698 sayılı Kişisel Verilerin Korunması Kanunu (bundan sonra "Kanun") uyarınca sizi bilgilendirmek için hazırlanmıştır. Veri sorumlusu: {{controller_name}}.

## `notice.scope.heading`

Ne inceleniyor?

## `notice.scope.text`

Kurum ağından yapay zeka asistanlarına ve kodlama araçlarına gönderdiğiniz istekler ve aldığınız yanıtlar bir güvenlik geçidinden geçer ve otomatik olarak incelenir. Bunun için ayrıca bir şey yapmanız gerekmez.

## `notice.data.heading`

Hangi bilgiler işleniyor?

## `notice.data.text`

Hangi yapay zeka platformunu, hangi araçla, hangi kurumsal hesapla ve ne zaman kullandığınız; güvenlik kurallarının verdiği karar; gönderdiğiniz ve aldığınız içeriğin kişisel veriler ve gizli bilgiler çıkarılmış (maskelenmiş) hâli. Bulunan hassas bilginin kendisi kaydedilmez, yalnızca türü kaydedilir.

## `notice.purpose.heading`

Neden?

## `notice.purpose.text`

Müşteri sırlarının, kişisel verilerin ve gizli bilgilerin (parola, anahtar gibi) kurum dışına çıkmasını önlemek; yapay zeka araçlarının yalnızca kurumsal hesapla kullanılmasını sağlamak; güvenlik olaylarını incelemek.

## `notice.basis.heading`

Hukuki sebep

## `notice.basis.text`

Kullanım kayıtları ve güvenlik kararları, kurumun bilgi sistemleri güvenliğine ilişkin hukuki yükümlülüğü nedeniyle (Kanun'un 5. maddesinin 2. fıkrasının (ç) bendi); maskelenmiş içerik, kurumun meşru menfaati nedeniyle (Kanun'un 5. maddesinin 2. fıkrasının (f) bendi) işlenir. Bu işleme açık rızanıza dayanmaz; bu nedenle sizden rıza istenmez.

## `notice.transfer.heading`

Kimlere aktarılıyor?

## `notice.transfer.text`

Kullandığınız yapay zeka platformunun sağlayıcısına yalnızca kurumsal politikanın izin verdiği içerik iletilir. Bu sağlayıcılar yurt dışında bulunabilir; aktarım yalnızca Kanun'un 9. maddesine uygun aktarım dayanağı kurum tarafından kayda geçirilmiş sağlayıcılara yapılır. Kullanım kayıtları ve güvenlik kararları kurumun güvenlik izleme sistemine aktarılır; içerik bu sisteme aktarılmaz.

## `notice.retention.heading`

Ne kadar saklanıyor?

## `notice.retention.text`

Kullanım kayıtları ve güvenlik kararları {{retention_metadata}} gün, maskelenmiş içerik {{retention_redacted}} gün saklanır. Süresi dolan bilgiler silinir ve silme işlemi kayıt altına alınır.

## `notice.rights.heading`

Haklarınız

## `notice.rights.text`

Kanun'un 11. maddesindeki haklarınız için (bilgilerinize erişmek, düzeltilmesini ya da silinmesini istemek, itiraz etmek gibi) {{dpo_contact}} adresine başvurabilirsiniz.

## `notice.personal.heading`

Kişisel hesaplar

## `notice.personal.text`

Kurum ağında yapay zeka araçlarına kişisel hesapla giriş engellenir. Engellenen denemenin yalnızca kendisi kaydedilir; kişisel hesap bilginiz ve içerik kaydedilmez.

## `notice.acknowledge.text`

Devam ettiğinizde bu metni okuduğunuz kaydedilir (sürüm {{notice_version}}). Bu kayıt bir onay ya da rıza değildir; yalnızca bilgilendirildiğinizi gösterir. Kurumun insan kaynakları politikası kapsamında bu sürümü okuduğunuz kayda geçtiyse o kayıt da aynı anlamı taşır.
