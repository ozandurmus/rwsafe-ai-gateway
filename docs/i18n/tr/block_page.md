# Block page (403)

The block page body per reason kind (`EndUserPages.BlockKind`), the shared footer and the one-sentence API message. The data plane's `BlockPages` maps a decision reason to a kind: a fail-closed class to `class`, an oversize, encoded or unparsable body to `uninspectable`, an internal failure or overload to `unavailable`, a platform rule to `platform`, a personal account to `personal` (see `personal_account_block.md`), anything else to `generic`. Fail-closed classes take no exception (PC-5), so no exception link is rendered.

Review copy of the product catalogue `java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties`; `EndUserCatalogueDocsTest` fails when the two differ. Each heading is the key; the text below it is the Turkish text.

## `page.reference`

Yardım isterseniz bu referansı bildirin: {{ref}}

## `page.policy`

Kurumsal yapay zeka kullanım politikası: {{policy_link}}

## `block.title`

İstek engellendi

## `block.class.body`

Gönderdiğiniz içerikte {{class}} bulundu. Kurumsal politika gereği bu tür bilgiler {{platform}} platformuna gönderilemez.

## `block.class.advice`

Bulunan bilginin kendisi bu sayfada gösterilmez ve kaydedilmez; yalnızca türü kaydedilir. Bu bilgiyi içerikten çıkarıp tekrar deneyebilirsiniz.

## `block.class.noexception`

> LEGAL-REVIEW LR-6: the statement that no exception exists for the four fail-closed classes (PC-5, ADR-010, SR-DLP-1) as an employee-facing promise.

Bu tür bilgiler için istisna tanınmaz: müşteri bilgileri, gizli bilgiler, özel nitelikli kişisel veriler ve kurum içi kimlik bilgileri hiçbir yapay zeka platformuyla paylaşılamaz.

## `block.uninspectable.body`

Gönderdiğiniz içerik güvenlik denetiminden geçirilemedi ({{reason}}). Denetlenemeyen içerik, kurumsal politika gereği {{platform}} platformuna gönderilmez.

## `block.uninspectable.advice`

İçeriği küçültüp ya da düz metin olarak yeniden göndermeyi deneyebilirsiniz.

## `block.unavailable.body`

Güvenlik denetimi şu anda tamamlanamadı. Denetlenemeyen içerik, kurumsal politika gereği {{platform}} platformuna gönderilmez.

## `block.unavailable.advice`

Lütfen birkaç dakika sonra tekrar deneyin.

## `block.platform.body`

{{platform}} platformunun bu ağda kullanılmasına izin verilmiyor.

## `block.platform.advice`

Kurumun izin verdiği yapay zeka araçlarını kullanabilirsiniz. İzin verilen araçları kurumsal politikada bulabilirsiniz.

## `block.generic.body`

İsteğiniz kurumsal politika gereği engellendi.

## `block.generic.advice`

Bunun bir hata olduğunu düşünüyorsanız aşağıdaki referansla bilgi güvenliği ekibine başvurabilirsiniz.

## `api.class`

İstek, içerikte kurumsal politikanın izin vermediği bir bilgi türü bulunduğu için engellendi.

## `api.uninspectable`

İçerik güvenlik denetiminden geçirilemediği için istek engellendi.

## `api.unavailable`

Güvenlik denetimi tamamlanamadığı için istek engellendi; lütfen biraz sonra tekrar deneyin.

## `api.platform`

Bu yapay zeka platformunun bu ağda kullanılmasına izin verilmiyor.

## `api.generic`

İstek kurumsal politika gereği engellendi.
