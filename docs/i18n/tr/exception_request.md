# Exception request (draft, not in the product catalogue)

Draft text of the justification form for an expiring exception. It is not in the product catalogue yet: the exception
workflow for rules that are not fail-closed is not built. Exceptions never apply to the fail-closed classes (secret,
customer data, special-category personal data, internal identity; PC-5, ADR-010, SR-DLP-1), so the form is never offered
on their block page. `EndUserCatalogueDocsTest` names this file as the one draft without key sections.

İstisna talebi

Engellenen işlemin işiniz için gerekli olduğunu düşünüyorsanız gerekçenizi yazın. Talebiniz güvenlik analistine iletilir;
onaylanırsa belirli bir süre için geçerli olur ve süre sonunda kendiliğinden kapanır. Gerekçeye kişisel veri veya sır
yazmayın.

Gerekçe: ______  Süre: {{duration_options}}  Referans: {{ref}}
