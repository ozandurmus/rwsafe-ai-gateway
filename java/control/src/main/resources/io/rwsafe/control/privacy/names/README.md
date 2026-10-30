# Turkish name dictionary (rwmask layer 4)

The name layer of the text masker (`TextMasker`, `NameDictionary`; MASKING_AND_PRIVACY B2 layer 4, PO decision Q-23:
"names come from a public list").

| File | Holds |
|---|---|
| `given-names.txt` | common Turkish given names |
| `surnames.txt` | common Turkish family names |
| `common-words.txt` | the false-positive allow list: entries of the two lists that are also everyday Turkish or English words (deniz "sea", umut "hope", metin "text", kaya "rock", özel "private", yazıcı "printer", can, mine) |

## Source and licence

Composed for this repository from general knowledge of the most frequent Turkish given and family names, the kind of
names any public frequency list (for example the population registry's yearly "most given names" tables) shows at the
top. No list was downloaded or copied, so no third-party licence applies; the files are original work of this
repository under the repository's own terms. Every entry is a bare, generic name shared by a very large number of
people: no entry identifies a person, and no entry comes from estate data, a directory, a log or a customer record.

## Rules for changes

- Add only generic names that are common in Türkiye. Never add a full name, a rare name, a nickname, an estate account
  name or anything read from production data (AGENTS.md section 4.2).
- A name that is also a frequent lower-case word in operational text goes into `common-words.txt` as well: in lower
  case and alone it stays a word; capitalised, next to another name word or by a title (Sayın, Dr., Bey, Hanım) it is
  a name. A name people rarely write as a word in lower case (Kemal, Ramazan, Ozan) does not belong there (PR 26
  review D-01).
- One entry per line in Turkish spelling; `#` starts a comment. Matching folds case, the Turkish dotted and dotless i and
  the Turkish diacritics (ç ğ ı ö ş ü), so ASCII spellings need no entry of their own.
- A change of any list changes the masked output: bump `TextMasker.RULE_SET`.
