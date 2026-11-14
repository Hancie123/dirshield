# DirShield vault format, version 1

A vault is a directory named by its random 128-bit vault id (hex):

```
<vault id>/
  vault.dsv                 header
  manifest.dsb              encrypted manifest (BlobKind::Manifest)
  objects/<xx>/<id>.dsb     one encrypted blob per file; <id> = random 128-bit file id (hex), <xx> its first two chars
```

No original name, path or directory structure appears in file names or plaintext.

## Header — `vault.dsv`

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `DIRSHLD\0` |
| 8 | 2 | format version, u16 LE = 1 |
| 10 | 4 | body length, u32 LE (≤ 1 MiB) |
| 14 | n | UTF-8 JSON body |

Body fields: `format_version`, `algorithm` = `AES-256-GCM/STREAM-HKDF-SHA256`, `vault_id`, `chunk_size` (default 4 194 304), `created_utc`, `wrappers[]`, `sealed`, `mac`.

Wrappers (vault key = 256-bit random):

* `master` — `AES-256-GCM(MK, VK, aad="dirshield/v1/vault-key/master/<vault id>")`, random 96-bit nonce.
* `password` — Argon2id params `{alg, m_cost KiB, t_cost, p_cost, salt}` + `AES-256-GCM(KEK, VK, aad=…/password/<vault id>)`.
* `recovery_escrow` — `{recovery_id, salt, box:{eph_pub, sealed}}`: ephemeral X25519 key, `kek = HKDF-SHA256(ikm=DH, salt=eph_pub‖recipient_pub, info="dirshield/v1/escrow")`, recipient secret = `HKDF(recovery key, salt, "dirshield/v1/recovery-x25519")`.

`mac` = HMAC-SHA256 over the JSON body with `mac=""`, key = `HKDF(VK, "", "dirshield/v1/header-mac")`. Verified immediately after unwrapping VK. Argon2 parameters are range-checked before use so a tampered header cannot cause huge allocations.

`sealed = true` is written last, via write-temp → fsync → rename, and is the commit point.

## Blob — `*.dsb`

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `DSHB` |
| 4 | 1 | version = 1 |
| 5 | 1 | kind: 0 file, 1 manifest |
| 6 | 2 | reserved = 0 |
| 8 | 4 | chunk size, u32 LE (1 … 64 MiB) |
| 12 | 16 | file id (random) |
| 28 | … | chunks |

* Blob key: `HKDF-SHA256(ikm=VK, salt=file id, info="dirshield/v1/file-key" | "dirshield/v1/manifest-key")`.
* Chunk *i*: `ciphertext ‖ 16-byte tag`; every chunk except the last carries exactly `chunk size` plaintext bytes; an empty file is one empty final chunk.
* Nonce: `u64_be(i) ‖ 00 00 00 ‖ last_flag`.
* AAD: `vault id (16) ‖ blob header (28) ‖ u64_le(i) ‖ last_flag`.

Consequences: chunks can't be reordered, moved between blobs or vaults, truncated at a boundary, or extended; the header (incl. chunk size) is authenticated; no plaintext is released before its tag verifies. Exact size: `28 + n + 16·max(1, ceil(n / chunk))`.

## Manifest

JSON lines inside a manifest blob:

```
{"t":"h","v":1,"root_name":"…","original_path":"…","created_utc":…}
{"t":"d","p":"rel/dir","a":attrs,"m":mtime_ns}
{"t":"f","p":"rel/file","s":size,"a":attrs,"m":mtime_ns,"b":"<file id hex>","h":"<sha256 hex>","c":chunks}
{"t":"e","dirs":D,"files":F,"bytes":B}
```

Readers require a head first and an end last with matching counts. Paths must be relative, `/`-separated, with no empty, `.`, `..`, `\`, `:` (ADS) or other reserved characters.

## Leakage

Visible without keys: number of files, each file's size rounded to whole bytes (blob size), approximate total size, chunk size, creation time, and whether the vault uses a folder password. Not visible: names, structure, contents, timestamps, attributes.
