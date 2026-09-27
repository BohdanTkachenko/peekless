# peekless protocol v1

Three parties: the **CLI** (runs next to the agent), the **page** (a static
HTML file in the user's browser), and a **relay** (an untrusted in-memory
mailbox). The relay never holds a key, so it can neither read nor forge
anything.

## The link

```
<page-url>#r=<relay-url, percent-encoded>&k=<K>
```

- `K` — 32 random bytes, base64url without padding. The fragment is never
  sent to any server, so only whoever holds the link knows `K`.
- `r` — relay base URL. Omitted when the page is served by the relay itself
  (same origin).

## Key derivation

All HKDF is HKDF-SHA256 with salt `"peekless/v1"` (ASCII) unless noted.

| Value | Derivation |
|---|---|
| request id | `base64url(HKDF(K, info="id", L=16))` — 22 chars, the only name the relay sees |
| config key | `HKDF(K, info="config", L=32)` |
| fingerprint | `HKDF(K, info="fingerprint", L=3)` → 24 bits → four 6-bit indexes (most significant first) into the emoji table in `src/crypto.rs` |

## Padding

Every plaintext is `u32be(len) || data || zeros`, padded to the smallest of
4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB that fits. The relay learns only the
size class.

## Config (CLI → page)

```
blob = nonce(12) || AES-256-GCM(config key, nonce, pad(json), aad="peekless/v1/config:" || id)
```

`json` is the *wire config*: the agent's request (title, instructions, fields,
run, files — paths made absolute), the context (host, user, cwd, created /
expiry times), the exact argv to execute, warnings, and `pubkey` — the
request's X25519 public key, base64url. Because `pubkey` is inside the
authenticated config, the relay can't substitute its own.

## Answer (page → CLI)

```
shared = X25519(eph_secret, pubkey)            (reject all-zero)
ka     = HKDF(ikm=shared, salt=epk || pubkey, info="answer:" || id, L=32)
blob   = epk(32) || nonce(12) || AES-256-GCM(ka, nonce, pad(json), aad="peekless/v1/answer:" || id)
```

`json`:

```json
{ "v": 1, "declined": false, "reason": null,
  "fields": { "TOKEN": { "value": "...", "secret": true, "share_metadata": false, "skip_validation": false } } }
```

`secret`, `share_metadata` and `skip_validation` carry the user's overrides.
A decline is an ordinary answer with `"declined": true`, so the relay can't
tell a decline from a submission.

## Relay HTTP API

Bodies are raw `application/octet-stream`. CORS is open (`*`). Bodies are
capped at 1 MiB + 64 bytes.

| Method & path | Auth | Result |
|---|---|---|
| `GET /v1/health` | – | `{"protocol":"peekless/1","version":…,"max_ttl":secs,"max_body":bytes}` |
| `PUT /v1/r/{id}/config` | owner | `201`; `409` if the id exists; header `X-Peekless-TTL: <secs>` |
| `GET /v1/r/{id}/config` | – | `200` blob; `410` already answered; `404` unknown/expired |
| `PUT /v1/r/{id}/answer` | – | `201`; `409` already answered (first answer wins); `404` |
| `GET /v1/r/{id}/answer?wait=<secs>` | owner | `200` blob; `204` none yet (after long-polling up to `wait`, capped by the relay); `404` |
| `DELETE /v1/r/{id}` | owner | `204` |
| `GET /` | – | the page (optional; lets a relay double as the page host) |

*owner* = `Authorization: Bearer <token>`, a random token the CLI picks when
creating the request (the relay stores its SHA-256). It keeps link holders
from fetching answer ciphertext or deleting the request; it grants no
cryptographic power.

A relay must keep everything in memory, expire entries at their TTL, and
never log bodies.

## What a relay can and can't do

- **Can't** read configs or answers, forge answers (it never learns
  `pubkey`), or learn `K`.
- **Can** drop or delay requests (the CLI times out), see IP addresses and
  timing, and see the size class.

## Page integrity

Browsers can't pin a top-level document, so:

1. The canonical page is served from GitHub Pages, built from a tagged commit.
2. `peekless run` fetches the page it's about to link and refuses unless its
   SHA-256 equals the page embedded in the CLI (`peekless page-hash`;
   `--no-verify-page` to skip).
3. The page carries a CSP that forbids loading any other script.
