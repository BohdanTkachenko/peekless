---
name: request-secret
description: Ask the user for secrets (API keys, passwords, tokens) through an end-to-end encrypted peekless link, then deliver them straight into an approved command or file without ever seeing them. Use whenever a task needs a credential the user hasn't provided through a safe channel.
---

# Requesting a secret with peekless

Never ask the user to paste a secret into the chat. Write a peekless request
instead: the user opens a link, sees exactly what you'll run, fills in the
values, and `peekless run` delivers them into your command. You only see the
command's output, with secret values scrubbed.

## 1. Work out exactly what you need

- Which values, their format (write a `pattern` if you know it), and where
  they must end up.
- Plan the delivery so values never land in argv (visible in `ps`) or on
  stdout: pass them on stdin or through the environment.
- For sops: `jq -n 'env.PEEKLESS_TOKEN' | sops set --value-stdin <file> '["key"]'`
  (`sops set` expects a JSON-encoded value; jq produces one).

## 2. Write the request config

```yaml
title: Cloudflare API token so I can manage DNS for example.com
instructions: |
  I'll store the token in sops (secrets/cloudflare.yaml) and restart ddns.
ttl: 30m                    # default 1h, max 24h
fields:
  - name: CF_TOKEN          # → env var PEEKLESS_CF_TOKEN
    label: API token
    description: Needs Zone:DNS:Edit on example.com only.
    steps: |
      1. Open https://dash.cloudflare.com/profile/api-tokens
      2. Create Token → "Edit zone DNS" template → Zone: example.com
    secret: true            # default true
    share_metadata: true    # length/charset/hash visible to you; false for passwords
    pattern: '^[A-Za-z0-9_-]{40}$'
    pattern_hint: 40 letters, digits, - or _
run:
  cmd: ["sh", "-c", "jq -n 'env.PEEKLESS_CF_TOKEN' | sops set --value-stdin secrets/cloudflare.yaml '[\"token\"]'"]
  cwd: ~/Projects/infra
```

Rules:

- `run.cmd` is an argv array. Use `["sh", "-c", "…"]` only when you need a
  pipe. For anything longer, use `run.script` (with an optional
  `interpreter`, default `["sh", "-eu"]`): the user sees the whole script.
- Don't run local scripts (`./deploy.sh`): the user can't see their
  contents. Inline them as `run.script`. peekless warns the user about any
  local file your command references.
- Every field reaches the command as `PEEKLESS_<NAME>`, secret or not.
- To write a config file, use `files` instead of shell tricks:

  ```yaml
  files:
    - path: ~/.config/foo/credentials.toml
      format: toml          # json | yaml | toml | env | shell | raw
      mode: "0600"          # default
      overwrite: false      # default; the page shows it
      cleanup: never        # or after_run
      template: |
        [auth]
        user = {{ LOGIN }}
        token = {{ TOKEN }}
  ```

  Don't put quotes around placeholders: `format` quotes and escapes every value.
  Override per placeholder with `{{ X | raw }}`, `| base64`, `| urlencode`,
  `| shell`, `| json`, or `| env`.
- `peekless check <config>` validates the config and prints exactly what the page will show.

## 3. Run it and share the link

Run `peekless run <config>` **in the background**. It prints a link and a
four-emoji fingerprint, then waits. Send the user both, and tell them the
fingerprint must match. Relays:

- default: `relay:` from `~/.config/peekless/config.yaml` if set, else the
  bundled public relays; `--relay <url>` for a specific one.
- `--serve 0.0.0.0:<port>`: built-in relay when the user is on the same LAN or
  tailnet (plain HTTP is only allowed on private addresses).

## 4. Read the result

When it exits, read its output:

- A summary of every field: plain values in full; secrets as
  `[redacted: …]`, with metadata only if the user allowed it. `note:` lines
  report user overrides (e.g. they made a plain field secret). Respect them.
- The command's output, with secrets replaced by `[peekless:NAME]`.
- Exit codes: the command's own status on success; 64 bad config;
  65 user declined (the reason is printed); 66 expired; 67 relay error;
  68 invalid answer; 69 delivery failed; 130 interrupted.

Never try to recover a secret value: don't `cat` files peekless wrote, don't
echo `$PEEKLESS_*`, and don't write commands that exfiltrate values. The user
approved the exact command; that is the only thing that may touch the values.
