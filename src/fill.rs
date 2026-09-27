//! `peekless fill <link>`: answer a request from a terminal instead of a
//! browser — e.g. to move a key from one machine to another.

use crate::client::RelayClient;
use crate::config::{Answer, AnswerField, WireConfig};
use crate::crypto::{self, LinkKey};
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, IsTerminal, Write};
use zeroize::Zeroizing;

pub struct FillOpts {
    pub link: String,
    pub from_file: Vec<(String, String)>,
    pub from_env: Vec<(String, String)>,
    pub proxy: Option<String>,
    pub yes: bool,
    pub decline: Option<String>,
}

fn parse_link(link: &str) -> Result<(String, LinkKey)> {
    let (base, frag) = link.split_once('#').context("link has no #fragment")?;
    let mut relay = None;
    let mut key = None;
    for kv in frag.split('&') {
        match kv.split_once('=') {
            Some(("r", v)) => relay = Some(urldecode(v)?),
            Some(("k", v)) => key = Some(LinkKey::from_b64(v)?),
            _ => {}
        }
    }
    let key = key.context("link has no k=")?;
    let relay = match relay {
        Some(r) => r,
        None => {
            // The page was served by the relay itself: same origin.
            let u = reqwest::Url::parse(base).context("invalid link")?;
            u.origin().ascii_serialization()
        }
    };
    Ok((relay, key))
}

fn urldecode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3])?, 16)?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

fn prompt_line(label: &str) -> Result<Zeroizing<String>> {
    eprint!("{label}: ");
    std::io::stderr().flush()?;
    let mut s = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut s)?;
    let trimmed = Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned());
    Ok(trimmed)
}

pub async fn fill(opts: FillOpts) -> Result<()> {
    let (relay, k) = parse_link(&opts.link)?;
    let client = RelayClient::new(&relay, opts.proxy.as_deref())?;
    let id = k.request_id();
    let blob = client.get_config(&id).await?;
    let plain = k.open_config(&blob)?;
    let wire: WireConfig = serde_json::from_slice(&plain).context("malformed request")?;
    let pk: [u8; 32] = crypto::unb64(&wire.pubkey)?.as_slice().try_into().context("bad request key")?;
    let cfg = &wire.config;

    let mut e = std::io::stderr().lock();
    writeln!(e, "Request:     {}", cfg.title)?;
    writeln!(e, "Fingerprint: {}", k.fingerprint())?;
    writeln!(e, "From:        {}@{} in {}", wire.context.user, wire.context.host, wire.context.cwd)?;
    if !cfg.instructions.is_empty() {
        writeln!(e, "\n{}\n", cfg.instructions.trim_end())?;
    }
    if let (Some(run), Some(argv)) = (&cfg.run, &wire.exec) {
        writeln!(e, "Will run:    {}", shell_words::join(argv))?;
        if let Some(s) = &run.script {
            writeln!(e, "--- script ---\n{}\n--------------", s.trim_end())?;
        }
    }
    for f in &cfg.files {
        writeln!(e, "Will write:  {} ({}, {:?})\n{}", f.path, f.mode, f.format, f.template.trim_end())?;
    }
    for w in &wire.warnings {
        writeln!(e, "WARNING:     {w}")?;
    }
    drop(e);

    if let Some(reason) = opts.decline {
        let answer = Answer { v: 1, declined: true, reason: Some(reason), fields: BTreeMap::new() };
        client.put_answer(&id, crypto::seal_answer(&pk, &id, &serde_json::to_vec(&answer)?)?).await?;
        eprintln!("Declined.");
        return Ok(());
    }

    let files: HashMap<_, _> = opts.from_file.into_iter().collect();
    let envs: HashMap<_, _> = opts.from_env.into_iter().collect();
    let interactive = std::io::stdin().is_terminal();
    let mut fields = BTreeMap::new();
    for f in &cfg.fields {
        let value: Zeroizing<String> = if let Some(p) = files.get(&f.name) {
            let v = Zeroizing::new(std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?);
            // Files usually end with a newline that isn't part of the value.
            Zeroizing::new(if f.multiline { v.to_string() } else { v.trim_end_matches(['\n', '\r']).to_owned() })
        } else if let Some(var) = envs.get(&f.name) {
            Zeroizing::new(std::env::var(var).with_context(|| format!("${var} is not set"))?)
        } else if interactive {
            eprintln!("\n{} ({}){}", f.label.as_deref().unwrap_or(&f.name), f.name, if f.optional { " — optional" } else { "" });
            if !f.description.is_empty() {
                eprintln!("{}", f.description.trim_end());
            }
            if !f.steps.is_empty() {
                eprintln!("{}", f.steps.trim_end());
            }
            if f.secret {
                Zeroizing::new(rpassword::prompt_password(format!("{}: ", f.name))?)
            } else {
                prompt_line(&f.name)?
            }
        } else if f.optional {
            Zeroizing::new(String::new())
        } else {
            bail!("no value for {} (use --from-file / --from-env, or run interactively)", f.name);
        };
        let mut skip = false;
        if let (Some(p), false) = (&f.pattern, value.is_empty()) {
            if !regex::Regex::new(p)?.is_match(&value) {
                let hint = f.pattern_hint.as_deref().unwrap_or(p);
                if interactive && prompt_line(&format!("{} doesn't look like {hint}. Send anyway? [y/N]", f.name))?.eq_ignore_ascii_case("y") {
                    skip = true;
                } else {
                    bail!("{} doesn't match the expected format ({hint})", f.name);
                }
            }
        }
        fields.insert(
            f.name.clone(),
            AnswerField { value: value.to_string(), secret: f.secret, share_metadata: f.share_metadata, skip_validation: skip },
        );
    }
    if !opts.yes {
        if !interactive {
            bail!("refusing to send without confirmation; pass --yes");
        }
        if !prompt_line("Send these values? [y/N]")?.eq_ignore_ascii_case("y") {
            bail!("not sent");
        }
    }
    let answer = Answer { v: 1, declined: false, reason: None, fields };
    let json = Zeroizing::new(serde_json::to_vec(&answer)?);
    client.put_answer(&id, crypto::seal_answer(&pk, &id, &json)?).await?;
    eprintln!("Sent.");
    Ok(())
}
