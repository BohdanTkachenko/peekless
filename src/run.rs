//! `peekless run`: publish a request, wait for the answer, deliver the values
//! into the approved files and command, and exit with the command's status.

use crate::client::{Poll, RelayClient};
use crate::config::{self, Answer, Cleanup, Config, RequestContext, WireConfig, ENV_PREFIX};
use crate::crypto::{self, LinkKey, RequestKeys};
use crate::relay;
use crate::scrub::{self, Scrubber};
use crate::template;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub mod exit {
    pub const CONFIG: i32 = 64;
    pub const DECLINED: i32 = 65;
    pub const EXPIRED: i32 = 66;
    pub const RELAY: i32 = 67;
    pub const INVALID_ANSWER: i32 = 68;
    pub const DELIVERY: i32 = 69;
    pub const INTERRUPTED: i32 = 130;
}

pub struct RunOpts {
    pub config: PathBuf,
    pub relay: Option<String>,
    pub serve: Option<SocketAddr>,
    pub public_url: Option<String>,
    pub page: Option<String>,
    pub no_verify_page: bool,
    pub proxy: Option<String>,
    pub insecure: bool,
}

/// An error carrying the process exit code to use.
#[derive(Debug)]
pub struct Exit(pub i32, pub String);
impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}
impl std::error::Error for Exit {}

fn fail(code: i32, msg: impl Into<String>) -> anyhow::Error {
    Exit(code, msg.into()).into()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn say(msg: impl AsRef<str>) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", msg.as_ref());
    let _ = out.flush();
}

/// Validate the config and build what the page will show.
pub fn prepare(path: &Path, pubkey: &[u8; 32]) -> Result<(Config, WireConfig)> {
    let mut cfg = Config::load(path).map_err(|e| fail(exit::CONFIG, format!("{e:#}")))?;
    cfg.validate().map_err(|e| fail(exit::CONFIG, format!("invalid config: {e:#}")))?;
    let cwd = cfg.cwd()?;
    if !cwd.is_dir() {
        return Err(fail(exit::CONFIG, format!("run.cwd {} is not a directory", cwd.display())));
    }
    cfg.resolve_paths()?;
    let mut warnings = Vec::new();
    let exec = match cfg.run.as_ref() {
        Some(run) => Some(match (&run.cmd, &run.script) {
            (Some(cmd), _) => {
                let prog = config::resolve_program(&cmd[0], &cwd)
                    .ok_or_else(|| fail(exit::CONFIG, format!("{} not found in PATH", cmd[0])))?;
                warnings.extend(config::file_reference_warnings(cmd, &cwd));
                if cmd[0].contains('/') {
                    warnings.insert(0, format!("The command is the local file {} — its contents are not shown here.", prog.display()));
                }
                let mut argv = vec![prog.display().to_string()];
                argv.extend(cmd[1..].iter().cloned());
                argv
            }
            (None, Some(_)) => {
                let interp = run.interpreter.clone().unwrap_or_else(|| vec!["sh".into(), "-eu".into()]);
                let prog = config::resolve_program(&interp[0], &cwd)
                    .ok_or_else(|| fail(exit::CONFIG, format!("{} not found in PATH", interp[0])))?;
                let mut argv = vec![prog.display().to_string()];
                argv.extend(interp[1..].iter().cloned());
                argv.push("<the script below>".into());
                argv
            }
            _ => unreachable!("validated"),
        }),
        None => None,
    };
    for f in &cfg.files {
        let exists = Path::new(&f.path).exists();
        if exists && !f.overwrite {
            return Err(fail(exit::CONFIG, format!("{} exists and overwrite is false", f.path)));
        }
        if exists {
            warnings.push(format!("{} already exists and will be replaced.", f.path));
        }
    }
    for field in &cfg.fields {
        if field.pattern.as_deref().is_some_and(|p| p.contains("(?")) {
            warnings.push(format!("Field {}'s pattern uses (?…) syntax, which may differ between the page and the CLI.", field.name));
        }
    }
    let ttl = cfg.ttl()?;
    let created = now();
    let wire = WireConfig {
        v: 1,
        config: cfg.clone(),
        context: RequestContext {
            host: gethostname::gethostname().to_string_lossy().into_owned(),
            user: std::env::var("USER").unwrap_or_default(),
            cwd: cwd.display().to_string(),
            created_at: created,
            expires_at: created + ttl.as_secs(),
            peekless_version: env!("CARGO_PKG_VERSION").into(),
        },
        pubkey: crypto::b64(pubkey),
        exec,
        warnings,
        env_prefix: ENV_PREFIX.into(),
    };
    Ok((cfg, wire))
}

pub async fn check(path: &Path) -> Result<()> {
    let (_, wire) = prepare(path, &[0; 32])?;
    println!("{}", serde_json::to_string_pretty(&wire)?);
    Ok(())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Best-effort address other machines on the LAN can reach us at.
fn outbound_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?; // TEST-NET; no packet is sent
    Some(s.local_addr().ok()?.ip())
}

async fn host_is_private(url: &str) -> Result<bool> {
    let u = reqwest::Url::parse(url).context("invalid --public-url")?;
    let host = u.host_str().context("--public-url has no host")?;
    let port = u.port_or_known_default().unwrap_or(80);
    let addrs: Vec<_> = tokio::net::lookup_host((host.trim_matches(|c| c == '[' || c == ']'), port)).await?.collect();
    Ok(!addrs.is_empty() && addrs.iter().all(|a| is_private(a.ip())))
}

/// Optional per-user defaults in `$XDG_CONFIG_HOME/peekless/config.yaml`:
///     relay: https://relay.example
#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    relay: Option<String>,
}

fn user_config() -> Result<UserConfig> {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    let Some(path) = dir.map(|d| d.join("peekless/config.yaml")) else { return Ok(UserConfig::default()) };
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

async fn pick_relay(opts: &RunOpts) -> Result<String> {
    if let Some(r) = &opts.relay {
        return Ok(r.clone());
    }
    if let Some(r) = user_config()?.relay {
        return Ok(r);
    }
    #[derive(serde::Deserialize)]
    struct List {
        relays: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        url: String,
        #[serde(default)]
        onion: Option<String>,
    }
    let list: List = serde_json::from_str(include_str!("../relays.json"))?;
    let via_tor = opts.proxy.as_deref().is_some_and(|p| p.starts_with("socks5h://"));
    for e in list.relays {
        let url = if via_tor { e.onion.unwrap_or(e.url) } else { e.url };
        if RelayClient::new(&url, opts.proxy.as_deref())?.health().await.is_ok() {
            return Ok(url);
        }
    }
    bail!("no reachable public relay; pass --relay <url> or --serve <addr>")
}

pub async fn run(opts: RunOpts) -> Result<i32> {
    let keys = RequestKeys::generate();
    let (cfg, wire) = prepare(&opts.config, &keys.public)?;
    let ttl = cfg.ttl()?;
    let k = LinkKey::generate();
    let id = k.request_id();
    let owner = crypto::b64(&crypto::random_bytes::<32>());

    // Where the relay is, and where the user's browser loads the page from.
    let (client, link_base, relay_param, _server) = if let Some(addr) = opts.serve {
        let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
        let bound = listener.local_addr()?;
        let public = match &opts.public_url {
            Some(u) => u.trim_end_matches('/').to_owned(),
            None => {
                let ip = if bound.ip().is_unspecified() { outbound_ip().unwrap_or(bound.ip()) } else { bound.ip() };
                format!("http://{}", SocketAddr::new(ip, bound.port()))
            }
        };
        if public.starts_with("http://") && !host_is_private(&public).await? && !opts.insecure {
            return Err(fail(exit::CONFIG, format!(
                "{public} is not a private address; over plain HTTP anyone on the path could rewrite the page. \
                 Put it behind TLS (e.g. a tunnel) and pass --public-url https://…, or pass --insecure."
            )));
        }
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let opts_r = relay::RelayOpts { max_ttl: ttl + Duration::from_secs(60), max_requests: 16, ..Default::default() };
        tokio::spawn(relay::serve(listener, opts_r, async move {
            let _ = rx.await;
        }));
        let local = format!("http://{}", SocketAddr::new(if bound.ip().is_unspecified() { [127, 0, 0, 1].into() } else { bound.ip() }, bound.port()));
        (RelayClient::new(&local, None)?, format!("{public}/"), None, Some(tx))
    } else {
        let relay_url = pick_relay(&opts).await.map_err(|e| fail(exit::RELAY, format!("{e:#}")))?;
        let client = RelayClient::new(&relay_url, opts.proxy.as_deref())?;
        client.health().await.map_err(|e| fail(exit::RELAY, format!("relay {relay_url}: {e:#}")))?;
        let (page, param) = match opts.page.as_deref() {
            Some("relay") => (format!("{}/", client.base), None),
            Some(p) => (p.to_owned(), Some(relay_url.clone())),
            None => (crate::default_page(), Some(relay_url.clone())),
        };
        if !opts.no_verify_page {
            verify_page(&client, &page).await?;
        }
        (client, page, param, None)
    };

    let plaintext = Zeroizing::new(serde_json::to_vec(&wire)?);
    let blob = k.seal_config(&plaintext)?;
    client
        .put_config(&id, &owner, ttl + Duration::from_secs(60), blob)
        .await
        .map_err(|e| fail(exit::RELAY, format!("{e:#}")))?;

    let mut link = format!("{link_base}#");
    if let Some(r) = &relay_param {
        link.push_str(&format!("r={}&", urlencode(r)));
    }
    link.push_str(&format!("k={}", k.to_b64()));
    let expires = UNIX_EPOCH + Duration::from_secs(wire.context.expires_at);
    say(format!("peekless: request ready — {}", cfg.title));
    say(format!("Link:        {link}"));
    say(format!("Fingerprint: {}", k.fingerprint()));
    say(format!("Expires:     {} (in {})", humantime::format_rfc3339_seconds(expires), humantime::format_duration(ttl)));
    say("Waiting for the user to answer…");

    // Long-poll until answered, expired, or interrupted.
    let deadline = tokio::time::Instant::now() + ttl;
    let blob = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            client.delete(&id, &owner).await;
            return Err(fail(exit::EXPIRED, "peekless: the request expired without an answer"));
        }
        let poll = tokio::select! {
            p = client.poll_answer(&id, &owner, left.min(Duration::from_secs(25))) => p,
            _ = tokio::signal::ctrl_c() => {
                client.delete(&id, &owner).await;
                return Err(fail(exit::INTERRUPTED, "peekless: interrupted; request cancelled"));
            }
        };
        match poll {
            Ok(Poll::Answer(b)) => break b,
            Ok(Poll::Pending) => {}
            Ok(Poll::Gone) => return Err(fail(exit::EXPIRED, "peekless: the relay dropped the request")),
            Err(e) => {
                eprintln!("peekless: relay error ({e:#}); retrying");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    };
    client.delete(&id, &owner).await;

    let plain = keys.open_answer(&id, &blob).map_err(|e| fail(exit::INVALID_ANSWER, format!("{e:#}")))?;
    let answer: Answer = serde_json::from_slice(&plain).map_err(|e| fail(exit::INVALID_ANSWER, format!("malformed answer: {e}")))?;
    drop(plain);
    if answer.declined {
        let why = answer.reason.as_deref().filter(|r| !r.trim().is_empty()).unwrap_or("no reason given");
        return Err(fail(exit::DECLINED, format!("peekless: the user declined: {why}")));
    }
    deliver(&cfg, &wire, &answer)
}

async fn verify_page(client: &RelayClient, page: &str) -> Result<()> {
    let got = client
        .get_bytes(page)
        .await
        .map_err(|e| fail(exit::RELAY, format!("fetching page {page}: {e:#}")))?;
    let want = Sha256::digest(relay::PAGE.as_bytes());
    if Sha256::digest(&got) != want {
        return Err(fail(
            exit::RELAY,
            format!(
                "the page at {page} is not the one this peekless {} ships (sha256 {:x}). It may be a \
                 different version, or tampered with. Use a matching page/relay, or pass --no-verify-page.",
                env!("CARGO_PKG_VERSION"),
                want
            ),
        ));
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn describe(value: &str, share: bool, pattern: Option<&str>, skipped: bool) -> String {
    let mut parts = Vec::new();
    if share {
        parts.push(format!("{} chars", value.chars().count()));
        let mut classes = Vec::new();
        if value.chars().any(|c| c.is_ascii_lowercase()) {
            classes.push("a-z");
        }
        if value.chars().any(|c| c.is_ascii_uppercase()) {
            classes.push("A-Z");
        }
        if value.chars().any(|c| c.is_ascii_digit()) {
            classes.push("0-9");
        }
        if value.chars().any(|c| c.is_ascii_punctuation()) {
            classes.push("symbols");
        }
        if !value.is_ascii() {
            classes.push("non-ASCII");
        }
        if !classes.is_empty() {
            parts.push(classes.join(" "));
        }
        let h = Sha256::digest(value.as_bytes());
        parts.push(format!("sha256 {:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3]));
    } else if value.is_empty() {
        parts.push("empty".into());
    } else {
        parts.push("present".into());
    }
    if pattern.is_some() {
        parts.push(if skipped { "pattern skipped by user".into() } else { "pattern ok".into() });
    }
    if value != value.trim() {
        parts.push("has leading/trailing whitespace".into());
    }
    if value.contains('\n') {
        parts.push("multi-line".into());
    }
    format!("[redacted: {}]", parts.join("; "))
}

/// Validate the answer, report it safely, write files, run the command.
fn deliver(cfg: &Config, wire: &WireConfig, answer: &Answer) -> Result<i32> {
    for name in answer.fields.keys() {
        if !cfg.fields.iter().any(|f| &f.name == name) {
            return Err(fail(exit::INVALID_ANSWER, format!("answer has unknown field {name}")));
        }
    }
    say("peekless: answer received.");
    let width = cfg.fields.iter().map(|f| f.name.len()).max().unwrap_or(0);
    let mut values: HashMap<&str, &str> = HashMap::new();
    let mut secrets: Vec<(&str, &str)> = Vec::new();
    let mut notes = Vec::new();
    for f in &cfg.fields {
        let a = answer.fields.get(&f.name);
        let value = a.map(|a| a.value.as_str()).unwrap_or("");
        let secret = a.map(|a| a.secret).unwrap_or(f.secret);
        let share = a.map(|a| a.share_metadata).unwrap_or(f.share_metadata);
        let skipped = a.is_some_and(|a| a.skip_validation);
        if value.is_empty() && !f.optional {
            return Err(fail(exit::INVALID_ANSWER, format!("required field {} is empty", f.name)));
        }
        if let (Some(p), false, false) = (&f.pattern, skipped, value.is_empty()) {
            if !regex::Regex::new(p)?.is_match(value) {
                return Err(fail(exit::INVALID_ANSWER, format!("{} does not match its pattern (and the user did not skip validation)", f.name)));
            }
        }
        if secret != f.secret {
            notes.push(format!(
                "note: the user marked {} as {} (the request said {}).",
                f.name,
                if secret { "secret" } else { "plain" },
                if f.secret { "secret" } else { "plain" }
            ));
        }
        if secret && share != f.share_metadata {
            notes.push(format!(
                "note: the user {} metadata for {}.",
                if share { "chose to share" } else { "withheld" },
                f.name
            ));
        }
        let shown = if secret {
            describe(value, share, f.pattern.as_deref(), skipped)
        } else {
            serde_json::to_string(value)?
        };
        say(format!("  {:width$}  {:6}  {shown}", f.name, if secret { "secret" } else { "plain" }));
        values.insert(&f.name, value);
        if secret {
            if !value.is_empty() && value.len() < scrub::MIN_LEN {
                notes.push(format!("note: {} is under {} bytes, so it can't be scrubbed from output.", f.name, scrub::MIN_LEN));
            }
            secrets.push((&f.name, value));
        }
    }
    for n in notes {
        say(n);
    }

    // Files: all-or-nothing preflight, then atomic writes.
    for f in &cfg.files {
        if Path::new(&f.path).exists() && !f.overwrite {
            return Err(fail(exit::DELIVERY, format!("{} appeared while waiting and overwrite is false", f.path)));
        }
    }
    let mut written = Vec::new();
    for f in &cfg.files {
        let body = template::render(&f.template, f.format, &values)?;
        let mode = u32::from_str_radix(f.mode.trim_start_matches("0o"), 8)?;
        write_atomic(Path::new(&f.path), body.as_bytes(), mode)
            .map_err(|e| fail(exit::DELIVERY, format!("writing {}: {e:#}", f.path)))?;
        say(format!("peekless: wrote {} ({:04o})", f.path, mode));
        if f.cleanup == Cleanup::AfterRun {
            written.push(PathBuf::from(&f.path));
        }
    }

    let code = match (&cfg.run, &wire.exec) {
        (Some(run), Some(argv)) => {
            let scrubber = Scrubber::new(&secrets);
            let result = exec(run, argv, cfg, &values, &scrubber);
            for p in &written {
                let _ = std::fs::remove_file(p);
                say(format!("peekless: removed {}", p.display()));
            }
            result?
        }
        _ => {
            for p in &written {
                let _ = std::fs::remove_file(p);
            }
            0
        }
    };
    Ok(code)
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.peekless-{}", path.file_name().unwrap().to_string_lossy(), crypto::b64(&crypto::random_bytes::<6>())));
    let res = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn exec(run: &config::Run, argv: &[String], cfg: &Config, values: &HashMap<&str, &str>, scrubber: &Scrubber) -> Result<i32> {
    let cwd = run.cwd.clone().unwrap_or_else(|| ".".into());
    // An inline script runs from a private copy, so what the user read is what runs.
    let script_dir = match &run.script {
        Some(script) => {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
            let dir = base.join(format!("peekless-{}", crypto::b64(&crypto::random_bytes::<9>())));
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            let path = dir.join("script");
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o500).open(&path)?;
            f.write_all(script.as_bytes())?;
            Some((dir, path))
        }
        None => None,
    };
    let mut cmd = match &script_dir {
        Some((_, path)) => {
            let mut c = Command::new(&argv[0]);
            c.args(&argv[1..argv.len() - 1]).arg(path);
            c
        }
        None => {
            let mut c = Command::new(&argv[0]);
            c.args(&argv[1..]);
            c
        }
    };
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with(ENV_PREFIX) {
            cmd.env_remove(k);
        }
    }
    for f in &cfg.fields {
        cmd.env(format!("{ENV_PREFIX}{}", f.name), values.get(f.name.as_str()).copied().unwrap_or(""));
    }
    cmd.current_dir(&cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    say(format!("peekless: running {}", shell_words::join(argv)));
    say("--- command output (secrets scrubbed) ---");
    let result = (|| -> Result<i32> {
        let mut child = cmd.spawn().map_err(|e| fail(exit::DELIVERY, format!("starting {}: {e}", argv[0])))?;
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let status = std::thread::scope(|s| {
            let a = s.spawn(|| scrubber.pipe(out, std::io::stdout()));
            let b = s.spawn(|| scrubber.pipe(err, std::io::stderr()));
            let _ = a.join();
            let _ = b.join();
            child.wait()
        })?;
        use std::os::unix::process::ExitStatusExt;
        let code = status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
        say(format!("--- exit status {code} ---"));
        Ok(code)
    })();
    if let Some((dir, _)) = script_dir {
        let _ = std::fs::remove_dir_all(dir);
    }
    result
}
