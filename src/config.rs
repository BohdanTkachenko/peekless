//! The request config the agent writes, the wire form the page renders, and the
//! answer the page sends back.

use crate::template::{self, Format};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub const ENV_PREFIX: &str = "PEEKLESS_";
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// One line: what the agent needs and why.
    pub title: String,
    /// Page-level instructions for the user.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instructions: String,
    /// How long to wait for an answer, e.g. "30m". Default 1h, max 24h.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<Run>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// Upper-case identifier; exported as PEEKLESS_<NAME>.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// How to obtain the value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub steps: String,
    /// Redacted everywhere the agent can see (the user may flip this).
    #[serde(default = "yes")]
    pub secret: bool,
    /// Report length / character classes / fingerprint to the agent (the user may flip this).
    #[serde(default)]
    pub share_metadata: bool,
    /// Regex the value should match (use the subset shared by JS and Rust regex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_hint: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub multiline: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// argv; no shell unless you write ["sh", "-c", "..."] yourself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Inline script; shown to the user verbatim and executed from a private copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// Interpreter for `script`. Default ["sh", "-eu"].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    pub path: String,
    pub template: String,
    #[serde(default)]
    pub format: Format,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub cleanup: Cleanup,
}

fn default_mode() -> String {
    "0600".into()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cleanup {
    #[default]
    Never,
    AfterRun,
}

/// What gets encrypted for the page: the config with paths made absolute, plus
/// everything the user needs to judge it.
#[derive(Debug, Serialize, Deserialize)]
pub struct WireConfig {
    pub v: u32,
    pub config: Config,
    pub context: RequestContext,
    /// X25519 public key answers are sealed to (base64url).
    pub pubkey: String,
    /// The exact argv that will be executed (argv[0] resolved through PATH).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub env_prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestContext {
    pub host: String,
    pub user: String,
    pub cwd: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub peekless_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Answer {
    pub v: u32,
    #[serde(default)]
    pub declined: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, AnswerField>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnswerField {
    pub value: String,
    pub secret: bool,
    pub share_metadata: bool,
    #[serde(default)]
    pub skip_validation: bool,
}

impl Drop for AnswerField {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        );
        // YAML is a superset of JSON, so this reads both.
        serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn ttl(&self) -> Result<Duration> {
        match &self.ttl {
            None => Ok(DEFAULT_TTL),
            Some(s) => {
                let d = humantime::parse_duration(s).with_context(|| format!("invalid ttl {s:?}"))?;
                if d > MAX_TTL {
                    bail!("ttl {s} exceeds the 24h maximum");
                }
                Ok(d)
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            bail!("title is required");
        }
        self.ttl()?;
        if self.fields.is_empty() {
            bail!("at least one field is required");
        }
        let name_re = regex::Regex::new("^[A-Z][A-Z0-9_]*$").unwrap();
        let mut names = HashSet::new();
        for f in &self.fields {
            if !name_re.is_match(&f.name) {
                bail!("field name {:?} must match ^[A-Z][A-Z0-9_]*$", f.name);
            }
            if !names.insert(f.name.as_str()) {
                bail!("duplicate field name {}", f.name);
            }
            if let Some(p) = &f.pattern {
                regex::Regex::new(p).with_context(|| format!("field {}: invalid pattern", f.name))?;
            }
        }
        if self.run.is_none() && self.files.is_empty() {
            bail!("nothing would receive the values: add `run` and/or `files`");
        }
        if let Some(run) = &self.run {
            match (&run.cmd, &run.script) {
                (Some(c), None) if c.is_empty() => bail!("run.cmd is empty"),
                (Some(_), None) | (None, Some(_)) => {}
                _ => bail!("run needs exactly one of `cmd` or `script`"),
            }
            if run.interpreter.is_some() && run.script.is_none() {
                bail!("run.interpreter only applies to run.script");
            }
        }
        let mut paths = HashSet::new();
        for file in &self.files {
            if !paths.insert(&file.path) {
                bail!("file {} listed twice", file.path);
            }
            u32::from_str_radix(file.mode.trim_start_matches("0o"), 8)
                .ok()
                .filter(|m| *m <= 0o777)
                .with_context(|| format!("file {}: invalid mode {:?}", file.path, file.mode))?;
            template::check(&file.template, file.format, &names)
                .with_context(|| format!("file {}", file.path))?;
        }
        Ok(())
    }

    /// Absolute cwd, with `~` expanded.
    pub fn cwd(&self) -> Result<PathBuf> {
        let here = std::env::current_dir()?;
        Ok(match self.run.as_ref().and_then(|r| r.cwd.as_deref()) {
            Some(c) => here.join(expand_home(c)),
            None => here,
        })
    }

    /// Make every path absolute so the page shows exactly what will be touched.
    pub fn resolve_paths(&mut self) -> Result<()> {
        let cwd = self.cwd()?;
        if let Some(run) = &mut self.run {
            run.cwd = Some(cwd.display().to_string());
        }
        for f in &mut self.files {
            f.path = cwd.join(expand_home(&f.path)).display().to_string();
        }
        Ok(())
    }
}

pub fn expand_home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ if p == "~" => std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| p.into()),
        _ => PathBuf::from(p),
    }
}

/// Resolve argv[0] through PATH the way execvp would.
pub fn resolve_program(prog: &str, cwd: &Path) -> Option<PathBuf> {
    if prog.contains('/') {
        let p = cwd.join(prog);
        return p.exists().then_some(p);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(prog))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// Heuristic: flag arguments (and words inside `sh -c` strings) that name
/// existing local files. The page can't show their contents, so the user
/// should know they're trusting them.
pub fn file_reference_warnings(argv: &[String], cwd: &Path) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    for (i, a) in argv.iter().enumerate() {
        if i == 0 {
            continue;
        }
        words.push(a.clone());
        // Words of an inline shell program.
        if let Ok(parts) = shell_words::split(a) {
            if parts.len() > 1 {
                words.extend(parts);
            }
        }
    }
    for w in words {
        let w = w.trim_matches(|c: char| c == ';' || c == '&' || c == '|' || c == '(' || c == ')');
        if w.is_empty() || w.starts_with('-') || w.contains('\n') || w.len() > 4096 {
            continue;
        }
        let looks_like_path = w.contains('/') || w.contains('.');
        if !looks_like_path {
            continue;
        }
        let p = cwd.join(expand_home(w));
        if p.is_file() && seen.insert(p.clone()) {
            let kind = if is_executable(&p) { "runs or reads" } else { "reads" };
            out.push(format!(
                "The command {kind} the local file {} — its contents are not shown here.",
                p.display()
            ));
        }
    }
    out
}
