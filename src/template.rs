//! File templates: `{{ NAME }}` or `{{ NAME | filter }}` placeholders.
//!
//! The file's `format` picks the default filter, so every value is inserted as
//! a complete, correctly quoted token and a password containing `"`, `#` or a
//! newline can't break (or inject into) the file. `\{{` is a literal `{{`.

use anyhow::{bail, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Raw,
    Json,
    Yaml,
    Toml,
    Env,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Filter {
    Raw,
    Json,
    Env,
    Shell,
    Base64,
    Urlencode,
}

impl Filter {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "raw" => Self::Raw,
            "json" | "yaml" | "toml" => Self::Json,
            "env" => Self::Env,
            "shell" => Self::Shell,
            "base64" => Self::Base64,
            "urlencode" => Self::Urlencode,
            _ => bail!("unknown filter {s:?} (raw, json, yaml, toml, env, shell, base64, urlencode)"),
        })
    }

    fn default_for(f: Format) -> Self {
        match f {
            Format::Raw => Self::Raw,
            // JSON string syntax is also a valid YAML double-quoted scalar and a
            // valid TOML basic string (serde_json escapes control chars as \u00XX).
            Format::Json | Format::Yaml | Format::Toml => Self::Json,
            Format::Env => Self::Env,
            Format::Shell => Self::Shell,
        }
    }

    fn quotes(self) -> bool {
        matches!(self, Self::Json | Self::Env | Self::Shell)
    }

    fn apply(self, v: &str) -> Result<String> {
        Ok(match self {
            Self::Raw => v.to_owned(),
            Self::Json => serde_json::to_string(v)?,
            Self::Shell => format!("'{}'", v.replace('\'', r"'\''")),
            Self::Env => {
                if !v.contains('\'') && !v.contains('\n') {
                    format!("'{v}'")
                } else {
                    let mut s = String::from("\"");
                    for c in v.chars() {
                        match c {
                            '\\' | '"' | '$' | '`' => {
                                s.push('\\');
                                s.push(c)
                            }
                            '\n' => s.push_str("\\n"),
                            _ => s.push(c),
                        }
                    }
                    s.push('"');
                    s
                }
            }
            Self::Base64 => base64::engine::general_purpose::STANDARD.encode(v),
            Self::Urlencode => {
                let mut s = String::new();
                for b in v.bytes() {
                    if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                        s.push(b as char);
                    } else {
                        s.push_str(&format!("%{b:02X}"));
                    }
                }
                s
            }
        })
    }
}

enum Piece<'a> {
    Text(&'a str),
    Var { name: &'a str, filter: Option<Filter>, quoted_context: bool },
}

fn parse(t: &str) -> Result<Vec<Piece<'_>>> {
    let mut out = Vec::new();
    let mut rest = t;
    while let Some(i) = rest.find("{{") {
        if i > 0 && rest.as_bytes()[i - 1] == b'\\' {
            out.push(Piece::Text(&rest[..i - 1]));
            out.push(Piece::Text("{{"));
            rest = &rest[i + 2..];
            continue;
        }
        out.push(Piece::Text(&rest[..i]));
        let quoted_context = i > 0 && matches!(rest.as_bytes()[i - 1], b'"' | b'\'');
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else { bail!("unclosed {{{{ placeholder") };
        let inner = after[..j].trim();
        let (name, filter) = match inner.split_once('|') {
            Some((n, f)) => (n.trim(), Some(Filter::parse(f.trim())?)),
            None => (inner, None),
        };
        out.push(Piece::Var { name, filter, quoted_context });
        rest = &after[j + 2..];
    }
    out.push(Piece::Text(rest));
    Ok(out)
}

pub fn check(t: &str, format: Format, names: &HashSet<&str>) -> Result<()> {
    for p in parse(t)? {
        if let Piece::Var { name, filter, quoted_context } = p {
            if !names.contains(name) {
                bail!("template references unknown field {name:?}");
            }
            let f = filter.unwrap_or(Filter::default_for(format));
            if quoted_context && f.quotes() {
                bail!(
                    "placeholder {{{{ {name} }}}} is wrapped in quotes, but its filter already \
                     emits a quoted value — remove the surrounding quotes"
                );
            }
        }
    }
    Ok(())
}

pub fn render(t: &str, format: Format, values: &HashMap<&str, &str>) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(t.len()));
    for p in parse(t)? {
        match p {
            Piece::Text(s) => out.push_str(s),
            Piece::Var { name, filter, .. } => {
                // An optional field left empty renders as an empty value.
                let v = values.get(name).copied().unwrap_or("");
                let rendered = Zeroizing::new(filter.unwrap_or(Filter::default_for(format)).apply(v)?);
                out.push_str(&rendered);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(t: &str, f: Format, v: &str) -> String {
        render(t, f, &HashMap::from([("X", v)])).unwrap().to_string()
    }

    #[test]
    fn formats_quote_hostile_values() {
        let v = "a\"b'c\n$d";
        assert_eq!(r("k = {{ X }}", Format::Toml, v), r#"k = "a\"b'c\n$d""#);
        assert_eq!(r("X={{X}}", Format::Env, v), r#"X="a\"b'c\n\$d""#);
        assert_eq!(r("X={{X}}", Format::Env, "plain"), "X='plain'");
        assert_eq!(r("{{ X }}", Format::Shell, "it's"), r"'it'\''s'");
        assert_eq!(r("{{ X | urlencode }}", Format::Raw, "a b/c"), "a%20b%2Fc");
        assert_eq!(r(r"\{{ X }}", Format::Raw, "v"), "{{ X }}");
    }

    #[test]
    fn rejects_quoted_placeholders_and_unknown_names() {
        let names = HashSet::from(["X"]);
        assert!(check(r#"k = "{{ X }}""#, Format::Toml, &names).is_err());
        assert!(check(r#"k = "{{ X | raw }}""#, Format::Toml, &names).is_ok());
        assert!(check("{{ Y }}", Format::Raw, &names).is_err());
    }
}
