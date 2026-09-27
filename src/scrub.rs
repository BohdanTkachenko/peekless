//! Streaming redaction of secret values from the command's output.

use base64::Engine;
use std::io::{Read, Write};

/// Values shorter than this aren't scrubbed: replacing every "a" would wreck
/// the output while protecting nothing.
pub const MIN_LEN: usize = 4;

pub struct Scrubber {
    needles: Vec<(Vec<u8>, Vec<u8>)>,
    max: usize,
}

impl Scrubber {
    /// `secrets` = (field name, value). Also catches common re-encodings.
    pub fn new(secrets: &[(&str, &str)]) -> Self {
        let mut needles = Vec::new();
        for (name, v) in secrets {
            if v.len() < MIN_LEN {
                continue;
            }
            let label = format!("[peekless:{name}]").into_bytes();
            let mut forms = vec![v.to_string(), base64::engine::general_purpose::STANDARD.encode(v)];
            if let Ok(j) = serde_json::to_string(v) {
                forms.push(j[1..j.len() - 1].to_string());
            }
            forms.push(v.trim().to_string());
            for f in forms {
                if f.len() >= MIN_LEN && !needles.iter().any(|(n, _)| *n == f.as_bytes()) {
                    needles.push((f.into_bytes(), label.clone()));
                }
            }
        }
        // Longest first, so a value that contains another is replaced whole.
        needles.sort_by_key(|n| std::cmp::Reverse(n.0.len()));
        let max = needles.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        Self { needles, max }
    }

    /// Copy `r` to `w`, replacing secrets, holding back just enough bytes to
    /// catch a match split across reads.
    pub fn pipe(&self, mut r: impl Read, mut w: impl Write) -> std::io::Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = r.read(&mut chunk)?;
            let eof = n == 0;
            buf.extend_from_slice(&chunk[..n]);
            let keep = if eof { 0 } else { self.max.saturating_sub(1) };
            let (out, consumed) = self.process(&buf, keep);
            w.write_all(&out)?;
            w.flush()?;
            buf.drain(..consumed);
            if eof {
                return Ok(());
            }
        }
    }

    fn process(&self, buf: &[u8], keep: usize) -> (Vec<u8>, usize) {
        let limit = buf.len().saturating_sub(keep);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'outer: while i < limit {
            for (needle, label) in &self.needles {
                if buf[i..].starts_with(needle) {
                    out.extend_from_slice(label);
                    i += needle.len();
                    continue 'outer;
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Trickle<'a>(&'a [u8]);
    impl Read for Trickle<'_> {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() || b.is_empty() {
                return Ok(0);
            }
            b[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }

    #[test]
    fn scrubs_across_reads_and_encodings() {
        let s = Scrubber::new(&[("TOKEN", "hunter22"), ("PIN", "123")]);
        let mut out = Vec::new();
        s.pipe(Trickle(b"a hunter22 b aHVudGVyMjI= 123\n"), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "a [peekless:TOKEN] b [peekless:TOKEN] 123\n");
    }
}
