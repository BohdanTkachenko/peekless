//! Wire crypto, mirrored byte-for-byte by page/index.html. See spec/protocol.md.
//!
//! K (32 random bytes) lives only in the link fragment. Everything else derives
//! from it with HKDF-SHA256 (salt "peekless/v1"):
//!   id          = HKDF(K, "id")[..16], base64url — the only name the relay sees
//!   config key  = HKDF(K, "config")    — AES-256-GCM over the padded config
//!   fingerprint = HKDF(K, "fingerprint")[..3] — four emoji, shown on both sides
//! Answers are sealed to the request's X25519 key (carried inside the config):
//!   ka = HKDF(X25519(eph, pk_r), salt = epk || pk_r, "answer:" || id)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const SALT: &[u8] = b"peekless/v1";
const NONCE_LEN: usize = 12;

/// Plaintexts are padded to one of these sizes so the relay only learns a
/// coarse size class. The first 4 bytes of a padded buffer are the real length.
pub const BUCKETS: [usize; 5] = [4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20];
pub const MAX_PLAINTEXT: usize = (1 << 20) - 4;

/// 64 single-codepoint emoji; the fingerprint is 4 of them (24 bits).
pub const EMOJI: [&str; 64] = [
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔",
    "🐧", "🐦", "🐤", "🦆", "🦉", "🐴", "🦄", "🐝", "🐛", "🦋", "🐌", "🐞", "🐢", "🐍", "🦖", "🐙",
    "🦑", "🦀", "🐬", "🐳", "🦈", "🐊", "🦓", "🦒", "🐘", "🦏", "🐪", "🦘", "🌵", "🌲", "🌻", "🍄",
    "🌙", "🔥", "🌈", "🍎", "🍋", "🍉", "🍇", "🍓", "🍒", "🍍", "🥕", "🌽", "🍩", "🍪", "🎈", "🚀",
];

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim()).context("invalid base64url")
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF output length is valid");
}

/// The link secret K.
pub struct LinkKey(pub Zeroizing<[u8; 32]>);

impl LinkKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes()))
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        let v = unb64(s)?;
        let arr: [u8; 32] = v.as_slice().try_into().context("link key must be 32 bytes")?;
        Ok(Self(Zeroizing::new(arr)))
    }

    pub fn to_b64(&self) -> String {
        b64(&*self.0)
    }

    pub fn request_id(&self) -> String {
        let mut out = [0u8; 16];
        hkdf(&*self.0, SALT, b"id", &mut out);
        b64(&out)
    }

    fn config_key(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        hkdf(&*self.0, SALT, b"config", &mut *out);
        out
    }

    pub fn fingerprint(&self) -> String {
        let mut b = [0u8; 3];
        hkdf(&*self.0, SALT, b"fingerprint", &mut b);
        let bits = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        (0..4)
            .map(|i| EMOJI[((bits >> (18 - 6 * i)) & 63) as usize])
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn seal_config(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let aad = format!("peekless/v1/config:{}", self.request_id());
        seal(&self.config_key(), aad.as_bytes(), plaintext, &[])
    }

    pub fn open_config(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let aad = format!("peekless/v1/config:{}", self.request_id());
        open(&self.config_key(), aad.as_bytes(), blob)
    }
}

pub fn pad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() > MAX_PLAINTEXT {
        bail!("payload too large ({} bytes, max {MAX_PLAINTEXT})", data.len());
    }
    let size = BUCKETS.iter().copied().find(|b| data.len() + 4 <= *b).unwrap();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(size, 0);
    Ok(out)
}

pub fn unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 4 {
        bail!("padded payload too short");
    }
    let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    if len > data.len() - 4 {
        bail!("padded payload length out of range");
    }
    Ok(Zeroizing::new(data[4..4 + len].to_vec()))
}

/// prefix || nonce || AES-256-GCM(pad(plaintext))
fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8], prefix: &[u8]) -> Result<Vec<u8>> {
    let padded = pad(plaintext)?;
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &padded, aad })
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(prefix.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN + 16 {
        bail!("ciphertext too short");
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let padded = Zeroizing::new(
        Aes256Gcm::new(key.into())
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| anyhow::anyhow!("decryption failed (wrong key or tampered data)"))?,
    );
    unpad(&padded)
}

fn answer_key(shared: &[u8; 32], epk: &[u8; 32], pk_r: &[u8; 32], id: &str) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(pk_r);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf(shared, &salt, format!("answer:{id}").as_bytes(), &mut *out);
    out
}

/// The request's answer key pair. The secret half never leaves process memory.
pub struct RequestKeys {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl RequestKeys {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// blob = epk(32) || nonce(12) || AES-256-GCM(pad(answer))
    pub fn open_answer(&self, id: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 32 {
            bail!("answer too short");
        }
        let epk: [u8; 32] = blob[..32].try_into().unwrap();
        let shared = self.secret.diffie_hellman(&PublicKey::from(epk));
        if !shared.was_contributory() {
            bail!("answer uses a degenerate ephemeral key");
        }
        let ka = answer_key(shared.as_bytes(), &epk, &self.public, id);
        open(&ka, format!("peekless/v1/answer:{id}").as_bytes(), &blob[32..])
    }
}

/// Seal an answer to a request's public key (used by `peekless fill`).
pub fn seal_answer(pk_r: &[u8; 32], id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*pk_r));
    if !shared.was_contributory() {
        bail!("request public key is degenerate");
    }
    let ka = answer_key(shared.as_bytes(), &epk, pk_r, id);
    seal(&ka, format!("peekless/v1/answer:{id}").as_bytes(), plaintext, &epk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_are_distinct() {
        let set: std::collections::HashSet<_> = EMOJI.iter().collect();
        assert_eq!(set.len(), 64);
    }

    #[test]
    fn config_roundtrip() {
        let k = LinkKey::generate();
        let blob = k.seal_config(b"hello").unwrap();
        assert_eq!(blob.len(), NONCE_LEN + 4096 + 16);
        assert_eq!(&*k.open_config(&blob).unwrap(), b"hello");
        assert!(LinkKey::generate().open_config(&blob).is_err());
    }

    #[test]
    fn answer_roundtrip() {
        let keys = RequestKeys::generate();
        let blob = seal_answer(&keys.public, "abc", b"secret").unwrap();
        assert_eq!(&*keys.open_answer("abc", &blob).unwrap(), b"secret");
        assert!(keys.open_answer("other", &blob).is_err());
    }

    #[test]
    fn padding_buckets() {
        assert_eq!(pad(&[0; 4092]).unwrap().len(), 4096);
        assert_eq!(pad(&[0; 4093]).unwrap().len(), 16384);
        assert!(pad(&vec![0; MAX_PLAINTEXT + 1]).is_err());
    }
}
