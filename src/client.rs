//! HTTP client for the relay protocol (spec/protocol.md).

use anyhow::{bail, Context, Result};
use reqwest::StatusCode;
use std::time::Duration;

pub struct RelayClient {
    pub base: String,
    http: reqwest::Client,
}

pub enum Poll {
    Answer(Vec<u8>),
    Pending,
    Gone,
}

pub fn http_client(proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .connect_timeout(Duration::from_secs(15))
        .user_agent(concat!("peekless/", env!("CARGO_PKG_VERSION")));
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p).context("invalid --proxy")?);
    }
    Ok(b.build()?)
}

impl RelayClient {
    pub fn new(base: &str, proxy: Option<&str>) -> Result<Self> {
        Ok(Self { base: base.trim_end_matches('/').to_owned(), http: http_client(proxy)? })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn health(&self) -> Result<serde_json::Value> {
        let r = self
            .http
            .get(self.url("/v1/health"))
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .error_for_status()?;
        let v: serde_json::Value = r.json().await?;
        if v["protocol"] != crate::relay::PROTOCOL {
            bail!("{} speaks {:?}, not {}", self.base, v["protocol"], crate::relay::PROTOCOL);
        }
        Ok(v)
    }

    pub async fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let r = self.http.get(url).send().await?.error_for_status()?;
        Ok(r.bytes().await?.to_vec())
    }

    pub async fn put_config(&self, id: &str, owner: &str, ttl: Duration, blob: Vec<u8>) -> Result<()> {
        let r = self
            .http
            .put(self.url(&format!("/v1/r/{id}/config")))
            .bearer_auth(owner)
            .header("x-peekless-ttl", ttl.as_secs().to_string())
            .header("content-type", "application/octet-stream")
            .body(blob)
            .send()
            .await
            .with_context(|| format!("contacting relay {}", self.base))?;
        if r.status() != StatusCode::CREATED {
            bail!("relay refused the request: {} {}", r.status(), r.text().await.unwrap_or_default());
        }
        Ok(())
    }

    pub async fn get_config(&self, id: &str) -> Result<Vec<u8>> {
        let r = self.http.get(self.url(&format!("/v1/r/{id}/config"))).send().await?;
        match r.status() {
            StatusCode::OK => Ok(r.bytes().await?.to_vec()),
            StatusCode::GONE => bail!("this request was already answered"),
            StatusCode::NOT_FOUND => bail!("request not found — it expired, was cancelled, or was already answered"),
            s => bail!("relay error: {s}"),
        }
    }

    pub async fn put_answer(&self, id: &str, blob: Vec<u8>) -> Result<()> {
        let r = self
            .http
            .put(self.url(&format!("/v1/r/{id}/answer")))
            .header("content-type", "application/octet-stream")
            .body(blob)
            .send()
            .await?;
        match r.status() {
            StatusCode::CREATED => Ok(()),
            StatusCode::CONFLICT => bail!("this request was already answered"),
            StatusCode::NOT_FOUND => bail!("request not found — it expired, was cancelled, or was already answered"),
            s => bail!("relay error: {s}"),
        }
    }

    pub async fn poll_answer(&self, id: &str, owner: &str, wait: Duration) -> Result<Poll> {
        let r = self
            .http
            .get(self.url(&format!("/v1/r/{id}/answer?wait={}", wait.as_secs())))
            .bearer_auth(owner)
            .send()
            .await?;
        Ok(match r.status() {
            StatusCode::OK => Poll::Answer(r.bytes().await?.to_vec()),
            StatusCode::NO_CONTENT => Poll::Pending,
            StatusCode::NOT_FOUND => Poll::Gone,
            s => bail!("relay error while waiting: {s}"),
        })
    }

    pub async fn delete(&self, id: &str, owner: &str) {
        let _ = self
            .http
            .delete(self.url(&format!("/v1/r/{id}")))
            .bearer_auth(owner)
            .timeout(Duration::from_secs(5))
            .send()
            .await;
    }
}
