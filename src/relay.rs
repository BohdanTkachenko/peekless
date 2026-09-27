//! The relay: a blind, in-memory mailbox. It stores one encrypted config and
//! at most one encrypted answer per request id, and never sees a key.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower_http::cors::{Any, CorsLayer};

pub const PROTOCOL: &str = "peekless/1";
/// Largest padded plaintext plus nonce, tag and ephemeral key.
pub const MAX_BODY: usize = (1 << 20) + 64;
pub const PAGE: &str = include_str!("../page/index.html");

#[derive(Clone, Debug)]
pub struct RelayOpts {
    pub max_ttl: Duration,
    pub max_requests: usize,
    pub max_wait: Duration,
}

impl Default for RelayOpts {
    fn default() -> Self {
        Self {
            max_ttl: Duration::from_secs(24 * 3600),
            max_requests: 10_000,
            max_wait: Duration::from_secs(60),
        }
    }
}

struct Entry {
    config: Bytes,
    answer: Option<Bytes>,
    owner: [u8; 32],
    expires: Instant,
    notify: Arc<Notify>,
}

#[derive(Clone)]
struct AppState {
    opts: RelayOpts,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

pub fn router(opts: RelayOpts) -> Router {
    let state = AppState { opts, entries: Default::default() };
    let sweeper = state.entries.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let now = Instant::now();
            sweeper.lock().unwrap().retain(|_, e| e.expires > now);
        }
    });
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::PUT, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-peekless-ttl"),
        ])
        .max_age(Duration::from_secs(600));
    Router::new()
        .route("/", get(page))
        .route("/index.html", get(page))
        .route("/v1/health", get(health))
        .route("/v1/r/{id}", axum::routing::delete(delete_request))
        .route("/v1/r/{id}/config", get(get_config).put(put_config))
        .route("/v1/r/{id}/answer", get(get_answer).put(put_answer))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(cors)
        .with_state(state)
}

pub async fn serve(listener: TcpListener, opts: RelayOpts, shutdown: impl Future<Output = ()> + Send + 'static) -> std::io::Result<()> {
    axum::serve(listener, router(opts)).with_graceful_shutdown(shutdown).await
}

async fn page() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (HeaderName::from_static("x-content-type-options"), "nosniff"),
            (HeaderName::from_static("x-frame-options"), "DENY"),
        ],
        PAGE,
    )
        .into_response()
}

async fn health(State(s): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "protocol": PROTOCOL,
        "version": env!("CARGO_PKG_VERSION"),
        "max_ttl": s.opts.max_ttl.as_secs(),
        "max_body": MAX_BODY,
    }))
}

fn valid_id(id: &str) -> bool {
    id.len() == 22 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn owner_hash(h: &HeaderMap) -> Option<[u8; 32]> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    (v.len() >= 32).then(|| Sha256::digest(v.as_bytes()).into())
}

fn octets(b: Bytes) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "no-store")], b).into_response()
}

async fn put_config(State(s): State<AppState>, Path(id): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    if !valid_id(&id) || body.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(owner) = owner_hash(&h) else { return StatusCode::UNAUTHORIZED.into_response() };
    let ttl = h
        .get("x-peekless-ttl")
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(3600));
    if ttl.is_zero() || ttl > s.opts.max_ttl {
        return (StatusCode::BAD_REQUEST, "ttl out of range").into_response();
    }
    let mut entries = s.entries.lock().unwrap();
    let now = Instant::now();
    entries.retain(|_, e| e.expires > now);
    if entries.contains_key(&id) {
        return StatusCode::CONFLICT.into_response();
    }
    if entries.len() >= s.opts.max_requests {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    entries.insert(id, Entry { config: body, answer: None, owner, expires: now + ttl, notify: Arc::new(Notify::new()) });
    StatusCode::CREATED.into_response()
}

async fn get_config(State(s): State<AppState>, Path(id): Path<String>) -> Response {
    let entries = s.entries.lock().unwrap();
    match entries.get(&id) {
        Some(e) if e.expires <= Instant::now() => StatusCode::NOT_FOUND.into_response(),
        Some(e) if e.answer.is_some() => StatusCode::GONE.into_response(),
        Some(e) => octets(e.config.clone()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn put_answer(State(s): State<AppState>, Path(id): Path<String>, body: Bytes) -> Response {
    if body.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut entries = s.entries.lock().unwrap();
    match entries.get_mut(&id) {
        Some(e) if e.expires <= Instant::now() => StatusCode::NOT_FOUND.into_response(),
        // First answer wins; the link is spent.
        Some(e) if e.answer.is_some() => StatusCode::CONFLICT.into_response(),
        Some(e) => {
            e.answer = Some(body);
            e.notify.notify_waiters();
            StatusCode::CREATED.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(serde::Deserialize)]
struct WaitQuery {
    wait: Option<u64>,
}

async fn get_answer(State(s): State<AppState>, Path(id): Path<String>, h: HeaderMap, Query(q): Query<WaitQuery>) -> Response {
    let Some(owner) = owner_hash(&h) else { return StatusCode::UNAUTHORIZED.into_response() };
    let wait = Duration::from_secs(q.wait.unwrap_or(0)).min(s.opts.max_wait);
    let notify = {
        let entries = s.entries.lock().unwrap();
        match entries.get(&id) {
            None => return StatusCode::NOT_FOUND.into_response(),
            Some(e) if e.owner != owner => return StatusCode::FORBIDDEN.into_response(),
            Some(e) if e.expires <= Instant::now() => return StatusCode::NOT_FOUND.into_response(),
            Some(e) => match &e.answer {
                Some(a) => return octets(a.clone()),
                None => e.notify.clone(),
            },
        }
    };
    if !wait.is_zero() {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // Re-check after registering, so an answer that landed in between isn't missed.
        let answered = s.entries.lock().unwrap().get(&id).is_some_and(|e| e.answer.is_some());
        if !answered {
            let _ = tokio::time::timeout(wait, notified).await;
        }
    }
    let entries = s.entries.lock().unwrap();
    match entries.get(&id) {
        Some(e) => match &e.answer {
            Some(a) => octets(a.clone()),
            None => StatusCode::NO_CONTENT.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_request(State(s): State<AppState>, Path(id): Path<String>, h: HeaderMap) -> Response {
    let Some(owner) = owner_hash(&h) else { return StatusCode::UNAUTHORIZED.into_response() };
    let mut entries = s.entries.lock().unwrap();
    match entries.get(&id) {
        Some(e) if e.owner != owner => StatusCode::FORBIDDEN.into_response(),
        Some(_) => {
            entries.remove(&id);
            StatusCode::NO_CONTENT.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
