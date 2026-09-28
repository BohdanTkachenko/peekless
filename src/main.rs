mod client;
mod config;
mod crypto;
mod fill;
mod relay;
mod run;
mod scrub;
mod template;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Every release's page is published at `<PAGE_BASE>v<version>/`, so a CLI
/// always links (and verifies) the exact page it embeds.
pub const PAGE_BASE: &str = "https://bohdantkachenko.github.io/peekless/";

pub fn default_page() -> String {
    format!("{PAGE_BASE}v{}/", env!("CARGO_PKG_VERSION"))
}

#[derive(Parser)]
#[command(version, about = "Hand secrets to an AI agent's command without the agent ever seeing them")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Publish a request, print the link, wait for the answer, then write the
    /// files and run the command from the config. Exits with the command's status.
    Run {
        /// Request config (YAML or JSON).
        config: PathBuf,
        /// Relay base URL. Default: `relay` in ~/.config/peekless/config.yaml, else
        /// the first healthy relay in the bundled list.
        #[arg(long, conflicts_with = "serve")]
        relay: Option<String>,
        /// Run a relay in-process on this address and serve the page from it
        /// (e.g. 0.0.0.0:8080 when the user is on the same network).
        #[arg(long)]
        serve: Option<SocketAddr>,
        /// URL the user reaches --serve at (default: http://<LAN address>:<port>).
        #[arg(long, requires = "serve")]
        public_url: Option<String>,
        /// Page URL to put in the link. Default: this release's page on GitHub
        /// Pages. `relay` uses the page the relay itself serves.
        #[arg(long, conflicts_with = "serve")]
        page: Option<String>,
        /// Skip checking that the page is byte-identical to this release's.
        #[arg(long)]
        no_verify_page: bool,
        /// Proxy for relay traffic, e.g. socks5h://127.0.0.1:9050 for Tor.
        #[arg(long)]
        proxy: Option<String>,
        /// Allow --serve over plain HTTP on a non-private address.
        #[arg(long)]
        insecure: bool,
    },
    /// Validate a config and print exactly what the page will show.
    Check { config: PathBuf },
    /// Answer a request from the terminal (instead of the browser).
    Fill {
        link: String,
        /// Read a field's value from a file: NAME=PATH
        #[arg(long, value_parser = kv)]
        from_file: Vec<(String, String)>,
        /// Read a field's value from an environment variable: NAME=VAR
        #[arg(long, value_parser = kv)]
        from_env: Vec<(String, String)>,
        #[arg(long)]
        proxy: Option<String>,
        /// Send without asking for confirmation.
        #[arg(long)]
        yes: bool,
        /// Decline the request with this reason instead of answering.
        #[arg(long)]
        decline: Option<String>,
    },
    /// Run a relay.
    Relay {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(long, default_value = "24h", value_parser = humantime::parse_duration)]
        max_ttl: Duration,
        #[arg(long, default_value_t = 10_000)]
        max_requests: usize,
    },
    /// Print the SHA-256 of the page embedded in this build.
    PageHash,
    /// Check that a published page is byte-identical to this release's.
    VerifyPage {
        /// Default: this release's page on GitHub Pages.
        url: Option<String>,
    },
}

fn kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=').map(|(a, b)| (a.to_owned(), b.to_owned())).ok_or_else(|| format!("expected NAME=VALUE, got {s:?}"))
}

/// No core dumps, and no ptrace or /proc/<pid>/mem access from other
/// processes running as the same user.
fn harden() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}

#[tokio::main]
async fn main() {
    harden();
    let code = match real_main().await {
        Ok(code) => code,
        Err(e) => {
            if let Some(run::Exit(code, msg)) = e.downcast_ref::<run::Exit>() {
                eprintln!("{msg}");
                *code
            } else {
                eprintln!("peekless: {e:#}");
                1
            }
        }
    };
    std::process::exit(code);
}

async fn real_main() -> Result<i32> {
    match Cli::parse().cmd {
        Cmd::Run { config, relay, serve, public_url, page, no_verify_page, proxy, insecure } => {
            run::run(run::RunOpts { config, relay, serve, public_url, page, no_verify_page, proxy, insecure }).await
        }
        Cmd::Check { config } => run::check(&config).await.map(|_| 0),
        Cmd::Fill { link, from_file, from_env, proxy, yes, decline } => {
            fill::fill(fill::FillOpts { link, from_file, from_env, proxy, yes, decline }).await.map(|_| 0)
        }
        Cmd::Relay { listen, max_ttl, max_requests } => {
            let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
            eprintln!("peekless relay listening on http://{}", listener.local_addr()?);
            let opts = relay::RelayOpts { max_ttl, max_requests, ..Default::default() };
            relay::serve(listener, opts, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
            Ok(0)
        }
        Cmd::VerifyPage { url } => {
            let url = url.unwrap_or_else(default_page);
            let got = client::http_client(None)?.get(&url).send().await?.error_for_status()?.bytes().await?;
            let (got, want) = (Sha256::digest(&got), Sha256::digest(relay::PAGE.as_bytes()));
            println!("{url}\n  served:   sha256 {got:x}\n  expected: sha256 {want:x} (peekless {})", env!("CARGO_PKG_VERSION"));
            if got == want {
                println!("OK — identical to the page in this build.");
                println!("Provenance: gh attestation verify <saved page> --repo BohdanTkachenko/peekless");
                Ok(0)
            } else {
                println!("MISMATCH — a different version, or tampered with.");
                Ok(1)
            }
        }
        Cmd::PageHash => {
            println!("{:x}", Sha256::digest(relay::PAGE.as_bytes()));
            Ok(0)
        }
    }
}
