use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_smithy_http_client::tls;
use aws_smithy_types::timeout::TimeoutConfig;
use clap::Parser;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

const DEFAULT_REGION: &str = "us-east-1";
const CONNECT_TIMEOUT_SECS: u64 = 10;
const OPERATION_TIMEOUT_SECS: u64 = 300;
const ATTEMPT_TIMEOUT_SECS: u64 = 120;
const MAX_CONFIG_SIZE: u64 = 1_048_576; // 1 MiB
const MAX_CA_BUNDLE_SIZE: u64 = 10_485_760; // 10 MiB
const MAX_TARGET_LEN: usize = 2048;

// ──────────────────────────────────────────────
//  CLI
// ──────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "s3-get",
    about = "Download a file from an S3-compatible endpoint using ~/.mc/config.json aliases.\n\
             Emits a JSON result record to stdout (mc get equivalent).\n\n\
             TLS uses rustls + aws-lc-rs with X25519MLKEM768 as the preferred key exchange."
)]
struct Args {
    /// Source in the form  alias/bucket/key
    source: String,

    /// Local destination path.
    /// If omitted, the filename from the key is used in the current directory.
    /// If a directory or ends with '/', the filename from the key is appended.
    destination: Option<PathBuf>,

    /// Path to mc config file (default: ~/.mc/config.json)
    #[arg(long, env = "MC_CONFIG_DIR")]
    config: Option<PathBuf>,

    /// Override the region (default: us-east-1)
    #[arg(long)]
    region: Option<String>,

    /// Path to a PEM-encoded CA bundle to add to platform-native roots.
    #[arg(long)]
    ca_bundle: Option<PathBuf>,

    /// Write object content to stdout instead of a file.
    /// The JSON result record is suppressed on stdout; audit records
    /// still go to stderr.
    #[arg(long, default_value_t = false)]
    stdout: bool,

    /// Overwrite the destination file if it already exists.
    /// Without this flag, the application refuses to overwrite.
    #[arg(long, default_value_t = false)]
    overwrite: bool,

    /// Emit detailed error information.
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

// ──────────────────────────────────────────────
//  MinIO config.json model  (~/.mc/config.json)
// ──────────────────────────────────────────────

#[derive(Deserialize)]
struct McConfig {
    #[allow(dead_code)]
    version: String,
    aliases: HashMap<String, McAlias>,
}

/// Credentials held as [`SecretString`] (CWE-256/316).
/// `Debug` on `SecretString` emits `[REDACTED]` (CWE-532).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McAlias {
    url: String,
    access_key: SecretString,
    secret_key: SecretString,
    #[allow(dead_code)]
    api: Option<String>,
    path: Option<String>,
}

// ──────────────────────────────────────────────
//  JSON output models
// ──────────────────────────────────────────────

#[derive(Serialize)]
struct DownloadRecord {
    status: &'static str,
    #[serde(rename = "type")]
    record_type: &'static str,
    bucket: String,
    key: String,
    destination: String,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
    duration_ms: u128,
}

#[derive(Serialize)]
struct ErrorRecord {
    status: &'static str,
    error: String,
}

#[derive(Serialize)]
struct AuditStartRecord<'a> {
    event: &'static str,
    run_id: &'a str,
    alias: &'a str,
    endpoint: &'a str,
    bucket: &'a str,
    key: &'a str,
    destination: &'a str,
    region: &'a str,
    path_style: bool,
    pq_kx: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_bundle: Option<&'a str>,
}

#[derive(Serialize)]
struct AuditCompleteRecord<'a> {
    event: &'static str,
    run_id: &'a str,
    alias: &'a str,
    bucket: &'a str,
    key: &'a str,
    destination: &'a str,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<&'a str>,
    duration_ms: u128,
    outcome: &'static str,
}

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────

fn config_path(override_path: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.clone());
    }
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".mc").join("config.json"))
}

/// CWE-732: verify config file is not group/other accessible.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;
    let mode = meta.mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is accessible by group/others (mode {:o}). \
             Expected 0600. Fix with: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn load_config(path: &Path) -> Result<McConfig> {
    let meta =
        std::fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;
    if meta.len() > MAX_CONFIG_SIZE {
        bail!(
            "config file {} exceeds maximum allowed size ({} bytes)",
            path.display(),
            MAX_CONFIG_SIZE,
        );
    }
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: McConfig = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(cfg)
}

/// Split "alias/bucket/key/parts" → (alias, bucket, key).
/// Key is **required** for get operations.
fn parse_source(input: &str) -> Result<(String, String, String)> {
    let trimmed = input.trim_start_matches('/');
    let mut parts = trimmed.splitn(3, '/');

    let alias = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("source must start with an alias name")?
        .to_string();

    let bucket = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("source must include a bucket name (alias/bucket/key)")?
        .to_string();

    let key = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("source must include an object key (alias/bucket/key)")?
        .to_string();

    Ok((alias, bucket, key))
}

/// Extract the filename component from an S3 key.
/// e.g. "logs/2026/06/08/app.log" → "app.log"
fn filename_from_key(key: &str) -> Result<&str> {
    key.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .context("cannot derive filename from object key")
}

/// Resolve the local destination path.
///
/// - If destination is None → current dir + filename from key
/// - If destination is a directory or ends with '/' → append filename from key
/// - Otherwise → use as-is
fn resolve_destination(dest: Option<&PathBuf>, key: &str) -> Result<PathBuf> {
    let filename = filename_from_key(key)?;

    match dest {
        None => Ok(PathBuf::from(filename)),
        Some(p) => {
            let s = p.to_string_lossy();
            if s.ends_with('/') || s.ends_with('\\') || p.is_dir() {
                Ok(p.join(filename))
            } else {
                Ok(p.clone())
            }
        }
    }
}

fn resolve_path_style(alias: &McAlias) -> bool {
    match alias.path.as_deref() {
        Some("on") => true,
        Some("off") => false,
        _ => !alias.url.contains("amazonaws.com"),
    }
}

/// Format an SDK DateTime to RFC 3339.
fn format_dt(dt: Option<&aws_smithy_types::DateTime>) -> Option<String> {
    dt.map(|d| {
        d.fmt(aws_smithy_types::date_time::Format::DateTime)
            .unwrap_or_default()
            .to_string()
    })
}

// ──────────────────────────────────────────────
//  Main
// ──────────────────────────────────────────────

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        let err = ErrorRecord {
            status: "error",
            error: format!("{:#}", e),
        };
        eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    let run_id = Uuid::now_v7().to_string();
    let started = Instant::now();

    // ── Input validation (SI-10) ────────────────
    if args.source.len() > MAX_TARGET_LEN {
        bail!(
            "source string exceeds maximum allowed length ({} chars)",
            MAX_TARGET_LEN,
        );
    }

    // ── 1. Load mc config ───────────────────────
    let cfg_path = config_path(args.config.as_ref())?;
    check_permissions(&cfg_path)?;
    let cfg = load_config(&cfg_path)?;

    // ── 2. Resolve alias, bucket, key ───────────
    let (alias_name, bucket, key) = parse_source(&args.source)?;
    let alias = cfg.aliases.get(&alias_name).with_context(|| {
        if args.verbose {
            let known: Vec<&String> = cfg.aliases.keys().collect();
            format!(
                "alias '{}' not found in {}  (known aliases: {:?})",
                alias_name,
                cfg_path.display(),
                known,
            )
        } else {
            format!("alias '{}' not found in config", alias_name)
        }
    })?;

    let force_path = resolve_path_style(alias);
    let region_str = args.region.as_deref().unwrap_or(DEFAULT_REGION);

    // Resolve destination
    let dest_path = resolve_destination(args.destination.as_ref(), &key)?;
    let dest_display = if args.stdout {
        "<stdout>".to_string()
    } else {
        dest_path.display().to_string()
    };

    // Check overwrite safety
    if !args.stdout && !args.overwrite && dest_path.exists() {
        bail!(
            "destination {} already exists. Use --overwrite to replace.",
            dest_path.display(),
        );
    }

    // ── 3. Build HTTPS client with PQ KX ────────
    let mut builder = aws_smithy_http_client::Builder::new().tls_provider(tls::Provider::Rustls(
        tls::rustls_provider::CryptoMode::AwsLc,
    ));

    if let Some(ca_path) = &args.ca_bundle {
        let ca_meta = std::fs::metadata(ca_path)
            .with_context(|| format!("cannot stat CA bundle {}", ca_path.display()))?;
        if ca_meta.len() > MAX_CA_BUNDLE_SIZE {
            bail!(
                "CA bundle {} exceeds maximum allowed size ({} bytes)",
                ca_path.display(),
                MAX_CA_BUNDLE_SIZE,
            );
        }
        let pem = std::fs::read(ca_path)
            .with_context(|| format!("failed to read CA bundle {}", ca_path.display()))?;

        let trust_store = tls::TrustStore::default().with_pem_certificate(pem);

        let tls_ctx = tls::TlsContext::builder()
            .with_trust_store(trust_store)
            .build()
            .context("failed to build TLS context from CA bundle")?;

        builder = builder.tls_context(tls_ctx);

        eprintln!(
            "{{\"event\":\"ca_bundle_loaded\",\"run_id\":\"{}\",\"path\":\"{}\"}}",
            run_id,
            ca_path.display(),
        );
    }

    let http_client = builder.build_https();

    // ── 4. Build S3 client ──────────────────────
    let creds = Credentials::new(
        alias.access_key.expose_secret().to_string(),
        alias.secret_key.expose_secret().to_string(),
        None,
        None,
        "mc-config",
    );

    let timeout_config = TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .operation_timeout(Duration::from_secs(OPERATION_TIMEOUT_SECS))
        .operation_attempt_timeout(Duration::from_secs(ATTEMPT_TIMEOUT_SECS))
        .build();

    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region_str.to_string()))
        .credentials_provider(creds)
        .http_client(http_client)
        .timeout_config(timeout_config)
        .load()
        .await;

    let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
        .endpoint_url(&alias.url)
        .force_path_style(force_path)
        .build();

    let client = Client::from_conf(s3_config);

    // ── 5. Audit start record (CWE-778) ─────────
    let audit_start = AuditStartRecord {
        event: "get_object_start",
        run_id: &run_id,
        alias: &alias_name,
        endpoint: &alias.url,
        bucket: &bucket,
        key: &key,
        destination: &dest_display,
        region: region_str,
        path_style: force_path,
        pq_kx: "X25519MLKEM768",
        ca_bundle: args.ca_bundle.as_ref().map(|p| p.to_str().unwrap_or("?")),
    };
    eprintln!("{}", serde_json::to_string(&audit_start)?);

    // ── 6. GetObject ────────────────────────────
    let resp = client
        .get_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await
        .with_context(|| {
            if args.verbose {
                format!("GetObject failed: bucket={} key={}", bucket, key)
            } else {
                "GetObject request failed".to_string()
            }
        })?;

    // Capture metadata before consuming the body
    let etag = resp.e_tag().map(|s| s.to_string());
    let content_type = resp.content_type().map(|s| s.to_string());
    let content_length = resp.content_length().unwrap_or(0) as u64;
    let last_modified = format_dt(resp.last_modified());

    // ── 7. Stream body to destination ───────────
    let bytes_written = if args.stdout {
        stream_to_stdout(resp.body).await?
    } else {
        // Create parent directories if they don't exist
        if let Some(parent) = dest_path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        stream_to_file(resp.body, &dest_path).await?
    };

    let duration_ms = started.elapsed().as_millis();

    // ── 8. Emit result to stdout (unless --stdout) ─
    if !args.stdout {
        let record = DownloadRecord {
            status: "success",
            record_type: "download",
            bucket: bucket.clone(),
            key: key.clone(),
            destination: dest_display.clone(),
            size: bytes_written,
            etag: etag.clone(),
            content_type,
            last_modified,
            duration_ms,
        };
        println!("{}", serde_json::to_string(&record)?);
    }

    // ── 9. Audit completion record ──────────────
    let audit_complete = AuditCompleteRecord {
        event: "get_object_complete",
        run_id: &run_id,
        alias: &alias_name,
        bucket: &bucket,
        key: &key,
        destination: &dest_display,
        size: bytes_written,
        etag: etag.as_deref(),
        duration_ms,
        outcome: "success",
    };
    eprintln!("{}", serde_json::to_string(&audit_complete)?);

    // Sanity check: warn if bytes written differs from content-length
    if content_length > 0 && bytes_written != content_length {
        eprintln!(
            "{{\"event\":\"size_mismatch\",\"run_id\":\"{}\",\"expected\":{},\"actual\":{}}}",
            run_id, content_length, bytes_written,
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────
//  Streaming helpers
// ──────────────────────────────────────────────

/// Stream the ByteStream body to a local file.
/// Returns the total number of bytes written.
async fn stream_to_file(mut body: aws_sdk_s3::primitives::ByteStream, dest: &Path) -> Result<u64> {
    let mut file = File::create(dest)
        .await
        .with_context(|| format!("failed to create {}", dest.display()))?;

    let mut bytes_written: u64 = 0;

    while let Some(chunk) = body.try_next().await.context("error reading object body")? {
        file.write_all(&chunk)
            .await
            .with_context(|| format!("error writing to {}", dest.display()))?;
        bytes_written += chunk.len() as u64;
    }

    file.flush().await.context("error flushing output file")?;
    file.shutdown().await.context("error closing output file")?;

    Ok(bytes_written)
}

/// Stream the ByteStream body to stdout.
/// Returns the total number of bytes written.
async fn stream_to_stdout(mut body: aws_sdk_s3::primitives::ByteStream) -> Result<u64> {
    let mut out = tokio::io::stdout();
    let mut bytes_written: u64 = 0;

    while let Some(chunk) = body.try_next().await.context("error reading object body")? {
        out.write_all(&chunk)
            .await
            .context("error writing to stdout")?;
        bytes_written += chunk.len() as u64;
    }

    out.flush().await.context("error flushing stdout")?;

    Ok(bytes_written)
}
