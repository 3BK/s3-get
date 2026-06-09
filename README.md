# s3-get

> **MinIO-compatible S3 file downloader with structured JSONL output and post-quantum TLS.**

`s3-get` is a Rust CLI tool that reads `~/.mc/config.json` (MinIO Client
configuration) and performs the equivalent of:

```bash
mc get <alias>/<bucket>/<key> [<local-path>]
```

It emits a JSON result record to **stdout** and structured audit records to
**stderr**, making it suitable for automation pipelines, SIEM ingestion, and
compliance-auditable environments.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Destination Resolution](#destination-resolution)
- [Output Schema](#output-schema)
- [TLS and Post-Quantum Key Exchange](#tls-and-post-quantum-key-exchange)
- [FIPS 140-2/3 Mode](#fips-140-23-mode)
- [Security Controls](#security-controls)
- [Compliance Mapping](#compliance-mapping)
- [Audit Logging](#audit-logging)
- [Proxy Support](#proxy-support)
- [Known Limitations](#known-limitations)
- [Related Projects](#related-projects)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Drop-in MinIO Client config** — reads `~/.mc/config.json` aliases directly.
- **Structured JSONL output** — JSON result record to stdout; audit records to
  stderr.  Compatible with `jq`, NATS, and SIEM ingestion.
- **Automatic destination resolution** — if the local path is omitted or is a
  directory, the filename is derived from the S3 key.
- **Streaming download** — object body is streamed chunk-by-chunk to disk or
  stdout; the entire object is never buffered in memory.
- **Stdout mode** — `--stdout` writes the object content directly to stdout
  for piping to other tools.
- **Overwrite protection** — refuses to overwrite existing files unless
  `--overwrite` is specified.
- **Size verification** — warns on stderr if bytes written differs from the
  Content-Length header.
- **Post-quantum TLS** — prefers X25519MLKEM768 (hybrid ML-KEM-768 + X25519)
  during TLS 1.3 handshake via `rustls` + `aws-lc-rs`.
- **Credential protection** — HMAC keys held as `secrecy::SecretString` (zeroed
  on drop, `Debug`-safe).
- **Config file permission enforcement** — refuses to start if
  `~/.mc/config.json` is group- or world-readable on Unix (mode `0600`
  required).
- **Audit logging** — emits JSONL audit records (startup, completion) to stderr
  with a UUID v7 `run_id` for correlation.
- **Input validation** — enforces maximum lengths on source strings, config
  files, and CA bundles.
- **Timeouts** — connect (10 s), operation (300 s), and per-attempt (120 s)
  timeouts prevent indefinite hangs.
- **Custom CA bundle** — `--ca-bundle` adds PEM-encoded certificates on top of
  platform-native roots (does not replace them).
- **Parent directory creation** — automatically creates parent directories for
  the destination path if they don't exist.

---

## Requirements

| Requirement       | Version       | Notes                                        |
|-------------------|---------------|----------------------------------------------|
| Rust toolchain    | >= 1.85       | Edition 2024 support                         |
| C compiler        | clang or gcc  | Required by `aws-lc-rs` to build `aws-lc`   |
| CMake             | >= 3.10       | Required on some platforms for `aws-lc`      |
| Go toolchain      | >= 1.22       | **Only** required for `--features fips`      |

---

## Build

### Standard (non-FIPS)

```bash
cargo build --release
```

### FIPS 140-2/3 validated cryptography

```bash
cargo build --release --features fips
```

### Static musl build (Linux)

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Installation

```bash
cp target/release/s3-get /usr/local/bin/
chmod 755 /usr/local/bin/s3-get
```

---

## Configuration

`s3-get` reads the standard MinIO Client configuration file at
`~/.mc/config.json`.  See the [s3-put](../s3-put/) README for the full
config file reference.

### File permissions (Unix)

```bash
chmod 600 ~/.mc/config.json
```

---

## Usage

### Download to current directory (filename from key)

```bash
s3-get myminio/docs-bucket/reports/2026/Q2/report.pdf
```

Creates `./report.pdf`.

### Download to explicit path

```bash
s3-get myminio/docs-bucket/reports/2026/Q2/report.pdf ./local-report.pdf
```

### Download into a directory

```bash
s3-get myminio/docs-bucket/reports/2026/Q2/report.pdf ./downloads/
```

Creates `./downloads/report.pdf`.

### Stream to stdout (pipe to another tool)

```bash
s3-get --stdout myminio/analytics-bucket/data.csv | csvtool col 1,3 -
```

### Overwrite an existing file

```bash
s3-get --overwrite myminio/docs-bucket/config.yaml ./config.yaml
```

### Custom CA bundle

```bash
s3-get --ca-bundle /etc/pki/tls/certs/internal-ca.pem \
  ibmcos/clinical-bucket/ascent/export.json ./export.json
```

### CLI reference

```
s3-get [OPTIONS] <SOURCE> [DESTINATION]

Arguments:
  <SOURCE>         Source in the form alias/bucket/key
  [DESTINATION]    Local destination path (default: filename from key)

Options:
      --config <PATH>       Path to mc config file
                            [default: ~/.mc/config.json]
                            [env: MC_CONFIG_DIR]
      --region <REGION>     Override region [default: us-east-1]
      --ca-bundle <PATH>    PEM CA bundle to add to native roots
      --stdout              Write object content to stdout
      --overwrite           Overwrite destination if it exists
      --verbose             Emit detailed error information
  -h, --help                Print help
```

---

## Destination Resolution

| Invocation | Resolved local path |
|------------|-------------------|
| `s3-get alias/bucket/path/to/file.csv` | `./file.csv` |
| `s3-get alias/bucket/path/to/file.csv ./renamed.csv` | `./renamed.csv` |
| `s3-get alias/bucket/path/to/file.csv ./downloads/` | `./downloads/file.csv` |
| `s3-get alias/bucket/path/to/file.csv /tmp/data/` | `/tmp/data/file.csv` |
| `s3-get --stdout alias/bucket/path/to/file.csv` | `<stdout>` |

---

## Output Schema

### Download result (stdout)

```json
{
  "status": "success",
  "type": "download",
  "bucket": "telemetry-bucket",
  "key": "raw/2026/06/08/sensors.csv",
  "destination": "./sensors.csv",
  "size": 4096,
  "etag": "\"d41d8cd98f00b204e9800998ecf8427e\"",
  "content_type": "text/csv",
  "last_modified": "2026-06-08T14:00:00Z",
  "duration_ms": 347
}
```

> **Note:** When `--stdout` is used, the JSON result record is **not** emitted
> to stdout (to avoid mixing with the object data).  Audit records on stderr
> still contain all metadata.

### Error record (stderr)

```json
{
  "status": "error",
  "error": "alias 'bogus' not found in config"
}
```

### Field reference

| Field           | Type   | Present      | Description                          |
|-----------------|--------|--------------|--------------------------------------|
| `status`        | string | always       | `"success"` or `"error"`            |
| `type`          | string | on success   | `"download"`                         |
| `bucket`        | string | on success   | Source bucket name                   |
| `key`           | string | on success   | S3 object key                        |
| `destination`   | string | on success   | Local file path or `<stdout>`        |
| `size`          | u64    | on success   | Bytes written to destination         |
| `etag`          | string | on success   | Server-returned entity tag           |
| `content_type`  | string | on success   | MIME type from server                |
| `last_modified` | string | on success   | RFC 3339 last-modified timestamp     |
| `duration_ms`   | u128   | on success   | Total download duration              |
| `error`         | string | on error     | Human-readable error description     |

---

## TLS and Post-Quantum Key Exchange

Identical to [s3-put](../s3-put/) and [s3-ls-json](../s3-ls-json/).  The
`prefer-post-quantum` feature ensures **X25519MLKEM768** is offered first
during TLS 1.3 handshake.

### Verification

```bash
SSLKEYLOGFILE=/tmp/tls-keys.log s3-get myminio/test-bucket/test.txt
```

---

## FIPS 140-2/3 Mode

```bash
cargo build --release --features fips
```

Requires a Go toolchain (>= 1.22) at build time.

---

## Security Controls

### Credential protection

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Memory zeroing             | `secrecy::SecretString` zeroes credential memory on drop    |
| Debug redaction            | `SecretString` prints `[REDACTED]` in `Debug` output        |
| Config file permissions    | Enforces `0600` on Unix; refuses to start if too permissive |
| Error message sanitization | Endpoint URLs and alias lists hidden unless `--verbose`     |

### TLS hardening

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Post-quantum KX            | X25519MLKEM768 preferred via `prefer-post-quantum`          |
| FIPS mode                  | Optional `--features fips` build                            |
| CA bundle isolation        | `--ca-bundle` adds to (not replaces) platform-native roots  |
| CA bundle warning          | Warning emitted to stderr when custom trust store is active |

### Download safety

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Overwrite protection       | Refuses to overwrite unless `--overwrite` is specified      |
| Size verification          | Warns if bytes written differs from Content-Length header    |
| Streaming I/O              | Object body never fully buffered in memory                  |
| Parent directory creation  | Creates parent dirs automatically; does not follow symlinks |

### Input validation

| Control                    | Implementation                                              |
|----------------------------|-------------------------------------------------------------|
| Config file size limit     | Refuses files larger than 1 MiB                             |
| CA bundle size limit       | Refuses bundles larger than 10 MiB                          |
| Source string length       | Refuses sources longer than 2048 characters                 |

### Timeout configuration

| Timeout    | Default | Purpose                              |
|------------|---------|--------------------------------------|
| Connect    | 10 s    | TCP + TLS handshake                  |
| Operation  | 300 s   | Total time for complete download     |
| Attempt    | 120 s   | Single retry attempt                 |

---

## Compliance Mapping

### Credential and key management

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| SecretString memory zeroing   | SC-12, SC-28  | A.8.24    | 3.5.1       | V-222542   | 3.11     |
| Config file permission check  | AC-3          | A.8.3     | 7.2.2       | V-222425   | 6.1      |
| Debug redaction               | SI-11         | A.8.15    | 3.3.1       | V-222658   | 3.11     |
| Error message sanitization    | SI-11         | A.8.15    | 6.2.4       | V-222609   | 16.6     |

### Cryptographic protection

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| X25519MLKEM768 PQ KX          | SC-8(1)       | A.8.24    | 4.2.1       | V-222610   | 3.10     |
| FIPS mode (optional)          | SC-13         | A.8.24    | 4.2.1       | V-222596   | 3.10     |
| CA bundle add (not replace)   | SC-23         | A.8.24    | 4.2.1       | V-222577   | 3.10     |

### Audit and logging

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| Startup audit record          | AU-2, AU-3    | A.8.15    | 10.2.1      | V-222457   | 8.2      |
| Completion audit record       | AU-2, AU-12   | A.8.15    | 10.2.1      | V-222457   | 8.2      |
| Size mismatch warning         | AU-2, AU-12   | A.8.15    | 10.2.1      | V-222457   | 8.2      |
| UUID v7 run_id correlation    | AU-3(1)       | A.8.15    | 10.2.1.2    | V-222458   | 8.5      |

### Input validation

| Control                       | 800-53        | ISO 27001 | PCI DSS 4.0 | STIG       | CIS v8.1 |
|-------------------------------|---------------|-----------|-------------|------------|----------|
| Config file size limit        | SI-10         | A.8.28    | 6.2.4       | V-222609   | 16.6     |
| CA bundle size limit          | SI-10         | A.8.28    | 6.2.4       | V-222609   | 16.6     |
| Source string length limit    | SI-10         | A.8.28    | 6.2.4       | V-222609   | 16.6     |

---

## Audit Logging

All audit records are emitted to **stderr** as JSONL.  Each record includes a
`run_id` (UUID v7) for correlation.

### Startup record

```json
{
  "event": "get_object_start",
  "run_id": "0192f3a4-5b6c-7d8e-9f01-234567890abc",
  "alias": "myminio",
  "endpoint": "https://minio.example.com",
  "bucket": "docs-bucket",
  "key": "reports/2026/Q2/report.pdf",
  "destination": "./report.pdf",
  "region": "us-east-1",
  "path_style": true,
  "pq_kx": "X25519MLKEM768",
  "ca_bundle": null
}
```

### Completion record

```json
{
  "event": "get_object_complete",
  "run_id": "0192f3a4-5b6c-7d8e-9f01-234567890abc",
  "alias": "myminio",
  "bucket": "docs-bucket",
  "key": "reports/2026/Q2/report.pdf",
  "destination": "./report.pdf",
  "size": 1048576,
  "etag": "\"d41d8cd98f00b204e9800998ecf8427e\"",
  "duration_ms": 523,
  "outcome": "success"
}
```

### Size mismatch warning

Emitted if bytes written differs from the Content-Length header:

```json
{
  "event": "size_mismatch",
  "run_id": "0192f3a4-5b6c-7d8e-9f01-234567890abc",
  "expected": 1048576,
  "actual": 1048000
}
```

### Log integrity

Audit log integrity protection is an **operational responsibility**.
The consuming pipeline must enforce write-once semantics or cryptographic
log chaining per NIST SP 800-53 AU-9.

---

## Proxy Support

The underlying HTTP client respects:

| Variable       | Example                          | Description                   |
|----------------|----------------------------------|-------------------------------|
| `HTTPS_PROXY`  | `http://proxy.example.com:3128`  | HTTPS proxy endpoint          |
| `HTTP_PROXY`   | `http://proxy.example.com:3128`  | HTTP proxy endpoint           |
| `NO_PROXY`     | `localhost,127.0.0.1,.internal`  | Bypass proxy for these hosts  |

---

## Known Limitations

1. **Static HMAC keys only** — STS / AssumeRole / session tokens not yet
   supported.
2. **No cryptoperiod enforcement** — no warning when keys exceed recommended
   rotation interval.
3. **No alias access restriction** — any user with config file access can use
   any alias.
4. **No TOCTOU hardening** — config file read without `O_NOFOLLOW`.
5. **No range requests** — the entire object is always downloaded.  Partial
   download via `--range` is planned for a future release.
6. **No checksum verification** — the application does not verify SHA-256 /
   CRC32C checksums against the server response.  Planned.
7. **No resume support** — interrupted downloads must be restarted from the
   beginning.

---

## Related Projects

- [s3-ls-json](../s3-ls-json/) — list S3 objects with JSONL output.
- [s3-put](../s3-put/) — upload files to S3 with multipart support.

All three tools share the same config format, security controls, and PQ TLS
stack.

---

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Ensure `cargo clippy -- -D warnings` passes.
4. Ensure `cargo test` passes.
5. Run `cargo audit` and resolve any advisories.
6. Submit a pull request.

---

## License
This project is licensed under the [MIT License](LICENSE).
