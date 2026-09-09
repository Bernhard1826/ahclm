# AHCLM — Adaptive HTTPS Certificate Lifecycle Monitor

A Go system that continuously scans the **Tranco Top** sites, captures their deployed
HTTPS certificates (zgrab-style TLS handshakes), and tracks each certificate's
**lifecycle** over time — renewals, issuer changes, revocations and expiry — using an
**adaptive scanning strategy** that clusters scans around expiry milestones so it
captures the interesting moments without storing mountains of unchanged data.

## Why it's built this way

Continuously rescanning popular sites produces overwhelmingly unchanged data. AHCLM
addresses that with two ideas:

1. **Adaptive milestone scheduling.** Instead of a fixed interval, every domain carries
   a `next_scan_at` that is recomputed after each scan to land on the configured
   expiry milestones (**30, 14, 10, 7, 3, 1 days before** expiry, plus **1, 3, 7
   days after**). Far from expiry it falls back to a weekly baseline; within a day of
   expiry it accelerates to every few hours. Scans get denser exactly when a
   certificate is most likely to change.

2. **Hybrid storage.** Distinct certificates are de-duplicated globally by SHA-256
   fingerprint; a small per-domain row holds the *current* deployment + schedule state;
   and an append-only **observation** log records a row **only** on a meaningful event
   (initial sighting, change, milestone crossing, revocation change, expiry). Routine
   "still the same" scans just bump a heartbeat, so the time-series stays small but
   complete.

## Features

- **zgrab-style scanning** — TLS handshake, full chain capture, works on expired /
  self-signed / revoked certs (records rather than validates).
- **Revocation monitoring** — OCSP (stapled + active) **and** CRL (with per-URL
  caching). CRL is on by default because CRL-only CAs such as Let's Encrypt no longer
  serve OCSP.
- **Real Tranco ingestion** — downloads the actual `top-1m.csv.zip`, unzips in memory,
  registers the top-N (configurable) as the scanning population.
- **Adaptive per-certificate scheduling** driven by `next_scan_at`.
- **ARI polling** — supported CAs are re-polled using `Retry-After` or a
  configurable fallback cadence, and the poll is scheduled through the normal
  scan pipeline.
- **Persisted scan-job audit trail** — records why every scheduled/manual scan
  ran, its timing, result, certificate fingerprint, revocation and ARI status.
- **Change / revocation / anomaly detection** with a lifecycle timeline per domain.
- **Alerts** — log + webhook + SMTP on expiring / changed / revoked / expired.
- **React dashboard** — domains, per-domain timeline, adaptive schedule, anomalies,
  daily-trend charts.

## Architecture

```
ahclm/
├── ahclm_backend/                 # Go backend
│   ├── cmd/main.go                # entry: config, wiring, HTTP server
│   ├── internal/
│   │   ├── api/                   # Gin REST handlers
│   │   ├── database/              # PostgreSQL (GORM) + hybrid-storage queries
│   │   ├── models/                # entities, config, helpers, scheduling math helpers
│   │   ├── scanner/               # TLS handshake scanner
│   │   ├── revocation/            # OCSP (stapled/active) + CRL with cache
│   │   ├── scheduler/             # adaptive next_scan_at engine + worker pool
│   │   ├── tranco/                # real top-1m.csv.zip fetcher
│   │   └── alerts/                # webhook + SMTP notifier
│   └── config.yaml
├── ahclm_frontend/                # React + Vite + Tailwind + Recharts
└── docker-compose.yml             # optional PostgreSQL container; port is configured by env
```

### Data model (PostgreSQL)

| Table | Purpose |
|-------|---------|
| `certificates` | one row per distinct cert (dedup by SHA-256 fingerprint) |
| `domain_certificates` | per-domain current cert + lifecycle/schedule state (`next_scan_at`) |
| `cert_observations` | append-only time-series of meaningful lifecycle events |
| `daily_scan_stats` | per-day counters incremented in place |
| `scan_jobs` | audit trail for scheduled and manual scan attempts |
| `ari_cache_entries` | persisted ARI responses keyed by RFC 9773 certificate ID |
| `crl_cache_entries` | persisted CRL payloads keyed by distribution-point URL |
| `tranco_lists` | fetched-list metadata |
| `certificate_alerts` | alert rules (API CRUD) |

## Quick start

### Prerequisites
- Go 1.21+
- Node.js 18+
- PostgreSQL with the database and credentials declared in `config.yaml` (or its explicit
  environment overrides). The optional Compose file also requires those values in the
  environment; it does not supply credentials or a host port.

```bash
docker compose --env-file .env up -d
```

### Backend (PowerShell)
```powershell
cd ahclm_backend
go mod tidy
$env:AHCLM_CONFIG_FILE = (Resolve-Path .\config.yaml).Path
go run ./cmd --config $env:AHCLM_CONFIG_FILE
```
The file passed with `--config` is required. On start, if enabled there, AHCLM downloads the
configured Tranco source and begins adaptive scanning.

### Frontend (PowerShell)
```powershell
cd ahclm_frontend
npm install
$env:AHCLM_FRONTEND_HOST = '0.0.0.0'
$env:AHCLM_FRONTEND_PORT = '25173'
$env:AHCLM_API_PROXY = 'http://127.0.0.1:28000'
$env:VITE_API_URL = '/api'
npm run dev
```

## Configuration (`config.yaml` / `AHCLM_*` env)

```yaml
database: { host: <configured-db-host>, port: <configured-db-port>, user: <configured-user>, password: <configured-secret>, database: <configured-name> }
scanner:   { workers: 20, check_revocation: true, check_crl: true, revocation_timeout: 15s }
scheduler:
  milestones: [30, 14, 10, 7, 3, 1]     # days before expiry
  post_expiry_checks: [1, 3, 7]         # days after expiry
  baseline_interval: 168h               # far-from-expiry cadence
  near_expiry_interval: 6h              # within ~1 day of expiry
  ari_poll_interval: 24h                # fallback when ARI omits Retry-After
  max_daily_scans: 100000
tranco:    { enabled: true, max_domains: 1000, fetch_on_start: true }
```

Environment overrides: `AHCLM_CONFIG_FILE`, `AHCLM_BACKEND_HOST`, `AHCLM_BACKEND_PORT`,
`AHCLM_DB_HOST/PORT/USER/PASSWORD/NAME`, `AHCLM_WORKERS`, `AHCLM_MAX_DOMAINS`.

The frontend requires `AHCLM_FRONTEND_HOST`, `AHCLM_FRONTEND_PORT`, `AHCLM_API_PROXY` and
`VITE_API_URL`. The backend and database ports are read from the explicit configuration or
the corresponding environment override; no executable contains a fallback port. See
`.env.example`.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health`, `/api/stats` | health / system statistics |
| GET | `/api/domains` | monitored domains (paginated, filterable) |
| GET | `/api/domains/:domain` | domain detail + current certificate |
| GET | `/api/domains/:domain/observations` | lifecycle timeline |
| GET | `/api/certificates` | distinct-certificate inventory |
| GET | `/api/certificates/expiring?days=`, `/expired` | expiry views |
| GET | `/api/revocations` | revoked deployments |
| GET | `/api/analysis/anomalies` | explainable findings with occurrence count, monitoring-round count, evidence and reason |
| GET | `/api/schedule/upcoming` | upcoming adaptive scans |
| POST | `/api/scan`, `/api/scan/batch` | on-demand scans |
| GET | `/api/scan/jobs` | recent scan-job audit trail |
| GET/POST | `/api/scheduler/status`, `/pause`, `/resume`, `/tranco` | scheduler control |
| GET | `/api/statistics/daily` | daily counters |
| GET/POST/PUT/DELETE | `/api/alerts` | alert rules |

## Tests

```bash
cd ahclm_backend && go test ./...     # scheduling math, milestone crossing, OCSP/CRL, Tranco parsing
```

Revocation can be checked live against `revoked.badssl.com` (→ revoked, via CRL) and
`google.com` (→ good, via OCSP).

## License
MIT
