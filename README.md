# AHCLM — Adaptive HTTPS Certificate Lifecycle Monitor

A Go system that continuously scans the **Tranco Top** sites plus configured local domain
lists, captures their deployed
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
  and registers exactly the first 10,000 entries as the ranked scanning population.
  Every refresh removes domains that fell out of the current list while retaining
  domains supplied by local lists.
  Tranco is a ranking source, not a subdomain enumerator; apart from deliberate leading
  `www` normalization, supplied FQDN labels are preserved.
- **Combined domain populations** — plain-line and JSONL local lists are streamed,
  normalized, de-duplicated, and refreshed daily alongside Tranco. On-demand scans
  accept only domains in this combined current population.
- **Adaptive per-certificate scheduling** driven by `next_scan_at`.
- **ARI polling** — supported CAs are re-polled using `Retry-After` or a
  configurable fallback cadence, and the poll is scheduled through the normal
  scan pipeline.
- **Persisted scan-job audit trail** — records why every scheduled/manual scan
  ran, its timing, result, certificate fingerprint, revocation and ARI status.
- **CDN certificate propagation experiments** — after an observed same-endpoint
  replacement, independently poll configured Globalping regions and retain each TLS
  leaf fingerprint, answering address, first target time, the last predecessor
  observation before that target, regional spread, and separate all-regions and
  stable-confirmation bounds. Operators can also start a controlled experiment
  with the source-side update time and known predecessor/successor leaves.
  This measures public regional observations, not the CDN's private deployment logs.
  Controlled origin rotations additionally verify per-region fresh responses and
  the certificate on the actual origin TLS connection; HTTP 200 alone cannot
  complete a rotation. Overflow experiments are persisted in a restart-safe queue.
  See [受控源站换证实验](docs/origin-certificate-experiment.md) for the origin
  endpoint, reload event, submission script, measurement bounds, and tests.
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
│   │   ├── domainlist/             # plain-line and JSONL local-list loaders
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
| `cdn_propagation_experiments` | source/update timing, target leaf, cadence, region coverage, and completion state |
| `cdn_propagation_rounds` | immutable per-poll aggregate results |
| `cdn_propagation_observations` | per-region leaf fingerprint, address, and handshake result |

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

### Linux (frontend + backend)

```bash
./start.sh          # start Postgres (if needed), backend, and frontend
./start.sh status
./start.sh stop
```

The script reads optional `.env` overrides, builds `bin/ahclm-backend`, and writes
timestamped logs plus pid files under `logs/`. UI: `http://127.0.0.1:25173`.
API: `http://127.0.0.1:28000/api/health`.

### Backend (PowerShell)
```powershell
cd ahclm_backend
go mod tidy
$env:AHCLM_CONFIG_FILE = (Resolve-Path .\config.yaml).Path
go run ./cmd --config $env:AHCLM_CONFIG_FILE
```
The file passed with `--config` is required. On start, if enabled there, AHCLM downloads the
configured Tranco source, loads local lists, and begins adaptive scanning. The shipped
configuration reads the two temporary files from `../analysis/` relative to
`ahclm_backend/config.yaml`; change those paths if the files move.

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
propagation:
  enabled: true
  auto_start_on_change: true
  cdn_only: true
  poll_interval: 15m
  max_duration: 72h
  stable_rounds: 2
  locations: ["NA", "EU", "AS"]
  timeout: 45s
  max_active: 32
tranco:    { enabled: true, max_domains: 10000, fetch_on_start: true }
local_lists:
  enabled: true
  fetch_on_start: true
  refresh_interval: 24h
  sources:
    - { name: secrank-topdomain1m, path: ../analysis/secrank-topdomain1M-domainonly-20240722.txt, format: lines, max_domains: 0 }
    - { name: secrank-icp, path: ../analysis/domains_secrank-icp-out.txt, format: jsonl, max_domains: 0 }
```

Environment overrides: `AHCLM_CONFIG_FILE`, `AHCLM_BACKEND_HOST`, `AHCLM_BACKEND_PORT`,
`AHCLM_DB_HOST/PORT/USER/PASSWORD/NAME`, `AHCLM_WORKERS`, and `AHCLM_GLOBALPING_TOKEN`.
Keep the Globalping token in the local `.env` file (copy `.env.example` first); the
environment value overrides the empty `scanner.global_probe_token` config default.
Tranco remains fixed at
its first 10,000 entries; local lists are additional and refreshed as a union.

The frontend accepts `AHCLM_FRONTEND_HOST`, `AHCLM_FRONTEND_PORT`, `AHCLM_API_PROXY` and
`VITE_API_URL`; when omitted, the Vite development defaults are `127.0.0.1:25173`,
`http://127.0.0.1:28000`, and `/api`. When the Vite proxy cannot reach the backend through
the listener address, set `AHCLM_API_PROXY_TARGET` to the backend's reachable network
address. The backend and database ports are read from the explicit configuration or the
corresponding environment override. See `.env.example`.

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
| GET | `/api/analysis/anomalies` | observed finding index with deterministic/speculative class, certificate evidence, and monitoring rounds |
| GET | `/api/analysis/diagnosis?domain=&type=` | on-demand longitudinal diagnosis for one observed finding |
| GET | `/api/schedule/upcoming` | upcoming adaptive scans |
| POST | `/api/scan`, `/api/scan/batch` | on-demand scans for current monitored domains |
| GET | `/api/scan/jobs` | recent scan-job audit trail |
| GET | `/api/cdn-propagation/config` | propagation cadence and configured regions |
| GET/POST | `/api/cdn-propagation` | list experiments / start a controlled experiment |
| GET | `/api/cdn-propagation/experiments/:id` | regional rollout report and observation rounds |
| POST | `/api/cdn-propagation/experiments/:id/cancel` | stop an active experiment |
| GET/POST | `/api/scheduler/status`, `/pause`, `/resume`, `/tranco`, `/local-lists` | scheduler control and population refresh |
| GET | `/api/statistics/daily` | daily counters |
| GET/POST/PUT/DELETE | `/api/alerts` | alert rules |

## Tests

```bash
cd ahclm_backend && go test ./...     # scheduling math, milestone crossing, OCSP/CRL, Tranco parsing
```

Revocation parsing and CRL/OCSP fallback are covered by unit tests. Runtime monitoring
accepts only domains in the current combined population; unrelated manual/test hosts
are not retained in the production population.

## License
MIT
