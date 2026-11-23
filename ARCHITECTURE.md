# Architecture: Good Morning Breach

This file owns HOW the system is built: its components, boundaries, technology, and data flow. `REQUIREMENTS.md` owns WHAT the system does. `DESIGN.md` owns how it looks. `SECURITY.md` owns the detailed controls. The application scaffold, one-source RSS ingestion, and the first authenticated dashboard slice are implemented; the remaining product workflows are still in progress.

Version pins were checked against official release and registry sources on 2026-11-16. The scaffold's Go and npm dependency trees were resolved, license-checked, and audited before being added. The npm production and full audits passed, and 44 installed packages had verified registry signatures. The original Go scaffold passed `go mod verify` and `govulncheck ./...`; all 55 modules had recognized permissive licenses. The 94-package npm tree includes 12 optional, platform-specific Lightning CSS packages under MPL-2.0; this is acceptable for this private, non-distributed service, but must be reconsidered before distribution. The Gin tree required patched `x/net`, `quic-go`, and `x/crypto` pins to pass the vulnerability gate. On 2026-11-16, the added pgx v5.13.0 and gofeed v1.5.0 tags were verified from upstream/Go module sources, their MIT licenses were checked, direct OSV queries returned no advisories, `govulncheck ./...` found no vulnerabilities, and `go-licenses check` passed for third-party dependencies. Continue these checks before adding other proposed packages.

## Required Architecture Inputs

- **Requirements and design sources:** `REQUIREMENTS.md` (FR-1 to FR-10, NFR-1 to NFR-4); `DESIGN.md`; `reports/Licensed cyber news sources.md`.
- **Target surfaces:** a web dashboard; background jobs for collection, analysis, the morning alert, and retention. Public APIs: none.
- **Runtime and deployment environment:** CONFIRMED (AQ-1): a single machine owned by the owner, for the owner only. The server listens on localhost only and uses a local TLS certificate (NFR-3.1). Alerts at 07:00 need that machine to be on and awake. Because availability is best effort (NFR-4.1), this is accepted. Accounts beyond the owner's are supported (NFR-2.1) but can only be used on this machine.
- **Server framework:** Go with Gin (explicit choice).
- **Client frameworks:** ReactJS (explicit choice), built as a single-page app and served by the Go server.
- **API style:** a private JSON-over-HTTPS API used only by the bundled client. It is not a public API.
- **Authentication and session model:** email and password only; the TOTP second factor was removed by owner decision (migration 020). A server-side session referenced by a cookie, with a 30-minute idle timeout and an 8-hour absolute timeout.
- **Outbound calls:** collection sources, MITRE, SMTP, Slack webhooks, and the HIBP range API. There are no inbound connections from outside the machine.
- **Authorization model:** two roles, admin and user (FR-6.4), plus ownership checks on per-user settings (FR-6.12). Enforced in the server only.
- **Data store and expected scale:** PostgreSQL, one local instance on the same machine (CONFIRMED, AQ-2). Scale: at least 10 accounts (NFR-2.1) and 365 days of stories (FR-10.1). Story volume per day is UNKNOWN.
- **Logging library or platform logger:** Go standard library `log/slog`.
- **Security expectations:** owned by `SECURITY.md`. This file only names the enforcement points.

## Stack

| Technology | Pinned version / line | Justification | Status |
|---|---|---|---|
| Go | [1.27.4](https://go.dev/doc/devel/release) | Explicit choice: server. Includes `net/http`, `crypto`, `html/template`, `log/slog`, `net/smtp`, and `time`, which cover HTTP clients, email bodies (FR-4.12, NFR-3.4), logging, and scheduling without extra packages. Update to supported security patches deliberately. | CONFIRMED |
| Gin (`github.com/gin-gonic/gin`) | [v1.12.0](https://github.com/gin-gonic/gin/releases/tag/v1.12.0) (minimum Go 1.25) | Explicit choice: HTTP routing and middleware for the dashboard API. | CONFIRMED |
| React + React DOM | [19.3.1](https://github.com/react/react/releases/tag/v19.3.1) | Explicit choice: dashboard client (FR-5). Keep both packages on the same version. | CONFIRMED |
| React type declarations (`@types/react`, `@types/react-dom`) | [19.3.0](https://www.npmjs.com/package/@types/react/v/19.3.0) | Development-only TypeScript declarations needed to type-check React components. `@types/react-dom` requires the matching 19.3 type line. | CONFIRMED |
| Node.js | [26.13.1](https://nodejs.org/en/download/archive/v26.13.1) LTS (build machine only, not at runtime) | Needed to build the React client. It does not run in production. | CONFIRMED |
| Vite | [8.3.8](https://github.com/vitejs/vite/releases/tag/v8.3.8) | Builds and bundles the React client. React has no build tool of its own. | CONFIRMED |
| TypeScript | [7.0.2](https://github.com/microsoft/TypeScript/releases/tag/v7.0.2) | Type-checks the client and its API contracts, so mistakes in rendering untrusted data are caught at build time. | CONFIRMED (AQ-7, delegated decision) |
| PostgreSQL | 18.x (18.7 current; supported until 2030-11-14) | Stores stories, sources, accounts, settings, and records (FR-1 to FR-10). Its built-in full-text search covers keyword search (FR-5.5) without a separate search engine. | CONFIRMED (AQ-2) |
| `github.com/jackc/pgx/v5` | [v5.13.0](https://github.com/jackc/pgx/tree/v5.13.0) (minimum Go 1.25) | PostgreSQL driver and connection pool. The Go standard library has no PostgreSQL driver. The tagged release is MIT-licensed. | CONFIRMED |
| `golang.org/x/net` | [v0.62.0](https://pkg.go.dev/golang.org/x/net@v0.62.0) | Pins above Gin 1.12.0's vulnerable v0.51.0 and is used to parse untrusted HTML title markup safely. `govulncheck` found no reachable advisories at this pin. | CONFIRMED |
| `github.com/quic-go/quic-go` (Gin HTTP/3 dependency) | [v0.65.0](https://github.com/quic-go/quic-go/releases/tag/v0.65.0) | Explicitly pins above Gin 1.12.0's vulnerable v0.59.0; `govulncheck` found a reachable HTTP/3 advisory. Gin builds with this release. | CONFIRMED |
| `golang.org/x/crypto` (argon2id) | [v0.59.0](https://github.com/golang/crypto/tree/v0.59.0) | Password hashing (FR-6.5). The Go standard library has no memory-hard password hash. Also removes an unreachable OpenPGP advisory in Gin's dependency tree. | CONFIRMED |
| `golang.org/x/term` | [v0.48.0](https://pkg.go.dev/golang.org/x/term@v0.48.0) | Reads the bootstrap administrator password without echoing it to the terminal. The official Go sub-repository is BSD-3-Clause licensed and depends on the already-pinned `golang.org/x/sys` v0.50.0. Checked against the upstream tag and OSV on 2026-11-17. | CONFIRMED |
| `github.com/mmcdole/gofeed` | [v1.5.0](https://github.com/mmcdole/gofeed/releases/tag/v1.5.0) | Parses RSS, Atom, and JSON feeds from the FR-1.14 sources. Writing three feed parsers by hand would add more risk than one dependency. The tagged release is MIT-licensed. | CONFIRMED |
| MITRE ATT&CK Enterprise STIX bundle | [v20.1](https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1) | Technique IDs, names, tactics, and links (FR-1.4, FR-7). Compressed asset and source bundle hashes plus attribution are recorded in `internal/analyzer/data/NOTICE`. This is a data file, not a package. | CONFIRMED (required) |
| Email delivery | The owner's personal mail account over SMTP with STARTTLS or TLS and an app password. The provider is UNKNOWN. | Morning alerts and password reset (FR-4.2, FR-6.9). Go's `net/smtp` is the client, so no extra package is needed. | CONFIRMED (AQ-4) |
| Slack incoming webhooks | Slack platform | Slack alerts (FR-4.4, FR-4.16). Uses the standard `net/http` client with no SDK. | CONFIRMED (required) |
| HIBP Pwned Passwords range API | v3 range API | FR-6.6. Uses k-anonymity: only the first 5 hex characters of the password's SHA-1 leave the machine, with the `Add-Padding` header. If the API is unreachable, the password is refused and the user is told to try again later (fails closed). A local copy of the full list (about 40 GB) is too large for a personal tool. | CONFIRMED (AQ-6, delegated decision) |
| Vitest | [5.1.0](https://github.com/vitest-dev/vitest/releases/tag/v5.1.0) | Client unit tests. It shares Vite's configuration and supports Vite 8 and Node.js 26. | CONFIRMED |

The client does not use a router, a state library, or a UI kit. The four screens in `DESIGN.md` can use React state and URL fragments. If they turn out not to be enough, that becomes a new AQ.

## Current Scaffold

- `cmd/server` starts a loopback-only HTTPS server. It requires `GB_TLS_CERT_FILE` and `GB_TLS_KEY_FILE`; the certificate must be locally trusted and cover only `localhost`, `127.0.0.1`, and `::1`, and the private key must be outside the repository with mode `0600`.
- `internal/httpserver` configures TLS, request limits, timeouts, disabled trusted proxies, security headers, CSRF checks, and generic error responses. Its API supports sign-in, session activity/logout, filtered and paginated stories, per-account alert preferences, and admin-only account, audit-log, and source-health endpoints.
- `internal/identity` implements first-admin bootstrap, Argon2id password hashing with a HIBP range check, failed-login lockout, hashed server-side sessions, and administrator account management. Password reset sends a single-use, 30-minute link through the shared SMTP sender (configured by `GB_SMTP_HOST`, `GB_SMTP_PORT`, `GB_SMTP_TLS`, `GB_SMTP_USERNAME`, `GB_SMTP_FROM`, and `GB_SMTP_PASSWORD_FILE`; the server verifies connect, TLS, and sign-in in a background goroutine at startup (it does not delay startup) and logs a warning (without aborting) if that fails, while an invalid configuration still stops startup; `cmd/smtptest` sends a test message without touching the database; at most 3 requests per account per hour; tokens stored hashed; success ends all sessions). It needs SMTP configured. For local development only, `GB_DEV_MAIL_DIR` (used only when SMTP is unset) swaps in `alerting.FileMailer`, which writes each message to a `0600` file in a `0700` directory and never logs its contents.
- `internal/applog` writes structured JSON logs to stdout and private daily files under the OS user configuration directory. The log directory is `0700`; log files are `0600`; files older than 30 days are removed.
- `cmd/migrate` applies the versioned PostgreSQL schema as the local database owner. `cmd/collect` uses the restricted `gb_app` role for a one-shot run. `cmd/server` checks enabled sources at startup and hourly while running; a macOS LaunchAgent can also run `cmd/collect` at login and hourly while the server is stopped. Both collection paths share a PostgreSQL advisory lock.
- `internal/ingest` fetches the seeded CERT-EU, SANS ISC, CERT-FR, CISA, EFF, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, GitHub Advisory Database, additional CISA feeds (ICS, ICS medical, news, blog), FBI IC3, NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News RSS and JSON feeds, respects each persisted poll interval, stores only normalized headlines and links, and records failures. `internal/store/postgres` deduplicates stories globally by canonical link and keeps source associations and collection status.
- The collector's shared outbound client blocks private and special-use IP addresses at connection time, does not use proxies or follow redirects, and has bounded timeouts. Feed responses are capped at 10 MiB.
- `src` provides sign-in, logout, a filtered and paginated stories view, per-account alert preferences, administrator source health, and admin account/audit management. Story titles are rendered as text and external links are scheme-checked. Preferences are stored but do not trigger alerts; the browser suggests its time zone before the first save.
- `npm run build` type-checks and creates the client bundle embedded by the Go process. `npm run dev` starts Vite on localhost but does not proxy the API; use the integrated server to test the full path.

## Components and Flows

The HTTP API and hourly collection scheduler run in one Go process against one local PostgreSQL database (AQ-2). On macOS, an optional LaunchAgent runs the same one-shot collector while the server is stopped; a database advisory lock serializes both paths. Other background jobs remain planned for this process.

| Component | Responsibility | Business rules enforced | Data owned | Requirement IDs | Status |
|---|---|---|---|---|---|
| Web client (React) | Sign-in, logout, filtered stories, source health, and admin account/audit management | Displays server-authorized data; renders collected content as text; requires typed email to confirm account deletion | None | FR-5, FR-8.6, FR-8.7, FR-9.1 to FR-9.6, DESIGN.md | PARTIAL |
| HTTP API (Gin) | Authentication routes, session lifecycle, CSRF, filtered story listing, admin source health, account/audit endpoints, and static assets | Enforces admin authorization, protects story reads, and validates requests | None | FR-6.1, FR-6.2, FR-8.6, FR-8.7, FR-9.1 to FR-9.6, NFR-3.1 | PARTIAL |
| Identity | Initial admin, password-only authentication, lockout, sessions, and account management | Password checks, session timeouts, no self-removal, and last-active-admin protection | Accounts, credential hashes, sessions | FR-6, FR-9 | PARTIAL |
| Audit log | Records account creation, updates, and deletion, and lets admins read the 200 most recent records | Append-only application permissions; account IDs retained without email addresses | Admin action records | FR-9.6 | PARTIAL |
| Source registry | Seeded CERT-EU, SANS ISC, CERT-FR, CISA, EFF, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, GitHub Advisory Database, additional CISA feeds (ICS, ICS medical, news, blog), FBI IC3, NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News source records and license metadata; admins can list, create, edit, enable/disable and delete sources and categories (`internal/catalog`, `/api/admin/categories`, `/api/admin/source-records`, `/api/admin/sources`; migration 017) | Source HTTPS validation, persisted poll intervals, per-story attribution; catalog writes require an admin, use https-only URLs with no userinfo, non-443 ports, local hosts or blocked IP literals, reject withdrawn and prohibited sources, and write an audit row in the same transaction. Securelist addresses reject system summaries and require complete titles. Records with stories cannot be deleted (disable instead), and the `other` category is protected. Sources have no category column. Collection still uses the egress client (no redirects, private IPs blocked at dial). Content rights are decided only by `internal/contentrights` (see below): a source has a content policy and a rights class (`licensed` or `all_rights_reserved`, FR-1.21; migration 025) | Sources, license records, source status | FR-1.5, FR-1.6, FR-1.21, FR-8.1 to FR-8.3, FR-8.5, FR-8.8, FR-8.9 | PARTIAL |
| Collector (job) | Fetches the seeded CERT-EU, SANS ISC, CERT-FR, CISA, EFF, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, GitHub Advisory Database, additional CISA feeds (ICS, ICS medical, news, blog), FBI IC3, NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News RSS and JSON sources | Normalizes and de-duplicates stories; records failures; respects each source's poll interval | Collection results | FR-1, FR-8.5 to FR-8.7 | PARTIAL |
| Analyzer (job) | Local semantic engine over headlines and source-format hints (CVE extraction, cue-based ATT&CK tags), with the deterministic baseline as fallback | Assigns categories, risk, sentiment, CVEs, and ATT&CK tags; records engine and confidence; permitted article text and generated summaries remain unimplemented | Category, sentiment, risk, and technique assignments | FR-2.1 to FR-2.4, FR-3, FR-7.1, FR-7.2 | PARTIAL |
| Story store | Ingested stories, source associations, baseline analysis, and ATT&CK tags; filtered, paginated story query | Canonical-link de-duplication, source attribution, risk-first ordering, and versioned analysis backfill | Stories and analysis results | FR-1.12, FR-2.1 to FR-2.4, FR-3, FR-5.2 to FR-5.5, FR-7.1, FR-7.2, FR-10.1 | PARTIAL |
| Alerting (job) | Per-user preferences and channel settings are stored. `internal/alerting` runs a one-minute scheduler, selects stories collected since each channel's last alert, and delivers through per-channel `Channel`s (email, Slack), each with its own state and retries (every 10 minutes, 4 attempts). A failure on one channel never stops another (FR-4.18). `ContactService` owns channel selection, the write-only Slack webhook (validated per SC-013, test message on save, sealed with the data key), with the per-account Slack test limit (SC-058). Email renders HTML and plain text; Slack renders escaped mrkdwn (SC-034). Content is headline and link only; links are https-only | Validates time, IANA time zone, days, risk, and webhook; at least one channel stays on; Slack needs a saved webhook; settings are owned by the session account (HTTP: `/api/alert-channels*`) | Alert settings, channel settings, channel state, outbound message log, delivery records (migrations 022 and 024) | FR-4, FR-10.2 | PARTIAL |
| Channel adapters | Email (SMTP over implicit TLS or mandatory STARTTLS, `GB_SMTP_*`); Slack (incoming webhook over the SC-020 egress client, redirects refused, webhook never logged or returned) | None | Alert state, delivery records, and message log (migrations 022 and 024) | FR-4.2, FR-4.4, FR-4.16 to FR-4.19 | IMPLEMENTED |
| Scheduler | Checks enabled-source collection at startup and every 10 minutes while the server is running (each source runs when its interval has elapsed; each source is fetched only when its own persisted interval has elapsed since its last attempt, success or failure; the Collector also drops items published more than 365 days ago so retention is not undone); optional macOS LaunchAgent runs at login and hourly | Respects persisted per-source poll intervals; PostgreSQL advisory lock prevents overlapping collection runs | None | FR-1.8, FR-1.9 | PARTIAL |
| Retention (job) | `internal/retention` runs at server start and every 6 hours (independent of SMTP), deleting stories older than 365 days (by `created_at`) and delivery records older than 90 days in batches of 500, at most 200 batches per run; child rows cascade | Windows from FR-10.1 and FR-10.2; bounded batches; errors are logged and the other table still runs | None (deletes only) | FR-10 | IMPLEMENTED |

### Main data flows

1. **Collect (current):** server scheduler (startup + hourly), macOS LaunchAgent (login + hourly), or manual `cmd/collect` → Collector → CERT-EU, SANS ISC, CERT-FR, CISA, EFF, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, GitHub Advisory Database, additional CISA feeds (ICS, ICS medical, news, blog), FBI IC3, NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News RSS and JSON (HTTPS) → Collector validates and normalizes → Story store. A PostgreSQL advisory lock serializes runs; persisted 24-hour, 30-minute, and one-hour source intervals prevent unnecessary fetches. Additional sources remain future work.
2. **Analyze (current baseline):** the Collector applies deterministic keyword rules and pinned ATT&CK technique-name/alias phrase matching to collected headlines, then persists categories, risk, sentiment, and matched technique tags. Server startup backfills unanalysed stories in bounded batches. Structured feed data, permitted article text, semantic ATT&CK mapping, summaries, and related-story CVE grouping is done, see Analysis method.
3. **Read:** browser → HTTP API (session check) → Identity (role and ownership) → Story store, Source registry, or admin audit store → JSON → React renders it as text.
4. **Alert:** Scheduler → Alerting selects stories for the user → renders per channel, applying content rights → channel adapter → provider. Each attempt goes to delivery records.
5. **Administer:** browser → HTTP API → Identity (admin check) → Source registry or Identity → Audit log.

### Trust boundaries and enforcement points

- **TB-1 Browser ↔ HTTP API.** Authentication, CSRF protection, and the session idle timeout are enforced in HTTP API middleware. Request validation happens at the API edge. Authorization (role and ownership) happens in Identity, called by every handler. The client is never trusted.
- **TB-2 External sources → Collector.** All collected data is untrusted (NFR-3.4). The Collector validates size, type, and URL scheme on intake. Output encoding happens at render time: React escapes text, and email bodies use `html/template`. Slack text is escaped before sending.
- **TB-3 Server → delivery providers (SMTP, Slack) and the HIBP range API.** Outbound only. Slack webhook URLs are validated against the Slack incoming-webhook format when saved (FR-4.16). Provider credentials stay on the server.
- **TB-4 Process ↔ PostgreSQL and secrets on disk.** PostgreSQL listens on localhost only. `cmd/collect` and `cmd/server` use the restricted `gb_app` role; `cmd/migrate` and `cmd/bootstrap` use the local database owner. The server and bootstrap command access the application data key. Secrets at rest are owned by `SECURITY.md`.
- **TB-5 Operator ↔ installation.** The first admin is created at install time (FR-9.7) through a local setup step, not through the web.

**Analysis method (CONFIRMED, AQ-3).** The Analyzer runs local rules only, and no collected content leaves the machine. The current partial implementation applies deterministic keyword rules and exact multiword technique-name/alias matching to story headlines. It loads the compressed Enterprise STIX v20.1 file embedded in the binary, verifies both the compressed asset and official source bundle SHA-256 values, and parses the bundle into typed structs. Technique identifiers are validated and display URLs are generated by the server; bundle-provided URLs are ignored. This is a conservative title-only baseline, not a semantic claim that a story describes a technique. It does not inspect article bodies or structured feed metadata, and it does not map CVE links. The planned full analysis combines keyword and pattern matching on titles and permitted text, structured feed fields (CVSS, CISA KEV membership, CVE IDs, vendor advisory severity), and names and aliases in the MITRE ATT&CK bundle. The Analyzer generates no free-text summaries. Where FR-8.8 permits "system summary" or "verbatim excerpt", the "short summary" shown (FR-4.12, FR-5.2) is a truncated verbatim excerpt. Where only "headline and link" is permitted, no summary is shown. This satisfies FR-8.9 by construction. The exact full rules remain TO BE DECIDED in later steps.

**Semantic analysis (implemented, local).** `analyzer.AnalyzeStory` scores weighted, word-boundary headline cues per category, with negation handling, and derives risk and sentiment. It also reads the story's source formats (CISA KEV, NVD, GitHub advisories, HIBP) as structured hints that add categories and a risk floor. It extracts CVE identifiers (capped per story) and adds cue-based ATT&CK techniques, each validated against the pinned bundle, to the exact-name matches. Results carry `analysis_engine` (`semantic` or `baseline`) and a confidence score (migration 018). If no category reaches the cue threshold, or the semantic path panics, the baseline analyzer result is used, so every story is always analyzed. CVEs go to `story_cves`; stories sharing a CVE are returned as related headline-and-link references (FR-1.13). Only the stored title and source format are analyzed, so no content-policy gate is needed, nothing leaves the machine, no summaries are generated, and no dependency or API key is added. External LLM and local-model options were rejected for privacy, licence (FR-8.8, FR-8.9), cost, and dependency reasons. Title-token clustering was left out; related stories use shared CVEs only. `currentAnalysisVersion` 2 makes the startup backfill re-analyze existing stories.

## Dependency Rules

- **DR-1** Dependencies point one way: Web client → HTTP API → domain components (Identity, Source registry, Story store, Analyzer, Alerting, Audit log) → storage and channel adapters. Nothing points back, and there are no cycles.
- **DR-2** Business rules live only in domain components. They never live in Gin handlers, React code, the SQL layer, or channel or source adapters.
- **DR-3** Each component writes only the data it owns (see the table). Other components use its interface to read or change that data.
- **DR-4** Every content-rights decision (FR-8.8, FR-8.9, FR-1.21) goes through one function, `contentrights.Gate` (`internal/contentrights`), used by the dashboard API and every alert channel. Stores scan stored text into `contentrights.Raw` and return `contentrights.Content`; output story types embed `Content`, so no output type can carry excerpt or summary text that skipped the gate. A guard test fails if another type declares such a field.
- **DR-5** Vendor code (Gin, pgx, feed parser, SMTP provider, Slack) is wrapped in adapters, so domain code never imports it directly.
- **DR-6** The client receives only data the server already authorized and filtered. It never receives secrets, webhook URLs, or hashes (NFR-3.3).
- **DR-7** Jobs (Collector, Analyzer, Alerting, Retention) call domain components. They do not call the HTTP API.

## Diagrams

```mermaid
flowchart LR
  subgraph Browser["Browser (untrusted)"]
    UI[React client]
  end
  subgraph Server["Go process (trusted)"]
    API[HTTP API / Gin<br/>authn, CSRF, validation]
    ID[Identity<br/>authz]
    SR[Source registry]
    ST[Story store]
    AN[Analyzer]
    CO[Collector]
    AL[Alerting]
    AU[Audit log]
    SC[Scheduler]
    DB[(PostgreSQL)]
  end
  subgraph External["External (untrusted)"]
    SRC[News sources,<br/>MITRE]
    PRV[SMTP, Slack,<br/>HIBP range API]
  end
  UI -- TB-1 HTTPS --> API
  API --> ID
  API --> ST & SR & RA & AL
  ID --> AU
  SC --> CO & AN & AL
  CO -- TB-2 --> SRC
  CO --> SR & ST
  AN --> ST & SR
  AL --> ST & SR
  AL -- TB-3 --> PRV
  ID & SR & ST & AL & RA & AU -- TB-4 --> DB
```

## Toolchain

| Check | Command | Notes |
|---|---|---|
| Install (server) | `go mod download` | PostgreSQL 18 is installed separately, for example with `brew install postgresql@18` |
| Install (client) | `npm ci --ignore-scripts` | Uses Node 26 LTS; scripts disabled per SC-091 |
| Build (client) | `npm run build` | Must run before building the Go server; output is embedded in the binary |
| Build (server) | `go build ./...` | |
| Type-check (server) | `go vet ./...` | The compiler type-checks during the build |
| Type-check (client) | `tsc --noEmit` | |
| Test (server) | `go test -race ./...` | |
| Test (client) | `npx vitest run` | |
| Dependency audit (server) | `govulncheck ./...` | Install it with `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| Dependency audit (client) | `npm audit --omit=dev`; `npm audit signatures` | Signatures check per SC-091 |
| Dependency verify (server) | `go mod verify` | Per SC-091 |
| Lint | `go vet ./...` (server). Client: N/A, because `tsc --noEmit` and React's default escaping cover the required checks. | A separate linter is not required by the inputs *(delegated decision)* |

## Open Questions

No architecture choices block implementation. In the interview, the owner answered AQ-1 to AQ-4. The owner then told the author to answer the rest. AQ-5, AQ-6, and AQ-7 were decided on that instruction and are marked *(delegated decision)* in the Stack table. The owner's SMTP provider is still UNKNOWN and will be selected when configuring email delivery. The scaffold's `go.mod`/`go.sum` and `package.json`/`package-lock.json` are committed; review resolved dependency trees and rerun security and license checks before adding proposed packages.

Migration 016 adds the `nvd_json`, `hibp_breaches_json`, and `hacker_news_json` formats. NVD requests ask for critical CVEs published in the last 72 hours; HIBP keeps breaches added in the last 30 days and skips fabricated and spam-list entries; Hacker News fetches the top 100 stories with a fixed 16-worker pool and keeps only security-keyword titles with an external URL. No dependencies were added. ACSC (its site blocks the collector), Reddit, Cloudflare Radar and Zero Wire, FIRST EPSS, CISA Vulnrichment, and abuse.ch are out of scope by owner decision.

Migration 017 adds catalog audit targets (`target_kind`, `target_id`) and the `gb_app` grants for editing categories and sources. Migration 016 is now registered in the migrator, and two semicolons inside its string literals were replaced with commas because the migrator splits statements on semicolons.

Migration 019 grants `gb_app` DELETE on `stories` for the retention job, adds an index on `stories(created_at)`, adds the `account_totp_reset` audit action, and caps source poll intervals at 24 hours. CERT-EU keeps its terms-based 24-hour interval and SANS ISC keeps 30 minutes. The catalog API accepts 1 to 24 hours; FR-1.8 expects hourly unless a source's terms set a lower rate. The CLI recovery path for the last admin's TOTP (SC-057) is not built yet.

Migration 020 removes the TOTP second factor by owner decision. It deletes partial sessions and drops `accounts.totp_required`, `totp_secret_ciphertext`, `totp_nonce`, `totp_enrolled_at`, `last_totp_step`, and `auth_sessions.partial_expires_at`. It is irreversible. The `admin_audit_log` action check keeps `account_totp_reset` so historical rows remain valid. Run `go run ./cmd/migrate` before starting the updated server. `internal/secrets` (the local data key) is no longer used by bootstrap; migration 022 and the server use it again to seal Slack webhooks (SC-071). The SC-057 CLI recovery is moot. Password reset never depended on TOTP.

Migration 021 points the two Canadian Cyber Centre sources at their Atom endpoints (`/api/cccs/atom/v1/get`). The old `/rss/v1/get` URLs answered with a 301 redirect, which the collector refuses by design, so every collection failed. The host is unchanged and the redirect refusal is untouched.


Migration 022 adds `alert_channel_settings` (channel flags and the sealed Slack webhook), `alert_channel_state` (per-channel last-sent and retry state, seeded from `alert_state` as email), and `outbound_message_log` (counts for the Slack test limit, purged after 90 days with delivery records), and widens `alert_deliveries.channel`. Migration 023 added SMS storage (phone number, verification codes, SMS channel values). **SMS was deliberately dropped:** migration 024 deletes SMS state, deliveries, and log rows, drops `phone_verifications` and the `sms_enabled`, `phone_e164`, and `phone_verified_at` columns, and restores the CHECKs to email and Slack only (idempotent, so it is safe on a database that already applied 023). Slack plus the Slack phone app covers mobile push. `internal/secrets.Box` (AES-256-GCM, associated data `purpose:accountID`) still seals webhooks. Slack was tested only against fake local HTTP servers, so real Slack acceptance is unverified.

Migration 026 adds `stories.excerpt` (at most 500 characters). The collector stores a feed-description prefix only where `contentrights` permits an excerpt, and the dashboard, email, Slack, and keyword search read it only through the gate or the `ExcerptPolicies()` parameter. No summaries are generated.

Migration 025 adds `data_sources.rights_class` (`licensed` by default, or `all_rights_reserved`) and a CHECK that an all-rights-reserved source has the `headline_link` policy, so only the headline, source name, and link can be shown (FR-1.21). Existing sources stay `licensed`; all are already `headline_link`. The content-rights gate (`internal/contentrights`) fails closed: an empty, unknown, or all-rights-reserved source set allows no excerpt or summary; `verbatim_excerpt` never allows a summary (FR-8.9); a story reported by several sources gets the most restrictive allowance. Collection still stores only headlines and links, so the gate currently has nothing beyond them to release; it is the prerequisite for summaries and excerpts.

Every alert (email and Slack, including one with no stories) carries the Have I Been Pwned credit and the SANS CC BY-NC-SA 4.0 mark from `alerting.SourceNotices` (FR-8.11, FR-8.12). `Migrate` refuses a database whose newest recorded migration is newer than the binary. Backup and restore are documented in the README.

Migration 027 adds per-story excerpt review (FR-8.8). `data_sources.rights_class` may now be `conditional`; `stories.excerpt_approved_at` and `excerpt_approved_by` record an admin's approval; the audit log gains `story_excerpt_approved`, `story_excerpt_revoked`, and target kind `story`. The collector still stores the verbatim excerpt for a conditional source (so an admin can review it), but `contentrights.Gate` releases it only for an approved story. Admins use `GET /api/admin/review-stories` and `PUT /api/admin/review-stories/:id` (`{"approved": bool}`).
