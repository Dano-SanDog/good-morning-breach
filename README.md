<p align="center"><img src="logo.svg" width="96" height="96" alt="Good Morning Breach logo: a dawn sun over a broken horizon"></p>

# Good Morning Breach

A private, non-commercial morning cybersecurity news feed. Good Morning Breach collects security news from licensed open sources, categorizes and scores each story, tags it with MITRE ATT&CK techniques, and sends each user a morning alert. Logged-in users can also browse all stories on a dashboard.

> **Status:** The application supports approved RSS and JSON sources, initial-admin setup, password-only sign-in, an authenticated stories dashboard with filters and administrator source-health warnings, administrator account management with an audit log, automatic retention of stories and delivery records, saved alert preferences, scheduled email and Slack alerts, password reset by email, and admin-editable categories and data sources. A local semantic engine assigns categories, risk, and sentiment, extracts CVE IDs, groups related stories by shared CVE, and adds ATT&CK tags from the pinned Enterprise bundle; email alerts show these. Story summaries and the remaining product workflows are still in progress. See [REQUIREMENTS.md](REQUIREMENTS.md) for the full, numbered requirements and [DESIGN.md](DESIGN.md) for the design system. This README is a summary; if the two disagree, REQUIREMENTS.md wins.

## Goals

- Give a short, useful picture of the overnight threat landscape every morning.
- Use only ethical data sources, and honor each source's license and terms of use.
- Link stories to MITRE ATT&CK so readers can see the tactics and techniques involved.
- Stay private and non-commercial, for personal use only.

## Data Sources

Source licenses were researched for this use case. See [reports/Licensed cyber news sources.md](reports/Licensed%20cyber%20news%20sources.md).

The migrations seed 24 sources (migrations 001 to 016), all enabled by default: CERT-EU, SANS Internet Storm Center, five CERT-FR feeds, CISA cybersecurity advisories, EFF Deeplinks, UK NCSC, two Canadian Cyber Centre feeds, Kaspersky Securelist, CISA KEV, the GitHub Advisory Database, additional CISA feeds (ICS, ICS medical, news, blog), FBI IC3 (PSA and CSA), NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News (security-keyword titles and links only). Out of scope by owner decision: Australia ASD's ACSC (its site blocks the collector), Reddit, Cloudflare Radar and Zero Wire, FIRST EPSS, CISA Vulnrichment, and abuse.ch (Feodo Tracker, SSL Blacklist, URLhaus, ThreatFox, MalwareBazaar).

| Group | Sources |
| --- | --- |
| Government and CERT | CISA advisories, ICS, ICS medical, news and blog feeds, CISA KEV, NVD critical CVEs, FBI IC3 (PSA and CSA), UK NCSC, CERT-EU, CERT-FR (five feeds), Canadian Cyber Centre (two feeds) |
| Vulnerability and threat data | GitHub Advisory Database, Have I Been Pwned breach catalog |
| News and research | SANS Internet Storm Center, EFF Deeplinks, Kaspersky Securelist, Hacker News (titles and links only) |
| Frameworks | MITRE ATT&CK |

**Out of scope by owner decision (not seeded, and rejected by the admin source API):** Reddit, Cloudflare Radar and Zero Wire, FIRST EPSS, CISA Vulnrichment, abuse.ch, and Australia ASD's ACSC.

**Not used (terms forbid display to other persons):** LevelBlue/AlienVault OTX, GreyNoise free tier, OpenPhish free feed, Spamhaus DROP, Shadowserver.

### Ethical sourcing

- An admin records each source's license, terms link, and permitted use before the source can be enabled. Admins can now do this from the dashboard (see Catalog administration).
- Each source has a content rule: full text, verbatim excerpt, summary, or headline and link only. "All rights reserved" news sources get headline and link only.
- Every story shows its source name, attribution, and a link to the original.
- The per-story SANS ISC attribution includes its CC BY-NC-SA 4.0 notice; CERT-FR attributions identify Licence Ouverte 2.0 and disclaim ANSSI endorsement; EFF attributions identify CC BY 4.0; UK NCSC attributions carry the Open Government Licence v3.0 statement; Canadian Cyber Centre attributions state the copy notice; KEV attributions state CC0 1.0 and no CISA/DHS endorsement; GitHub Advisory Database attributions state CC BY 4.0 and that headlines are reformatted; Securelist attributions carry the "Securelist blog" credit. FBI IC3 has no published reuse terms, so it is headline and link only. NVD, HIBP, and Hacker News attributions are per story. The dashboard footer shows the NVD, MITRE ATT&CK, and Have I Been Pwned notices. No government logos or seals, and no claim of endorsement.
- CISA stories use headline and link only, with a source notice and no implied CISA or DHS endorsement.
- If the service ever becomes commercial, non-commercial-only sources must be disabled or licensed.

## Features

### Morning Alert
**Email alerts.** Signed-in users can save their future email-alert preferences (time, IANA time zone, days, minimum risk, and enabled status). The default form is 07:00 daily at Medium risk and suggests the browser's time zone until saved. Email delivery is sent only when the server has SMTP configured: configure SMTP as described under "Email setup (SMTP)" (`GB_SMTP_HOST`, `GB_SMTP_PORT`, `GB_SMTP_TLS`, `GB_SMTP_USERNAME`, `GB_SMTP_FROM`, and `GB_SMTP_PASSWORD_FILE`; the password is never read from an environment variable). Without `GB_SMTP_HOST` the email channel is unavailable, but the scheduler still runs for Slack. The server checks every minute and sends each enabled account its alert at its saved time, time zone, and days (up to 2 hours late if the server was asleep), with stories collected since its previous alert at or above its minimum risk (at most 10, highest risk first). Failed sends are retried per channel up to 3 times at 10-minute intervals, and a failure on one channel never stops the others. Last-sent state and delivery records (kept 90 days) are stored by migration 012; apply it after updating. Accounts that have never saved alert preferences receive no alert. The email contains each story's title, link, risk, tone, source, publication time, categories, CVE IDs, ATT&CK tags (linked to attack.mitre.org), up to 3 related stories that share a CVE (headline and link only), and each source's required attribution; the MITRE notice appears when tags are shown. Only https links are rendered as links, and all text is escaped. Stories have no summary because only headlines are stored. With `GB_DEV_MAIL_DIR` set and no SMTP, alerts are also written there as `.eml` files for inspection.

**Password reset.** With SMTP configured, the sign-in page offers "Forgot password?". The emailed link (`https://localhost:8443/#reset=…`, token in the fragment) is single use and expires in 30 minutes; the request always gets the same reply, and at most 3 emails per account per hour are sent. A successful reset ends all of the account's sessions. Apply migration 013 after updating. Without SMTP, password reset is disabled: requests get the usual reply but no message is sent, and the server logs a warning at startup. **Local development only:** set `GB_DEV_MAIL_DIR` to an absolute path (created with mode `0700`) and leave `GB_SMTP_HOST` unset; each reset message is then written to a private `0600` file in that directory instead of being emailed (open the newest file to get the link). SMTP always takes precedence, and the message contents are never logged.

Implemented alert behavior (email):
- Default: 07:00 in each user's time zone, every day. Each user can change the time, time zone, and days, or stop the alert.
- Contains stories collected since the last alert at or above the user's minimum risk level (default Medium), highest risk first, up to 10.
- Failed deliveries are retried up to 3 times.

**Slack alerts.** Each user chooses channels under "Alert preferences" (at least one stays on). Migration 022 adds the channel tables. Migration 024 removes the earlier SMS tables and columns and deletes stored phone data (see "SMS was dropped" below).
- Slack: up to 10 stories (headline, link, risk, categories, CVE IDs, ATT&CK tags). The user pastes a Slack incoming webhook (`https://hooks.slack.com/services/...`; anything else is rejected). Saving sends a test message and reports a failure. The webhook is write-only: it is encrypted with AES-256-GCM using the local data key and never shown, returned, or logged. Story text is escaped before it is sent.
- Delivery records for all channels are kept 90 days.

Manual smoke test (needs a real webhook; automated tests use fake local servers only): save a webhook and confirm the test message arrives; set the alert time a few minutes ahead and confirm the message.

### Dashboard
- Shows the last 24 hours by default, sorted by risk.
- Filters by exact category, risk, source, and ATT&CK tactic or technique name or ID, plus local date range and title keyword search. Results are paginated in groups of 100; summaries are not yet stored or searchable.
- Admins see each source's last success, failure and cause, with a warning when an enabled source's first failure since its last success was at least 24 hours ago. An inactive collector alone does not count as a failure.

### Catalog administration
Admins see a "Categories and sources" panel on the dashboard. They can add, rename, enable or disable, and delete categories, and add, edit, enable or disable, and delete sources (name, HTTPS address, format, license name and link, permitted use, attribution, content rule, poll interval of 1 to 24 hours (FR-1.8: hourly by default; use a slower interval only where the source's terms set a lower rate), and whether to skip truncated titles). Endpoints are admin-only: `/api/admin/categories`, `/api/admin/source-records`, and `/api/admin/sources`. Rules: HTTPS only (no credentials, odd ports, local hosts, or blocked IP addresses); out-of-scope and prohibited sources are rejected, including trailing-dot host variants; a source cannot be enabled without a license record; the `other` category cannot be disabled or deleted; a category or source that has stories cannot be deleted, so disable it instead. Collection still uses the guarded outbound client (no redirects, private addresses blocked). Every change writes an audit row, shown in the administrator action log. Sources have no category column. Migration 017 adds this and migration 016 is now registered in the migrator.

### Story Categorization
One or more categories per story. Starting list: Vulnerability, Exploited Vulnerability, Ransomware, Malware, Data Breach, Phishing and Social Engineering, Nation-State Activity, Supply Chain, Cloud and Infrastructure, Internet Outage and DDoS, Policy and Regulation, Other. Admins manage categories as described above.

### Sentiment and Risk Analysis
- Risk: Critical, High, Medium, Low, Informational.
- Sentiment (tone of the story): Negative, Neutral, Positive.

### MITRE ATT&CK Analysis
The pinned Enterprise STIX v20.1 bundle is embedded and hash-checked. The current baseline tags a story only when its headline contains a complete multiword technique name or alias; each tag includes its ID, name, tactic(s), and a server-generated link. A local semantic engine adds cue-based techniques (for example phishing, ransomware, brute force) validated against the bundle, extracts CVE identifiers, and groups stories that share a CVE as related. It uses only headlines and source-format hints, never article text, and falls back to the baseline analyzer. ATT&CK tags and CVE IDs are included in email alerts.

### Data Retention
The server deletes stories 365 days after collection (FR-10.1) and alert delivery records after 90 days (FR-10.2). The job runs at startup and every 6 hours, independent of SMTP, in batches of 500 (up to 200 batches per run); story links to sources, categories, ATT&CK tags, and CVEs are removed with the story. Migration 019 grants `gb_app` the delete permission on stories. The collector does not store items whose publication date is older than 365 days, so deleted stories are not re-collected from feeds that still list them.

## Design

The full design system is in [DESIGN.md](DESIGN.md). A static preview of the palette, type scale, components, and dashboard is in [design/preview.html](design/preview.html). Open the preview file locally in a browser.

- **Look:** a pre-dawn palette, with night-indigo ink on a pale first-light background. The dawn amber appears only in the logo.
- **Risk at a glance:** each story has a left risk spine. It gets thicker and darker as risk rises, from 8 px for Critical to 2 px for Informational. Risk always shows as a word, a colour, and a spine width together.
- **Type:** Atkinson Hyperlegible Next, self-hosted. Atkinson Hyperlegible Mono is used only for CVE and ATT&CK IDs.
- **Accessibility:** every colour pair meets WCAG 2.2 AA. Controls show a visible focus ring and have touch targets of at least 44 px.
- **Security in the UI:**
  - Signed-in state is always visible.
  - Destructive actions need confirmation. Deleting an account means typing its email.
  - Sign-in has one generic error, including for a locked account.
  - Collected content is shown as plain text only.
- **Logo:** [logo.svg](logo.svg) is a dawn sun over a broken horizon, split by a breach crack.

## Access Control

This is a closed service. Every page needs a login, and there is no self sign-up.

- Login: email address and password (at least 12 characters, not on a breached-password list). There is no second factor (removed by owner decision); lockout after 5 failures in 15 minutes, 30-minute idle and 8-hour session limits, and email password reset remain.
- An account is blocked for 15 minutes after 5 failed logins in 15 minutes. Sessions end after 30 minutes of inactivity.

| Role | Capabilities |
| --- | --- |
| **admin** | Everything a user can do, plus manage users, roles, data sources, and categories, and view source status and the admin action log |
| **user** | View the dashboard and manage their own alert settings and profile |

### Account administration

Admins can create accounts with an initial password, change roles, disable or re-enable accounts, delete accounts, and review the 200 most recent administrator actions. New passwords must be at least 12 characters and pass the HIBP Pwned Passwords check; TOTP is required for new accounts by default. Administrators cannot disable, demote, or delete their own account, and the last enabled administrator cannot be removed. Disabling an account revokes its active sessions. An admin can reset another account's authenticator ("Reset authenticator" in the accounts table, `POST /api/admin/accounts/:id/reset-totp`, CSRF-protected): this clears the TOTP secret, ends that account's sessions, writes an audit row in the same transaction, and forces enrollment at the next sign-in. Admins cannot reset their own. There is no recovery path yet for the last admin who loses a device (SC-057 asks for a local CLI).

## Development

Use Go 1.27.4 and Node.js 26.13.1. From the repository root, install the locked client dependencies with `npm ci --ignore-scripts`; run `npm run build`, `npm test`, `go test ./...`, and `go vet ./...` to validate changes. The client build is embedded in the Go server, so run `npm run build` before starting or building the server. `npm run dev` serves only the client and does not provide the API; use the integrated HTTPS server for the working application.

### First feed collection

Install and start PostgreSQL 18, then create the database and its restricted application role (`createuser --login gb_app` and `createdb good_morning_breach`). Run migrations as the local database owner with `GB_MIGRATION_DATABASE_URL='host=127.0.0.1 dbname=good_morning_breach user=YOUR_DB_OWNER sslmode=disable' go run ./cmd/migrate`. The migrations seed the licensed CERT-EU, SANS Internet Storm Center, CERT-FR, CISA, EFF Deeplinks, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, GitHub Advisory Database, additional CISA feeds (ICS, ICS medical, news, blog), FBI IC3, NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News sources and grant the `gb_app` role only the ingestion, authentication, and story-reading permissions the application needs. Run one collection with `GB_DATABASE_URL='host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable' go run ./cmd/collect`. If PostgreSQL requires a password, store it in the local PostgreSQL password file with mode `0600`; do not put it in a connection string or environment variable.

The collector stores normalized headlines and original links, not feed descriptions. It deduplicates stories by canonical link, records source attribution and collection outcomes, and respects each source's persisted poll interval (24 hours for CERT-EU, per its terms; 30 minutes for SANS ISC; one hour for every other source; FR-1.8 allows a slower interval only where a source's terms set a lower rate). Sources whose terms forbid changes (Canadian Cyber Centre and Securelist) skip items whose title would exceed the 300-character limit rather than shortening them. `cmd/collect` remains available for a one-shot manual run; the server also checks for due collections at startup and every 10 minutes while it is running (a source is fetched only when its own interval has elapsed since its last attempt, successful or failed). Database connections are restricted to localhost or a Unix socket, and passwords must not be put in a connection string or environment variable.

### Schedule collection while the server is stopped (macOS)

After applying migrations and setting up the local database role, run `scripts/install-macos-collection-agent.sh` from the repository. It builds the one-shot collector and installs a per-user LaunchAgent that collects at login and hourly. It uses the default local database connection unless a non-secret `GB_DATABASE_URL` is provided during installation; the script rejects connection strings containing passwords or embedded credentials. Store any database password in the local PostgreSQL password file. The server's scheduler continues to run while the server is open; both paths use a PostgreSQL advisory lock so they cannot collect concurrently. The LaunchAgent runs only while the macOS user is logged in and the computer is awake. To stop it, run `launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.goodmorningbreach.collect.plist"`.

### Run the authenticated dashboard

After migrations are applied and the client dependencies are installed:

1. Build the client: `npm run build`.
2. Create and trust a localhost certificate with `mkcert` (install it with `brew install mkcert` on macOS):

   ```sh
   mkdir -p "$HOME/.config/gmb-tls"
   mkcert -install
   mkcert -cert-file "$HOME/.config/gmb-tls/localhost.pem" \
     -key-file "$HOME/.config/gmb-tls/localhost-key.pem" \
     localhost 127.0.0.1 ::1
   chmod 600 "$HOME/.config/gmb-tls/localhost-key.pem"
   ```

   Keep both files outside the repository. The server refuses to start unless the private key is a regular file with mode `0600`.
3. Create the first admin interactively: `go run ./cmd/bootstrap`. Enter the email normally and the password at the hidden prompt. The password must be at least 12 characters and not appear in the HIBP Pwned Passwords service. Sign-in is password-only; there is no authenticator (TOTP) step.
4. (Optional) Run an immediate one-shot collection with `GB_DATABASE_URL='host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable' go run ./cmd/collect`. The server also checks for due stories at startup and periodically while running.
5. Start the server:

   ```sh
   GB_TLS_CERT_FILE="$HOME/.config/gmb-tls/localhost.pem" \
   GB_TLS_KEY_FILE="$HOME/.config/gmb-tls/localhost-key.pem" \
     go run ./cmd/server
   ```

6. Open [https://localhost:8443](https://localhost:8443). The dashboard shows stories from CERT-EU, SANS ISC, CERT-FR, CISA, EFF, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, GitHub Advisory Database, CISA ICS/news/blog, FBI IC3, NVD critical CVEs, the Have I Been Pwned breach catalog, and Hacker News from the last 24 hours, with 100 results per page. Use "Filter stories" to search and select a date range; dates use the browser's local time zone. Admins can expand "View source collection status" to inspect the feeds. Sign-in sessions use a 30-minute idle timeout and an 8-hour maximum lifetime. The server starts a collection check immediately and checks every 10 minutes, while respecting each feed's persisted poll interval.

The migration and bootstrap commands use the local database owner; the server and collector use the restricted `gb_app` role. Migration 009 grants the server the account-management and append-only audit-log permissions it needs; migration 011 adds per-account alert preferences; migration 012 adds alert delivery records; migration 013 adds password reset tokens; migration 017 adds admin editing of categories and sources migration 019 adds story retention deletes, admin authenticator reset auditing, and caps poll intervals at 24 hours; migration 022 adds per-channel alert state, Slack webhook storage, and the outbound message log; migration 023 added SMS phone storage (removed again by migration 024); migration 020 permanently drops the TOTP columns and deletes partial sessions (irreversible; run `go run ./cmd/migrate` before starting the updated server, since the old columns are gone) (migrations 001 to 023 are all applied by `cmd/migrate`). Apply migrations after updating the application. Set `GB_MIGRATION_DATABASE_URL` or `GB_DATABASE_URL` when your local PostgreSQL role/database names differ. Application logs are JSON files under the OS user configuration directory at `good-morning-breach/logs`; they are private, rotate daily, and are pruned after 30 days.

### Email setup (SMTP)

Morning alerts and password reset (the only recovery path, since there is no second factor) need an SMTP account. Messages are sent only over TLS: implicit TLS or mandatory STARTTLS with certificate verification (TLS 1.2 or later). Plaintext SMTP is not supported.

| Variable | Required | Meaning |
|---|---|---|
| `GB_SMTP_HOST` | yes, to enable email | Bare host name, for example `smtp.example.org` (no `https://`, port, or path). Unset disables email. |
| `GB_SMTP_PORT` | no | Default `587`. |
| `GB_SMTP_TLS` | no | `starttls` or `implicit`. Default: `implicit` on port 465, otherwise `starttls`. |
| `GB_SMTP_USERNAME` | usually | Sign-in name; omit only for a relay that needs no sign-in. |
| `GB_SMTP_PASSWORD_FILE` | with a username | Path to a regular, non-empty file with mode `0600` containing only the password or app password. There is no password environment variable. |
| `GB_SMTP_FROM` | if the username is not an email address | Sender address; defaults to the username. |
| `GB_DEV_MAIL_DIR` | no | Development only: write messages to files when `GB_SMTP_HOST` is unset. |

Store the password outside the repository (and never in shell history or an environment variable):

```sh
mkdir -p "$HOME/.config/gmb-smtp"
( umask 077; read -rs -p "SMTP password: " p; printf '%s' "$p" > "$HOME/.config/gmb-smtp/password"; unset p )
chmod 600 "$HOME/.config/gmb-smtp/password"
```

Check the settings before relying on them. `smtptest` reads the same variables, never touches the database, and sends one fixed message to the address you give it:

```sh
export GB_SMTP_HOST=smtp.example.org GB_SMTP_USERNAME=me@example.org \
  GB_SMTP_PASSWORD_FILE="$HOME/.config/gmb-smtp/password"
go run ./cmd/smtptest -verify-only            # connect, TLS, sign-in; sends nothing
go run ./cmd/smtptest -to me@example.org      # also sends a test message
```

The server runs the same connect-and-sign-in check in the background at startup (it never delays startup). An invalid configuration stops startup with a clear error, but if the SMTP server is unreachable or rejects the sign-in, the server logs a warning and keeps running (deliveries are retried later). Passwords, usernames, and message contents are never logged. Messages also depend on your provider accepting the sender address; mail from a domain without matching SPF/DKIM may land in spam.

Typical settings (confirm each against the provider's current documentation; these were not tested against live accounts):

- **Generic SMTP relay:** use the host, port, and credentials the relay gives you. Port 587 with `starttls`, or 465 with `implicit`.
- **Gmail:** host `smtp.gmail.com`, port 587 (or 465 implicit). Turn on 2-Step Verification, create an app password, and put it in the password file. The username and sender are the full Gmail address.
- **iCloud Mail:** host `smtp.mail.me.com`, port 587 `starttls`. Create an app-specific password at account.apple.com; the username is your iCloud address, and the sender must be that address or one of its aliases.

If startup or `smtptest` reports a connection or TLS error, the port and `GB_SMTP_TLS` usually disagree; a sign-in error means a wrong username or password (use an app password where the provider requires one).

## Slack setup

**Slack (no server configuration).** Each user creates an incoming webhook for their own workspace (Slack app settings, Incoming Webhooks, Add New Webhook to Workspace), then pastes it under "Alert preferences". The server creates its data key (`secrets` directory under the OS user configuration directory, mode `0600`) on first start.


## SMS was dropped

Text message (SMS, Twilio) alerts and phone verification were built and then deliberately removed. Slack plus the Slack phone app covers mobile push, so no SMS provider, sender registration, or per-message cost is needed. The `GB_TWILIO_*`, `GB_SMS_DAILY_CAP`, and `GB_SMS_CODE_DAILY_CAP` settings no longer exist. Migration 024 drops the phone and SMS tables and columns; run `go run ./cmd/migrate` after updating.

## Roadmap

- [x] Write requirements ([REQUIREMENTS.md](REQUIREMENTS.md))
- [x] Research source licenses
- [x] Design system, logo, and preview ([DESIGN.md](DESIGN.md))
- [x] Choose and pin the tech stack baseline ([ARCHITECTURE.md](ARCHITECTURE.md); remaining proposed dependencies need checks before integration)
- [x] Create and audit the Go/React application scaffold
- [x] Implement the first licensed RSS ingestion slice (CERT-EU)
- [x] Schedule enabled-source collection while the server is running
- [x] Schedule collection while the server is stopped on macOS
- [x] Add the approved launch sources (24 seeded sources; see Data Sources)
- [x] Admin-editable categories and sources
- [x] Add categorization and risk scoring (local semantic engine with keyword baseline fallback)
- [x] MITRE ATT&CK mapping and email presentation (headline phrase and cue-based tags; shown on the dashboard and in email)
- [x] Complete authentication and roles (admin account management and audit log are implemented; password reset requires SMTP, see Alert email)
- [ ] Complete the dashboard (filters, admin source status, footer notices, catalog administration, CVE IDs, and related stories are implemented; summaries and summary search remain)
- [x] Add alert delivery (scheduled delivery with retries is implemented; email and Slack channels are implemented)

### Remaining work

- Story summaries and summary search, only where a source's content policy permits (FR-8.8, FR-8.9).
- The single content-rights gate for every output path (SC-023) and the "all rights reserved" source type (FR-1.21).
