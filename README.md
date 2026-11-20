<p align="center"><img src="logo.svg" width="96" height="96" alt="Good Morning Breach logo: a dawn sun over a broken horizon"></p>

# Good Morning Breach

A private, non-commercial morning cybersecurity news feed. Good Morning Breach collects security news from licensed open sources, categorizes and scores each story, tags it with MITRE ATT&CK techniques, and sends each user a morning alert. Logged-in users can also browse all stories on a dashboard.

> **Status:** The application supports approved RSS and JSON sources, initial-admin setup, password sign-in with per-account TOTP requirements, an authenticated stories dashboard with filters and administrator source-health warnings, administrator account management with an audit log, and saved email-alert preferences. A partial analysis baseline assigns categories, risk, and sentiment, ranks stories by risk, and adds conservative title-phrase ATT&CK tags from the pinned Enterprise bundle. Alert delivery, password reset, admin-editable categories and sources, semantic analysis, email display, and the remaining product workflows are still in progress. See [REQUIREMENTS.md](REQUIREMENTS.md) for the full, numbered requirements and [DESIGN.md](DESIGN.md) for the design system. This README is a summary; if the two disagree, REQUIREMENTS.md wins.

## Goals

- Give a short, useful picture of the overnight threat landscape every morning.
- Use only ethical data sources, and honor each source's license and terms of use.
- Link stories to MITRE ATT&CK so readers can see the tactics and techniques involved.
- Stay private and non-commercial, for personal use only.

## Data Sources

Source licenses were researched for this use case. See [reports/Licensed cyber news sources.md](reports/Licensed%20cyber%20news%20sources.md).

The collector currently enables CERT-EU, SANS Internet Storm Center, five CERT-FR feeds, CISA cybersecurity advisories, EFF Deeplinks, UK NCSC, two Canadian Cyber Centre feeds, Kaspersky Securelist, CISA KEV, and the GitHub Advisory Database; the sources below are the planned launch set, not all implemented yet.

| Group | Sources at launch |
| --- | --- |
| Government and CERT | remaining CISA advisory feeds, NVD API, FBI IC3, CERT-EU, CERT-FR, Australia ASD's ACSC |
| Vulnerability and threat data | FIRST EPSS, CISA Vulnrichment, abuse.ch (Feodo Tracker, SSL Blacklist, URLhaus, ThreatFox, MalwareBazaar), Have I Been Pwned breach catalog |
| News and research | SANS Internet Storm Center, EFF Deeplinks, Hacker News (titles and links only) |
| Internet signals | Cloudflare Radar (outages, attack trends, BGP events), Cloudflare Zero Wire (headline, link, CVE IDs, action label only) |
| Frameworks | MITRE ATT&CK |
| Reddit | r/netsec and r/cybersecurity, **only after Reddit approves API access**; titles and links shown without change, never summarized or scored |

**Not used:** LevelBlue/AlienVault OTX, GreyNoise free tier, OpenPhish free feed, Spamhaus DROP, Shadowserver. Their terms forbid display to other persons.

### Ethical sourcing

- An admin records each source's license, terms link, and permitted use before the source can be enabled.
- Each source has a content rule: full text, verbatim excerpt, summary, or headline and link only. "All rights reserved" news sources get headline and link only.
- Every story shows its source name, attribution, and a link to the original.
- The per-story SANS ISC attribution includes its CC BY-NC-SA 4.0 notice; CERT-FR attributions identify Licence Ouverte 2.0 and disclaim ANSSI endorsement; EFF attributions identify CC BY 4.0; UK NCSC attributions carry the Open Government Licence v3.0 statement; Canadian Cyber Centre attributions state the copy notice; KEV attributions state CC0 1.0 and no CISA/DHS endorsement; GitHub Advisory Database attributions state CC BY 4.0 and that headlines are reformatted; Securelist attributions carry the "Securelist blog" credit. Global NVD, MITRE ATT&CK, and Have I Been Pwned notices remain to be implemented. No government logos or seals, and no claim of endorsement.
- CISA stories use headline and link only, with a source notice and no implied CISA or DHS endorsement.
- If the service ever becomes commercial, non-commercial-only sources must be disabled or licensed.

## Features

### Morning Alert
**Email alerts.** Signed-in users can save their future email-alert preferences (time, IANA time zone, days, minimum risk, and enabled status). The default form is 07:00 daily at Medium risk and suggests the browser's time zone until saved. Email delivery is sent only when the server has SMTP configured: set `GB_SMTP_HOST`, optionally `GB_SMTP_PORT` (default 587; 465 uses implicit TLS, other ports require STARTTLS), `GB_SMTP_USERNAME`, `GB_SMTP_FROM`, and `GB_SMTP_PASSWORD_FILE` (a regular `0600` file containing the app password; never put the password in an environment variable). Without `GB_SMTP_HOST`, alerts are disabled. The server checks every minute and sends each enabled account its alert at its saved time, time zone, and days (up to 2 hours late if the server was asleep), with stories collected since its previous alert at or above its minimum risk (at most 10, highest risk first). Failed sends are retried up to 3 times at 10-minute intervals. Last-sent state and delivery records (kept 90 days) are stored by migration 012; apply it after updating. Accounts that have never saved alert preferences receive no alert. Text message and Slack channels are not implemented.

**Password reset.** With SMTP configured, the sign-in page offers "Forgot password?". The emailed link (`https://localhost:8443/#reset=…`, token in the fragment) is single use and expires in 30 minutes; the request always gets the same reply, and at most 3 emails per account per hour are sent. A successful reset ends all of the account's sessions; TOTP is still required at sign-in. Apply migration 013 after updating. Without SMTP, password reset is disabled: requests get the usual reply but no message is sent, and the server logs a warning at startup. **Local development only:** set `GB_DEV_MAIL_DIR` to an absolute path (created with mode `0700`) and leave `GB_SMTP_HOST` unset; each reset message is then written to a private `0600` file in that directory instead of being emailed (open the newest file to get the link). SMTP always takes precedence, and the message contents are never logged.

The planned alert behavior is:
- Default: 07:00 in each user's time zone, every day. Each user can change the time, time zone, and days, or stop the alert.
- Channels, chosen per user: **Email**, **Text (SMS)**, **Slack** (user-supplied incoming webhook).
- Contains stories collected since the last alert at or above the user's minimum risk level (default Medium), highest risk first.
- Email and Slack: up to 10 stories. SMS: up to 3 titles and a dashboard link.
- Phone numbers are verified by code. Slack webhooks get a test message. Failed deliveries are retried up to 3 times.

### Dashboard
- Shows the last 24 hours by default, sorted by risk.
- Filters by exact category, risk, source, and ATT&CK tactic or technique name or ID, plus local date range and title keyword search. Results are paginated in groups of 100; summaries are not yet stored or searchable.
- Cloudflare Radar data is not yet implemented.
- Admins see each source's last success, failure and cause, with a warning when an enabled source's first failure since its last success was at least 24 hours ago. An inactive collector alone does not count as a failure.

### Story Categorization
One or more categories per story. Starting list: Vulnerability, Exploited Vulnerability, Ransomware, Malware, Data Breach, Phishing and Social Engineering, Nation-State Activity, Supply Chain, Cloud and Infrastructure, Internet Outage and DDoS, Policy and Regulation, Other. Admins can add, rename, and disable categories.

### Sentiment and Risk Analysis
- Risk: Critical, High, Medium, Low, Informational.
- Sentiment (tone of the story): Negative, Neutral, Positive.

### MITRE ATT&CK Analysis
The pinned Enterprise STIX v20.1 bundle is embedded and hash-checked. The current baseline tags a story only when its headline contains a complete multiword technique name or alias; each tag includes its ID, name, tactic(s), and a server-generated link. This does not inspect article text or infer techniques semantically. Email alerts are not implemented yet.

### Data Retention
Stories are kept for 365 days. Alert delivery records are kept for 90 days.

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

- Login: email address and password (at least 12 characters, not on a breached-password list). TOTP is required by default, but can be disabled for an individual account.
- An account is blocked for 15 minutes after 5 failed logins in 15 minutes. Sessions end after 30 minutes of inactivity.

| Role | Capabilities |
| --- | --- |
| **admin** | Everything a user can do, plus manage users, roles, data sources, and categories, and view source status and the admin action log |
| **user** | View the dashboard and manage their own alert settings and profile |

### Account administration

Admins can create accounts with an initial password, change roles, disable or re-enable accounts, delete accounts, and review the 200 most recent administrator actions. New passwords must be at least 12 characters and pass the HIBP Pwned Passwords check; TOTP is required for new accounts by default. Administrators cannot disable, demote, or delete their own account, and the last enabled administrator cannot be removed. Disabling an account revokes its active sessions.

## Development

Use Go 1.27.4 and Node.js 26.13.1. From the repository root, install the locked client dependencies with `npm ci --ignore-scripts`; run `npm run build`, `npm test`, `go test ./...`, and `go vet ./...` to validate changes. The client build is embedded in the Go server, so run `npm run build` before starting or building the server. `npm run dev` serves only the client and does not provide the API; use the integrated HTTPS server for the working application.

### First feed collection

Install and start PostgreSQL 18, then create the database and its restricted application role (`createuser --login gb_app` and `createdb good_morning_breach`). Run migrations as the local database owner with `GB_MIGRATION_DATABASE_URL='host=127.0.0.1 dbname=good_morning_breach user=YOUR_DB_OWNER sslmode=disable' go run ./cmd/migrate`. The migrations seed the licensed CERT-EU, SANS Internet Storm Center, CERT-FR, CISA, EFF Deeplinks, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, and GitHub Advisory Database RSS and JSON sources and grant the `gb_app` role only the ingestion, authentication, and story-reading permissions the application needs. Run one collection with `GB_DATABASE_URL='host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable' go run ./cmd/collect`. If PostgreSQL requires a password, store it in the local PostgreSQL password file with mode `0600`; do not put it in a connection string or environment variable.

The collector stores normalized headlines and original links, not feed descriptions. It deduplicates stories by canonical link, records source attribution and collection outcomes, and respects each source's persisted poll interval (24 hours for CERT-EU, 30 minutes for SANS ISC, and one hour for every other source). Sources whose terms forbid changes (Canadian Cyber Centre and Securelist) skip items whose title would exceed the 300-character limit rather than shortening them. `cmd/collect` remains available for a one-shot manual run; the server also checks for due collections at startup and once per hour while it is running. Database connections are restricted to localhost or a Unix socket, and passwords must not be put in a connection string or environment variable.

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
3. Create the first admin interactively: `go run ./cmd/bootstrap`. Enter the email normally and the password at the hidden prompt. The password must be at least 12 characters and not appear in the HIBP Pwned Passwords service. Accounts with TOTP required enroll an authenticator on first sign-in.
4. (Optional) Run an immediate one-shot collection with `GB_DATABASE_URL='host=127.0.0.1 dbname=good_morning_breach user=gb_app sslmode=disable' go run ./cmd/collect`. The server also checks for due stories at startup and periodically while running.
5. Start the server:

   ```sh
   GB_TLS_CERT_FILE="$HOME/.config/gmb-tls/localhost.pem" \
   GB_TLS_KEY_FILE="$HOME/.config/gmb-tls/localhost-key.pem" \
     go run ./cmd/server
   ```

6. Open [https://localhost:8443](https://localhost:8443). The dashboard shows stories from CERT-EU, SANS ISC, CERT-FR, CISA, EFF, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, and GitHub Advisory Database from the last 24 hours, with 100 results per page. Use "Filter stories" to search and select a date range; dates use the browser's local time zone. Admins can expand "View source collection status" to inspect the feeds. Sign-in sessions use a 30-minute idle timeout and an 8-hour maximum lifetime. The server starts a collection check immediately and checks hourly, while respecting each feed's persisted poll interval.

The migration and bootstrap commands use the local database owner; the server and collector use the restricted `gb_app` role. Migration 009 grants the server the account-management and append-only audit-log permissions it needs; migration 011 adds per-account alert preferences. Apply migrations after updating the application. Set `GB_MIGRATION_DATABASE_URL` or `GB_DATABASE_URL` when your local PostgreSQL role/database names differ. Application logs are JSON files under the OS user configuration directory at `good-morning-breach/logs`; they are private, rotate daily, and are pruned after 30 days.

## Roadmap

- [x] Write requirements ([REQUIREMENTS.md](REQUIREMENTS.md))
- [x] Research source licenses
- [x] Design system, logo, and preview ([DESIGN.md](DESIGN.md))
- [x] Choose and pin the tech stack baseline ([ARCHITECTURE.md](ARCHITECTURE.md); remaining proposed dependencies need checks before integration)
- [x] Create and audit the Go/React application scaffold
- [x] Implement the first licensed RSS ingestion slice (CERT-EU)
- [x] Schedule enabled-source collection while the server is running
- [x] Schedule collection while the server is stopped on macOS
- [ ] Add the remaining approved sources (CERT-EU, SANS ISC, CERT-FR, CISA advisories, EFF Deeplinks, UK NCSC, Canadian Cyber Centre, Securelist, CISA KEV, and GitHub Advisory Database are implemented)
- [ ] Add categorization and risk scoring
- [ ] Complete MITRE ATT&CK mapping and alert presentation (headline phrase matching is implemented)
- [x] Complete authentication and roles (admin account management and audit log are implemented; password reset requires SMTP, see Alert email)
- [ ] Complete the dashboard (filters and admin source status are implemented; fuller analysis, summary search, and Radar remain)
- [ ] Add alert delivery (email preferences are saved; scheduling, email, SMS, and Slack delivery remain)
- [ ] Apply for Reddit API access
