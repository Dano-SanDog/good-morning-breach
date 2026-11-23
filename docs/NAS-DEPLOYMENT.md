# Moving to a Synology NAS (Virtual Machine Manager)

This guide moves Good Morning Breach from a MacBook to an Ubuntu Server VM in Synology Virtual Machine Manager (VMM). Commands were checked against this repository's code and README, but **nothing here has been run on real Synology hardware**. Treat VMM screens and DSM menu names as approximate.

## Read first: how you reach the app

The server listens on `127.0.0.1:8443` only (hard-coded in `internal/httpserver/server.go`) and builds password-reset links as `https://localhost:8443`. So other LAN devices cannot open it directly. The supported path with no code change is an **SSH tunnel** from your Mac (step 9). Direct LAN access (a configurable bind address and public base URL) would need a code change and a SECURITY.md update; it is not covered here.

Alerts do not need a browser: the scheduler runs on the VM, so email and Slack work around the clock.

## 1. VMM prerequisites and sizing

- VMM runs only on supported x86-64 Synology models (Intel/AMD). ARM models do not support VMM. Check your model at synology.com's VMM package page. Install **Virtual Machine Manager** from DSM Package Center.
- Free RAM: 2 GB for the VM, plus DSM's own needs. Suggested VM: 2 vCPU, 2 GB RAM, 20 GB disk (thin provisioned, on a volume with a snapshot or backup schedule).
- Linux: **Ubuntu Server 24.04 LTS (amd64) ISO**. Upload it in VMM under Image, create the VM, and install with OpenSSH server enabled. Use a Btrfs volume; keep the VM on the default NAS network with a DHCP reservation (or static IP) so its address does not change.
- Under the VM's Autostart option, enable **Auto-start with the NAS** (VMM > Virtual Machine > Edit > General). Install `qemu-guest-agent` in the VM for clean shutdowns: `sudo apt install qemu-guest-agent`.
- If the NAS is ARM (no VMM), or you want a different CPU type, set `GOARCH=arm64` in step 3 on a VM of that type. Not verified.

## 2. Prepare the VM

```sh
sudo apt update && sudo apt full-upgrade -y
sudo timedatectl set-ntp true
sudo timedatectl set-timezone America/Los_Angeles   # your zone; check with: timedatectl
sudo adduser --system --group --home /var/lib/gmb --shell /usr/sbin/nologin gmb
```

Each user's alert time zone is stored per account and the scheduler uses it, so the VM clock only has to be correct (NTP on). Keep the NAS's own NTP enabled too (DSM Control Panel > Regional Options).

## 3. Build the Linux binaries (on the Mac)

The client is embedded in the server, so build it first.

```sh
npm ci --ignore-scripts && npm run build
mkdir -p dist-linux
for c in server migrate collect bootstrap smtptest; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist-linux/gb-$c ./cmd/$c
done
scp dist-linux/gb-* YOU@VM_IP:/tmp/
```

On the VM:

```sh
sudo install -o root -g root -m 0755 /tmp/gb-* /usr/local/bin/
rm /tmp/gb-*
```

Alternative: install Go 1.27.4 and Node 26 on the VM, clone the repo, and run the same commands. Cross-compiling keeps the VM small.

## 4. Install PostgreSQL 18

Ubuntu 24.04's own repository ships an older major, so use the PostgreSQL project's apt repository (PGDG):

```sh
sudo apt install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh
sudo apt install -y postgresql-18
sudo -u postgres psql -c 'SHOW listen_addresses;'   # must be localhost
```

SC-073: keep `listen_addresses = 'localhost'` and no `md5` or `trust` in `/etc/postgresql/18/main/pg_hba.conf` (the Ubuntu default uses `peer` for the socket and `scram-sha-256` for TCP).

Create the roles and database. The migrator and `bootstrap` run as an owner role (`gmb`, matched to the OS user by peer authentication). The server and collector run as the restricted `gb_app` role, which must exist before migration because migrations grant to it.

```sh
sudo -u postgres createuser gmb
sudo -u postgres createuser --login gb_app
sudo -u postgres createdb --owner=gmb good_morning_breach
sudo -u postgres psql -c '\password gb_app'      # choose a long random password
```

Store the `gb_app` password in the service user's PostgreSQL password file (never in a URL or environment variable):

```sh
sudo -u gmb install -d -m 0700 /var/lib/gmb
sudo -u gmb sh -c 'umask 077; printf "127.0.0.1:5432:good_morning_breach:gb_app:%s\n" "THE_PASSWORD" > /var/lib/gmb/.pgpass'
```

(Typing the password on the command line leaves it in shell history; use `read -s` and expand a variable if you prefer.)

## 5. Move the data from the Mac

On the Mac, stop the server and the collector, then dump (see README "Backup and restore"):

```sh
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.goodmorningbreach.collect.plist"
# stop the running server (Ctrl+C or kill its PID)
pg_dump --format=custom --host=127.0.0.1 --username=YOUR_DB_OWNER \
  --file=gmb-final.dump good_morning_breach
```

Copy three things to the VM (use `scp`; keep them off shared folders):

- `gmb-final.dump`
- the **data key**: `~/Library/Application Support/good-morning-breach/data-key` (losing it breaks every saved Slack webhook)
- the SMTP app-password file you pointed `GB_SMTP_PASSWORD_FILE` at

On the VM:

```sh
sudo install -d -o gmb -g gmb -m 0700 /var/lib/gmb/.config /var/lib/gmb/.config/good-morning-breach /etc/gmb
sudo install -o gmb -g gmb -m 0600 /tmp/data-key /var/lib/gmb/.config/good-morning-breach/data-key
sudo install -o gmb -g gmb -m 0600 /tmp/smtp-password /etc/gmb/smtp-password
sudo -u gmb pg_restore --exit-on-error --no-owner --dbname=good_morning_breach /tmp/gmb-final.dump
sudo -u gmb env GB_MIGRATION_DATABASE_URL='host=/var/run/postgresql dbname=good_morning_breach user=gmb' gb-migrate
shred -u /tmp/data-key /tmp/smtp-password /tmp/gmb-final.dump
```

Where the data key lives: Go's `os.UserConfigDir()` is `$HOME/.config` on Linux; with `HOME=/var/lib/gmb` that is the path above. The directory must be `0700` and the file `0600`, or the server refuses to start. `gb-migrate` re-applies the `gb_app` grants and refuses a database newer than the binary. (A fresh install instead: skip the dump and run `sudo -u gmb ... gb-bootstrap` after migrating.)

## 6. TLS certificate

The certificate must cover only `localhost`, `127.0.0.1`, and `::1` (SC-002), and the key must be a `0600` file outside the repository. Because you reach the app through a tunnel to `localhost`, **reuse the Mac's mkcert certificate**; your Mac already trusts it.

```sh
# on the Mac
scp "$HOME/.config/gmb-tls/localhost.pem" "$HOME/.config/gmb-tls/localhost-key.pem" YOU@VM_IP:/tmp/
# on the VM
sudo install -d -o gmb -g gmb -m 0700 /etc/gmb/tls
sudo install -o gmb -g gmb -m 0600 /tmp/localhost-key.pem /etc/gmb/tls/
sudo install -o gmb -g gmb -m 0644 /tmp/localhost.pem /etc/gmb/tls/
shred -u /tmp/localhost-key.pem; rm /tmp/localhost.pem
```

Do not expose the VM to the internet and do not buy certificates. Other devices need a code change (see "Read first").

## 7. Configuration file and systemd units

`/etc/gmb/server.env` (mode `0600`, owner `gmb`) holds non-secret settings only. Copy the SMTP values from the Mac's environment. No secret goes here: the SMTP password is read from the file and the DB password from `.pgpass`.

```sh
sudo sh -c 'umask 077; cat > /etc/gmb/server.env' <<'EOT'
GB_TLS_CERT_FILE=/etc/gmb/tls/localhost.pem
GB_TLS_KEY_FILE=/etc/gmb/tls/localhost-key.pem
GB_SMTP_HOST=smtp.mail.me.com
GB_SMTP_PORT=587
GB_SMTP_TLS=starttls
GB_SMTP_USERNAME=you@icloud.com
GB_SMTP_FROM=you@icloud.com
GB_SMTP_PASSWORD_FILE=/etc/gmb/smtp-password
EOT
sudo chown gmb:gmb /etc/gmb/server.env
```

Use the exact values you use on the Mac. `GB_SMTP_TLS` accepts `starttls` or `implicit`. The default database URL (`127.0.0.1`, role `gb_app`) is already correct, so `GB_DATABASE_URL` is not needed.

`/etc/systemd/system/gmb-server.service`:

```ini
[Unit]
Description=Good Morning Breach server
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
User=gmb
Group=gmb
Environment=HOME=/var/lib/gmb
EnvironmentFile=/etc/gmb/server.env
ExecStart=/usr/local/bin/gb-server
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gmb
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/gmb-collect.service` and `.timer` (the hourly one-shot, equivalent to the macOS LaunchAgent; the server also collects while running, and both use a database advisory lock):

```ini
# gmb-collect.service
[Unit]
Description=Good Morning Breach one-shot collection
After=postgresql.service

[Service]
Type=oneshot
User=gmb
Environment=HOME=/var/lib/gmb
ExecStart=/usr/local/bin/gb-collect
```

```ini
# gmb-collect.timer
[Unit]
Description=Hourly collection

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and check:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now gmb-server.service gmb-collect.timer
systemctl status gmb-server --no-pager
journalctl -u gmb-server -n 30 --no-pager
sudo -u gmb env $(sudo cat /etc/gmb/server.env | xargs) gb-smtptest --verify-only   # checks SMTP login; add --to you@example.org to send a test
```

`ProtectHome=true` keeps the unit from reading real home directories; `/var/lib/gmb` (with the data key, logs, and `.pgpass`) stays writable. If the server fails to start under these hardening options, loosen them one at a time and note it; this was not tested here.

## 8. Firewall (LAN only)

The app listens on loopback only, so the only inbound service is SSH:

```sh
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp   # use your LAN subnet
sudo ufw enable
```

Do not port-forward anything on your router to the VM. Also review the Synology firewall (DSM Control Panel > Security).

## 9. Use it from the Mac

```sh
ssh -N -L 8443:127.0.0.1:8443 YOU@VM_IP
```

Open https://localhost:8443. Stop your Mac's local server first or the port will be taken. Password-reset links (which point at `localhost:8443`) work only while the tunnel is open.

## 10. Backups and restore test

On the VM, a daily dump by the `gmb` user (peer authentication, no password):

```sh
sudo install -d -o gmb -g gmb -m 0700 /var/backups/gmb
sudo tee /etc/systemd/system/gmb-backup.service <<'EOT'
[Unit]
Description=Good Morning Breach database dump

[Service]
Type=oneshot
User=gmb
UMask=0077
ExecStart=/bin/sh -c 'pg_dump --format=custom --file=/var/backups/gmb/gmb-$(date +%%F).dump good_morning_breach && ls -1t /var/backups/gmb/gmb-*.dump | tail -n +15 | xargs -r rm -f'
EOT
sudo tee /etc/systemd/system/gmb-backup.timer <<'EOT'
[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOT
sudo systemctl daemon-reload && sudo systemctl enable --now gmb-backup.timer
sudo systemctl start gmb-backup.service && ls -l /var/backups/gmb
```

Also back up `/var/lib/gmb/.config/good-morning-breach/data-key` and `/etc/gmb/smtp-password` somewhere separate and encrypted (a password manager), and copy the dumps off the VM: use a Hyper Backup task or snapshot of the VM volume in DSM, or `rsync` the dump directory to another host. **Restore test** (do it once now, then monthly), never over the live database:

```sh
sudo -u gmb createdb good_morning_breach_restore
sudo -u gmb pg_restore --exit-on-error --no-owner --dbname=good_morning_breach_restore /var/backups/gmb/gmb-YYYY-MM-DD.dump
sudo -u gmb psql good_morning_breach_restore -c 'SELECT count(*) FROM stories; SELECT max(version) FROM schema_migrations;'
sudo -u gmb dropdb good_morning_breach_restore
```

## 11. Cutover checklist

1. Mac: server stopped, collection LaunchAgent unloaded (step 5), so two machines never send duplicate alerts. Do not restart either on the Mac afterwards.
2. VM: database restored, `gb-migrate` run, data key and SMTP password in place with the right modes (steps 5 and 7).
3. `systemctl status gmb-server gmb-collect.timer`; `journalctl -u gmb-server` shows a clean start and a collection check.
4. Open the tunnel (step 9) and sign in; confirm stories, users, and alert settings arrived.
5. Admin source-health panel: sources collecting; run `sudo systemctl start gmb-collect.service` once.
6. Email: trigger a password reset to your own account, or set your alert time a few minutes ahead, and confirm the email arrives with the embedded logo.
7. Slack: in Alert settings, replace nothing; re-save your own webhook to send a test message, and confirm the next alert reaches Slack (a failing decrypt means the data key was not copied correctly). Check the Slack alert shows the logo: it loads from `raw.githubusercontent.com` (`alerting.SlackLogoURL`), which works only while the repository is public and the file is on `main`.
8. Reboot the VM and then the NAS; confirm VMM auto-starts the VM and the services return without action.
9. Confirm the next 07:00 alert arrives on time.

## 12. Rollback

Until you are confident, keep the Mac's database untouched (the dump is read-only). To roll back: `sudo systemctl disable --now gmb-server.service gmb-collect.timer` on the VM, then on the Mac reload the LaunchAgent (`scripts/install-macos-collection-agent.sh`) and start the server. Alerts sent from the VM during the trial are not recorded on the Mac, so users may receive one repeated alert. If you want to keep VM changes, take a new dump on the VM and restore it on the Mac as in README "Backup and restore".

## Not verified

VMM/DSM menu paths, Autostart wording, the hardened systemd options, and everything on real Synology hardware. Checked only against the repository's code and README.
