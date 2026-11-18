#!/bin/sh
set -eu
umask 077

repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
support_dir="$HOME/Library/Application Support/Good Morning Breach"
bin_dir="$support_dir/bin"
agent_dir="$HOME/Library/LaunchAgents"
agent_label="com.goodmorningbreach.collect"
agent_path="$agent_dir/$agent_label.plist"
agent_tmp="$agent_path.tmp.$$"
binary_path="$bin_dir/gb-collect"
binary_tmp="$binary_path.tmp.$$"

for executable in go plutil launchctl tr; do
	if ! command -v "$executable" >/dev/null 2>&1; then
		printf 'Required command not found: %s\n' "$executable" >&2
		exit 1
	fi
done

if [ -n "${GB_DATABASE_URL:-}" ]; then
	database_url_lower=$(printf '%s' "$GB_DATABASE_URL" | tr '[:upper:]' '[:lower:]')
	case "$database_url_lower" in
		*password=*|*://*@*)
			printf 'GB_DATABASE_URL must not contain credentials; use the local PostgreSQL password file.\n' >&2
			exit 1
			;;
	esac
fi

mkdir -p "$bin_dir" "$agent_dir"
trap 'rm -f "$agent_tmp" "$binary_tmp"' EXIT

cd "$repo_root"
go build -o "$binary_tmp" ./cmd/collect
chmod 700 "$binary_tmp"
mv -f "$binary_tmp" "$binary_path"

plutil -create xml1 "$agent_tmp"
plutil -insert Label -string "$agent_label" "$agent_tmp"
plutil -insert ProgramArguments -array "$agent_tmp"
plutil -insert ProgramArguments.0 -string "$binary_path" "$agent_tmp"
if [ -n "${GB_DATABASE_URL:-}" ]; then
	plutil -insert EnvironmentVariables -dictionary "$agent_tmp"
	plutil -insert EnvironmentVariables.GB_DATABASE_URL -string "$GB_DATABASE_URL" "$agent_tmp"
fi
plutil -insert RunAtLoad -bool true "$agent_tmp"
plutil -insert StartInterval -integer 3600 "$agent_tmp"
plutil -lint "$agent_tmp"
chmod 600 "$agent_tmp"
mv -f "$agent_tmp" "$agent_path"

user_domain="gui/$(id -u)"
if launchctl print "$user_domain/$agent_label" >/dev/null 2>&1; then
	launchctl bootout "$user_domain" "$agent_path"
fi
launchctl bootstrap "$user_domain" "$agent_path"
launchctl enable "$user_domain/$agent_label"
launchctl print "$user_domain/$agent_label" >/dev/null

printf 'Installed and started %s\n' "$agent_path"
