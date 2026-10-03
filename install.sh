#!/bin/sh

set -eu

umask 077

download_base_url="${LOREVA_DOWNLOAD_BASE_URL:-https://github.com/FroZor/loreva-agent/releases/latest/download}"
install_path="${LOREVA_INSTALL_PATH:-/usr/local/bin/loreva-agent}"

fail() {
	printf 'loreva-agent installer: %s\n' "$1" >&2
	exit 1
}

usage="usage: ./install.sh [--portal | --config FILE]"
mode="standalone"
config_path=""

case "$#:${1:-}" in
	0:) ;;
	1:--portal)
		mode="portal"
		;;
	2:--config)
		mode="portal"
		config_path="$2"
		if [ -L "$config_path" ] || [ ! -f "$config_path" ]; then
			fail "bootstrap config must be a regular file, not a link"
		fi
		;;
	*)
		fail "$usage"
		;;
esac

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

download() {
	curl \
		--fail \
		--silent \
		--show-error \
		--location \
		--proto '=https' \
		--proto-redir '=https' \
		--tlsv1.2 \
		--connect-timeout 10 \
		--max-time 300 \
		--max-filesize 134217728 \
		"$1" \
		--output "$2"
}

resolve_architecture() {
	case "$(uname -m)" in
		x86_64 | amd64)
			printf 'amd64\n'
			;;
		aarch64 | arm64)
			printf 'arm64\n'
			;;
		*)
			fail "unsupported architecture: $(uname -m)"
			;;
	esac
}

verify_download() {
	asset_name="$1"
	asset_path="$2"
	checksums_path="$3"

	expected_checksum="$(awk -v asset="$asset_name" '$2 == asset { print $1 }' "$checksums_path")"
	case "$expected_checksum" in
		*[!0-9a-fA-F]* | "")
			fail "release checksum is missing or invalid"
			;;
	esac

	[ "${#expected_checksum}" -eq 64 ] || fail "release checksum has an invalid length"

	actual_checksum="$(sha256sum "$asset_path" | awk '{ print $1 }')"
	[ "$actual_checksum" = "$expected_checksum" ] || fail "binary checksum verification failed"
}

ensure_service_user() {
	service_user="$1"
	state_dir="$2"

	if id "$service_user" >/dev/null 2>&1; then
		return
	fi

	if command -v useradd >/dev/null 2>&1; then
		nologin_shell="$(command -v nologin || true)"
		[ -n "$nologin_shell" ] || fail "nologin shell not found"

		useradd \
			--system \
			--user-group \
			--home-dir "$state_dir" \
			--shell "$nologin_shell" \
			"$service_user"
		return
	fi

	fail "system user management is not supported on this host"
}

install_systemd_service() {
	mode="$1"
	config_path="$2"
	service_name="loreva-agent"
	service_user="loreva-agent"
	state_dir="/var/lib/loreva-agent"
	unit_path="/etc/systemd/system/${service_name}.service"

	if [ -e "$unit_path" ] && ! grep -q '^# Managed by the Loreva Agent installer$' "$unit_path"; then
		fail "refusing to overwrite unmanaged service unit: $unit_path"
	fi

	ensure_service_user "$service_user" "$state_dir"
	service_group="$(id -gn "$service_user")"
	install -d -m 0750 -o "$service_user" -g "$service_group" "$state_dir"

	unit_tmp="${unit_path}.tmp.$$"
	(
		trap 'rm -f "$unit_tmp"' EXIT HUP INT TERM

		cat >"$unit_tmp" <<EOF
# Managed by the Loreva Agent installer
[Unit]
Description=Loreva node agent
After=network-online.target
Wants=network-online.target
ConditionPathExists=|${state_dir}/identity.json
ConditionPathExists=|${state_dir}/node.json
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=${service_user}
Group=${service_group}
ExecStart=${install_path} run --state-dir ${state_dir}
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
StateDirectory=loreva-agent
StateDirectoryMode=0750
ReadWritePaths=${state_dir}
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectClock=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

		chmod 0644 "$unit_tmp"
		mv -f "$unit_tmp" "$unit_path"
		trap - EXIT HUP INT TERM
	)

	systemctl daemon-reload
	systemctl enable "$service_name" >/dev/null

	if [ "$mode" = "portal" ] && [ ! -e "${state_dir}/identity.json" ]; then
		enroll_and_start_service \
			"$service_name" \
			"$service_user" \
			"$state_dir" \
			"$config_path"
		return
	fi

	if [ "$mode" = "standalone" ] && [ ! -e "${state_dir}/node.json" ] && [ ! -e "${state_dir}/identity.json" ]; then
		init_and_start_service \
			"$service_name" \
			"$service_user" \
			"$state_dir"
		return
	fi

	# Upgrade: keep the existing setup and never add a mode on its own.
	systemctl restart "$service_name"
	printf 'Loreva Agent installed and restarted.\n'
	if [ -e "${state_dir}/node.json" ]; then
		printf 'Run "sudo loreva-agent invite" to connect a device.\n'
	fi
}

init_and_start_service() {
	service_name="$1"
	service_user="$2"
	state_dir="$3"

	require_command runuser

	runuser -u "$service_user" -- \
		"$install_path" init --state-dir "$state_dir"

	systemctl start "$service_name"

	attempts=0
	while [ ! -S "${state_dir}/control.sock" ]; do
		attempts=$((attempts + 1))
		if [ "$attempts" -gt 15 ]; then
			printf 'Loreva Agent installed, but the service did not become ready. Check: journalctl -u %s\n' "$service_name" >&2
			return
		fi
		sleep 1
	done

	printf 'Loreva Agent installed and started.\n\n'

	# The installer may be piped into sh, so ask on the terminal directly.
	if (exec </dev/tty) 2>/dev/null; then
		"$install_path" invite --state-dir "$state_dir" </dev/tty || true
	else
		printf 'Run "sudo loreva-agent invite" to connect a device.\n'
	fi
}

enroll_and_start_service() {
	service_name="$1"
	service_user="$2"
	state_dir="$3"
	config_path="$4"

	require_command runuser

	if [ -n "$config_path" ]; then
		runuser -u "$service_user" -- \
			"$install_path" enroll --config - --state-dir "$state_dir" <"$config_path"
	elif [ -t 0 ]; then
		runuser -u "$service_user" -- \
			"$install_path" configure --state-dir "$state_dir"
	else
		runuser -u "$service_user" -- \
			"$install_path" configure --bootstrap - --state-dir "$state_dir"
	fi

	systemctl restart "$service_name"
	printf 'Loreva Agent installed, enrolled, and started.\n'
}

[ "$(id -u)" -eq 0 ] || fail "run this installer as root"
[ "$(uname -s)" = "Linux" ] || fail "this installer currently supports Linux only"

require_command awk
require_command curl
require_command install
require_command sha256sum
require_command uname

architecture="$(resolve_architecture)"
asset_name="loreva-agent-linux-${architecture}"

download_base_url="${download_base_url%/}"

case "$download_base_url" in
	https://*) ;;
	*) fail "download base URL must use HTTPS" ;;
esac

case "${download_base_url#https://}" in
	"" | *@* | *\?* | *\#*)
		fail "download base URL must not contain credentials, query, or fragment"
		;;
esac

case "$install_path" in
	/*) ;;
	*) fail "install path must be absolute" ;;
esac

case "$install_path" in
	*[!A-Za-z0-9_./-]* | *//* | */./* | */../* | */. | */.. | */)
		fail "install path contains unsupported characters"
		;;
esac

[ "${install_path##*/}" = "loreva-agent" ] || fail "install path must end with loreva-agent"
[ ! -L "$install_path" ] || fail "install path must not be a symbolic link"

install_dir="${install_path%/*}"
[ -d "$install_dir" ] || fail "install directory does not exist: $install_dir"

temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

download "${download_base_url}/${asset_name}" "${temporary_dir}/${asset_name}"
download "${download_base_url}/checksums.txt" "${temporary_dir}/checksums.txt"
verify_download "$asset_name" "${temporary_dir}/${asset_name}" "${temporary_dir}/checksums.txt"

install -m 0755 -- "${temporary_dir}/${asset_name}" "$install_path"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	install_systemd_service "$mode" "$config_path"
else
	printf 'Loreva Agent installed at %s. No supported service manager was detected.\n' "$install_path"
fi
