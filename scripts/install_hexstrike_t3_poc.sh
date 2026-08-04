#!/bin/sh
set -eu

umask 077

mode=${1:-install}
[ "$mode" = install ] || [ "$mode" = --bootstrap-identity ] || {
    echo "installation=FAIL error_code=usage_invalid" >&2
    exit 2
}

source_dir=${HEXSTRIKE_SOURCE_DIR:-/home/kali/hexstrike-ai}
install_root=/opt/hexstrike-t3-poc
config_dir=/etc/hexstrike
unit_dir=/etc/systemd/system
service_unit=hexstrike-t3-poc.service
agent_unit=hexstrike-t3-ssh-agent.service
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
requirements=$repo_root/config/hexstrike-t3-poc-requirements.txt
protected_runtime=t3-unified-runtime.json
application_files="hexstrike_t3_app.py hexstrike_t3_profile.py hexstrike_t3_execution.py"
app_dir=$install_root/app
venv_dir=$install_root/venv

fail() {
    echo "installation=FAIL error_code=$1" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail root_required
[ -d "$source_dir" ] || fail source_directory_missing
[ -f "$requirements" ] || fail requirements_manifest_missing
command -v python3 >/dev/null 2>&1 || fail python_missing
command -v systemctl >/dev/null 2>&1 || fail systemctl_missing
command -v systemd-analyze >/dev/null 2>&1 || fail systemd_analyze_missing
command -v runuser >/dev/null 2>&1 || fail runuser_missing

if ! getent group hexstrike >/dev/null 2>&1; then
    groupadd --system hexstrike || fail service_group_creation_failed
fi
if ! getent passwd hexstrike >/dev/null 2>&1; then
    useradd --system --gid hexstrike --home-dir /var/lib/hexstrike \
        --shell /usr/sbin/nologin hexstrike || fail service_user_creation_failed
fi
[ "$(id -gn hexstrike)" = hexstrike ] || fail service_identity_group_invalid

if [ "$mode" = --bootstrap-identity ]; then
    echo "installation=PASS phase=service_identity_only service_started=no"
    exit 0
fi

for name in $application_files; do
    [ -f "$source_dir/$name" ] || fail application_source_missing
done

[ -d "$config_dir" ] || fail protected_directory_missing
[ ! -L "$config_dir" ] || fail protected_directory_symlink
chown root:hexstrike "$config_dir" || fail protected_directory_owner_update_failed
chmod 0750 "$config_dir" || fail protected_directory_mode_update_failed
path=$config_dir/$protected_runtime
[ -e "$path" ] || fail protected_configuration_missing
[ -f "$path" ] && [ ! -L "$path" ] || fail protected_configuration_not_regular
chown hexstrike:hexstrike "$path" || fail protected_configuration_owner_update_failed
chmod 0600 "$path" || fail protected_configuration_mode_update_failed

install -d -o root -g root -m 0755 "$install_root" "$app_dir"
for name in $application_files; do
    install -o root -g root -m 0644 "$source_dir/$name" "$app_dir/$name" \
        || fail application_install_failed
done
install -o root -g root -m 0644 "$requirements" "$install_root/requirements.txt" \
    || fail requirements_install_failed

if [ ! -x "$venv_dir/bin/python3" ]; then
    python3 -m venv "$venv_dir" || fail virtual_environment_creation_failed
fi
"$venv_dir/bin/python3" -m pip install --disable-pip-version-check \
    --requirement "$install_root/requirements.txt" || fail dependency_install_failed
chown -R root:root "$install_root" || fail application_owner_update_failed
find "$install_root" -type d -exec chmod 0755 {} + || fail application_directory_mode_failed
find "$install_root" -type f -exec chmod a+r,go-w {} + || fail application_file_mode_failed

"$venv_dir/bin/python3" -m compileall -q "$app_dir" || fail application_compile_failed
"$venv_dir/bin/python3" -c \
    'import flask' \
    >/dev/null 2>&1 || fail required_dependency_missing
runuser -u hexstrike -- test -x "$venv_dir/bin/python3" \
    || fail service_entrypoint_not_executable
runuser -u hexstrike -- test -r "$app_dir/hexstrike_t3_app.py" \
    || fail service_entrypoint_not_readable

metadata=$(stat -c '%U:%G:%a' "$config_dir/$protected_runtime") \
    || fail protected_configuration_stat_failed
[ "$metadata" = hexstrike:hexstrike:600 ] || fail protected_configuration_metadata_invalid
runuser -u hexstrike -- "$venv_dir/bin/python3" -c \
    'import sys; sys.path.insert(0, sys.argv[1]); from hexstrike_t3_execution import load_runtime; load_runtime("/etc/hexstrike/t3-unified-runtime.json")' \
    "$app_dir" \
    >/dev/null 2>&1 || fail protected_configuration_json_invalid
[ "$(stat -c '%U:%G:%a' "$config_dir")" = root:hexstrike:750 ] \
    || fail protected_directory_metadata_invalid
systemd-analyze verify \
    "$repo_root/config/systemd/$agent_unit" \
    "$repo_root/config/systemd/$service_unit" >/dev/null 2>&1 \
    || fail systemd_unit_invalid
install -o root -g root -m 0644 "$repo_root/config/systemd/$agent_unit" \
    "$unit_dir/$agent_unit" || fail agent_unit_install_failed
install -o root -g root -m 0644 "$repo_root/config/systemd/$service_unit" \
    "$unit_dir/$service_unit" || fail service_unit_install_failed
systemctl daemon-reload || fail systemd_daemon_reload_failed
systemd-analyze verify "$unit_dir/$agent_unit" "$unit_dir/$service_unit" \
    >/dev/null 2>&1 || fail installed_systemd_unit_invalid

echo "installation=PASS service_started=no"
