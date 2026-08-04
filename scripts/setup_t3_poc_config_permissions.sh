#!/bin/sh
set -eu

mode=${1:---check}
directory=/etc/hexstrike
files="t3-reachability.json t3-poc-runtime.json job-targets.json t3a-credentials.json t3c-runtime.json"

if [ "$mode" = "--apply" ]; then
    install -d -o root -g hexstrike -m 0750 "$directory"
    for name in $files; do
        if [ -e "$directory/$name" ]; then
            chown root:hexstrike "$directory/$name"
            chmod 0640 "$directory/$name"
        fi
    done
elif [ "$mode" != "--check" ]; then
    echo "usage: setup_t3_poc_config_permissions.sh [--check|--apply]" >&2
    exit 2
fi

test "$(stat -c %U:%G:%a "$directory")" = "root:hexstrike:750" || {
    echo "failed_check=t3_config_directory error_code=directory_metadata_invalid" >&2
    exit 1
}
for name in $files; do
    [ ! -e "$directory/$name" ] ||
        test "$(stat -c %U:%G:%a "$directory/$name")" = "root:hexstrike:640" || {
            echo "failed_check=$name error_code=file_metadata_invalid" >&2
            exit 1
        }
done
echo "t3_poc_configuration_permissions=PASS"
