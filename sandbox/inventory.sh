#!/bin/sh
# Generate a candidate command list from installed direct Kali tool metapackage
# dependencies. Run inside the built image, then verify with `shadow tools audit`.
set -eu

apt-cache depends kali-linux-headless kali-tools-web kali-tools-reverse-engineering |
    awk '$1 == "Depends:" && $2 !~ /^</ { print $2 }' |
    sort -u |
    while IFS= read -r package; do
        case "$package" in
            kali-*|apache2|default-mysql-server|php|php-mysql) continue ;;
        esac
        dpkg-query -L "$package" 2>/dev/null || true
    done |
    while IFS= read -r path; do
        case "$path" in
            /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*)
                if [ -f "$path" ] && [ -x "$path" ]; then
                    name=${path##*/}
                    case "$name" in
                        *[!A-Za-z0-9._+-]*|'') ;;
                        *) printf '%s\n' "$name" ;;
                    esac
                fi
                ;;
        esac
    done |
    sort -u
