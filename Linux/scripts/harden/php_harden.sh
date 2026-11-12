#!/bin/sh
# Thanks UCI
#
# Harden every php.ini found and drop an override into each PHP conf.d scan
# dir (conf.d files load AFTER php.ini, so a planted one could undo php.ini).
# Re-runnable: the managed block is replaced, not appended again.
# Originals are backed up to $BCK/php/ (default /root/.cache/php/).
#
# Env vars (coordinate -E):
#   PHP_STRICT=1     also set file_uploads=off, max_execution_time=30,
#                    session.cookie_secure=1. These can BREAK scored web apps
#                    (uploads, slow pages, logins over plain HTTP) - opt in.
#   PHP_FULL_SCAN=1  search the whole filesystem for php.ini (slow: use -T 300)
#   BCK              backup root

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Must run as root."
    exit 1
fi

BCK="${BCK:-/root/.cache}"
BEGIN_MARK="; BEGIN COORD PHP HARDEN"
END_MARK="; END COORD PHP HARDEN"
OVERRIDE_NAME="zzzz-coord-harden.ini"

SETTINGS="disable_functions = exec,system,shell_exec,passthru,popen,proc_open,pcntl_exec,curl_exec,curl_multi_exec,show_source
html_errors = off
display_errors = off
short_open_tag = off
session.cookie_httponly = 1
session.use_only_cookies = 1
expose_php = off
allow_url_fopen = off
allow_url_include = off"

if [ -n "$PHP_STRICT" ]; then
    SETTINGS="$SETTINGS
file_uploads = off
max_execution_time = 30
session.cookie_secure = 1"
fi

BLOCK=$(printf '%s\n%s\n%s' "$BEGIN_MARK" "$SETTINGS" "$END_MARK")

# ── Find php.ini files ──────────────────────────────────────────────────────
if [ -n "$PHP_FULL_SCAN" ]; then
    INIS=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        -type f -name php.ini -print 2>/dev/null)
else
    INIS=$(find /etc /usr/local/etc /opt /usr/local/lib /usr/local/php* /usr/lib/php* \
        -type f -name php.ini 2>/dev/null)
fi
# Ask each php binary where its ini lives (catches custom builds)
for php in $(command -v php php-cgi 2>/dev/null) /usr/bin/php[0-9]* /opt/remi/*/root/usr/bin/php; do
    [ -x "$php" ] || continue
    f=$("$php" -r 'echo php_ini_loaded_file();' 2>/dev/null)
    [ -n "$f" ] && [ -f "$f" ] && INIS="$INIS
$f"
done
INIS=$(printf '%s\n' "$INIS" | grep -v '^$' | sort -u)

if [ -z "$INIS" ]; then
    echo "[-] No php.ini found (set PHP_FULL_SCAN=1 to search everything)."
    exit 0
fi

backup() {
    dest="$BCK/php$(dirname "$1")"
    mkdir -p "$dest" && [ ! -e "$dest/$(basename "$1")" ] && cp -p "$1" "$dest/"
}

# ── Patch php.ini files ─────────────────────────────────────────────────────
SCANDIRS=""
for file in $INIS; do
    backup "$file"
    # Strip a previous managed block, then append the new one (last value wins)
    tmp="$file.coordtmp.$$"
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip' "$file" > "$tmp" && { cat "$tmp"; printf '\n%s\n' "$BLOCK"; } > "$file"
    rm -f "$tmp"
    echo "[+] $file changed"

    d=$(dirname "$file")
    [ -d "$d/conf.d" ] && SCANDIRS="$SCANDIRS $d/conf.d"
done

# Distro-wide scan dirs (RHEL /etc/php.d, FreeBSD /usr/local/etc/php)
for d in /etc/php.d /usr/local/etc/php /etc/opt/remi/*/php.d; do
    [ -d "$d" ] && SCANDIRS="$SCANDIRS $d"
done

# ── conf.d overrides ────────────────────────────────────────────────────────
for d in $(printf '%s\n' $SCANDIRS | sort -u); do
    printf '%s\n' "$BLOCK" > "$d/$OVERRIDE_NAME"
    echo "[+] Wrote override $d/$OVERRIDE_NAME"
    # Anything sorting after us, or setting these keys elsewhere, is suspicious
    grep -l -iE '^[[:space:]]*(disable_functions|allow_url_include|allow_url_fopen)' "$d"/*.ini 2>/dev/null \
        | grep -v "$OVERRIDE_NAME" | while read -r f; do
            echo "[!] $f also sets hardened directives - review it:"
            grep -n -iE '^[[:space:]]*(disable_functions|allow_url_include|allow_url_fopen)' "$f"
        done
done

# ── Restart only services that are actually running ─────────────────────────
is_running() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl is-active --quiet "$1"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$1" status >/dev/null 2>&1
    elif command -v service >/dev/null 2>&1; then
        service "$1" status >/dev/null 2>&1 || service "$1" onestatus >/dev/null 2>&1
    else
        return 1
    fi
}

restart_svc() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl restart "$1"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$1" restart
    else
        service "$1" restart
    fi && echo "[+] $1 restarted" || echo "[-] $1 restart FAILED - check it now"
}

SVCS="apache2 httpd apache24 nginx lighttpd php-fpm php_fpm php-fpm81 php-fpm82 php-fpm83 php-fpm84"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    # Debian versioned units: php8.2-fpm, etc.
    SVCS="$SVCS $(systemctl list-units --type=service --state=running --no-legend 'php*fpm*' 2>/dev/null \
        | awk '{for (i=1;i<=NF;i++) if ($i ~ /\.service$/) {sub(/\.service$/,"",$i); print $i; break}}')"
fi

for svc in $(printf '%s\n' $SVCS | sort -u); do
    is_running "$svc" && restart_svc "$svc"
done
