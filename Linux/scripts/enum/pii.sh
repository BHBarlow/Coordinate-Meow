#!/bin/sh
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# pii.sh - look for PII (phone numbers, emails, SSNs, card numbers and office
# documents) in home dirs, the web root, FTP roots, Samba shares and,
# optionally, MySQL/MariaDB. Read-only.
#
# Settings (environment variables, so they work with coordinate -E):
#   PII_PATH     extra directory to search (locally you can also pass it as $1)
#   PII_DB_USER  MySQL user for the database check (skipped when unset)
#   PII_DB_PASS  that user's password - written to a private temp file for the
#                mysql client, never put on the command line
#   PII_MAX      max lines printed per check per location (default 200, 0 = no limit)

find_path=${PII_PATH:-$1}
PII_MAX=${PII_MAX:-200}
case $PII_MAX in ''|*[!0-9]*) PII_MAX=200 ;; esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pii.XXXXXX") || { echo "mktemp failed"; exit 1; }
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' INT TERM

PHONE_RE='(\([0-9]{3}\) |[0-9]{3}-)[0-9]{3}-[0-9]{4}'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
SSN_RE='[0-9]{3}-[0-9]{2}-[0-9]{4}'
CARD_RE='([0-9]{4}[- ]?){3}[0-9]{4}'

# -I skips binary files; not every grep (e.g. some BusyBox builds) has it
GREP_OPTS="-rEo"
if echo x | grep -I x >/dev/null 2>&1; then GREP_OPTS="-rEoI"; fi

# cap  -> pass at most PII_MAX lines through (keeps output under coordinate's 1 MiB limit)
cap() {
    if [ "$PII_MAX" -eq 0 ]; then
        cat
    else
        awk -v max="$PII_MAX" 'NR <= max {print}
            NR == max + 1 {print "    ... capped at " max " lines (set PII_MAX=0 to see all)"}'
    fi
}

# pii_check <title> <regex> <file-or-dir> [label]
pii_check() {
    echo "  [*] $1"
    # shellcheck disable=SC2086
    grep $GREP_OPTS -- "$2" "$3" 2>/dev/null | grep -iv 'mozilla' |
        awk -v l="$4" '{ if (l != "") print l ": " $0; else print }' | cap
}

scan_text() {   # scan_text <file-or-dir> [label]
    pii_check "Phone numbers"        "$PHONE_RE" "$1" "$2"
    pii_check "Email addresses"      "$EMAIL_RE" "$1" "$2"
    pii_check "Social security nums" "$SSN_RE"   "$1" "$2"
    pii_check "Credit card numbers"  "$CARD_RE"  "$1" "$2"
}

find_interesting_files_by_extension() {
    echo "  [*] Documents / spreadsheets / text files"
    find "$1" -type f \( -iname '*.doc' -o -iname '*.docx' -o -iname '*.docm' -o -iname '*.dot' \
        -o -iname '*.dotx' -o -iname '*.dotm' -o -iname '*.wbk' -o -iname '*.rtf' -o -iname '*.txt' \
        -o -iname '*.csv' -o -iname '*.pdf' -o -iname '*.xls' -o -iname '*.xlsx' -o -iname '*.xlsm' \
        -o -iname '*.xlsb' -o -iname '*.xlt' -o -iname '*.xltx' -o -iname '*.xltm' -o -iname '*.xla' \
        -o -iname '*.xlam' -o -iname '*.xll' -o -iname '*.ppt' -o -iname '*.pptx' -o -iname '*.pptm' \
        -o -iname '*.pot' -o -iname '*.potx' -o -iname '*.potm' -o -iname '*.pps' -o -iname '*.ppsx' \
        -o -iname '*.ppsm' -o -iname '*.ppam' -o -iname '*.odt' -o -iname '*.ods' -o -iname '*.odp' \
        -o -iname '*.odg' -o -iname '*.odf' -o -iname '*.odc' -o -iname '*.odb' -o -iname '*.odm' \) \
        2>/dev/null | cap
}

search() {   # search <dir>
    if [ -z "$1" ]; then return 0; fi
    if [ ! -e "$1" ]; then
        echo "[-] $1 does not exist, skipping"
        return 0
    fi
    scan_text "$1"
    find_interesting_files_by_extension "$1"
}

if [ -n "$find_path" ]; then
    echo "[+] Searching $find_path for PII."
    search "$find_path"
fi

echo "[+] Searching /home for PII."
search /home

echo "[+] Searching /var/www/html for PII."
search /var/www/html

# ---------------------------------------------------------------- FTP roots
# vsftpd uses key=value lines, e.g. anon_root=/srv/ftp
vsftpd_value() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$2" | tail -n 1 | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//'
}
check_vsftpd_config() {
    [ -f "$1" ] || return 0
    echo "[+] VSFTPD config file found at $1. Checking for anon_root and local_root directories."
    for key in anon_root local_root; do
        dir=$(vsftpd_value "$key" "$1")
        if [ -n "$dir" ]; then
            echo "[+] $key=$dir found. Checking for PII."
            search "$dir"
        fi
    done
}
check_vsftpd_config /etc/vsftpd.conf
check_vsftpd_config /etc/vsftpd/vsftpd.conf
check_vsftpd_config /usr/local/etc/vsftpd.conf
check_vsftpd_config /usr/local/vsftpd/vsftpd.conf

# proftpd: "DefaultRoot <dir> [group]" ("~" means each user's home, already covered by /home)
if [ -f /etc/proftpd/proftpd.conf ]; then
    echo "[+] ProFTPD config file found. Checking DefaultRoot."
    grep -E '^[[:space:]]*DefaultRoot[[:space:]]' /etc/proftpd/proftpd.conf | awk '{print $2}' > "$WORK/proftpd_roots"
    while IFS= read -r dir; do
        case $dir in "~"|"~/"*) echo "[+] DefaultRoot $dir is the user's home (covered by /home)"; continue ;; esac
        echo "[+] DefaultRoot $dir found. Checking for PII."
        search "$dir"
    done < "$WORK/proftpd_roots"
fi

# ---------------------------------------------------------------- Samba shares
# "path = /srv/my share" - keep spaces in the path
if [ -f /etc/samba/smb.conf ]; then
    echo "[+] Samba config file found. Checking for shares."
    grep -E '^[[:space:]]*path[[:space:]]*=' /etc/samba/smb.conf |
        sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//; s/"//g' > "$WORK/smb_paths"
    while IFS= read -r share; do
        [ -n "$share" ] || continue
        echo "[+] Checking $share for PII."
        search "$share"
    done < "$WORK/smb_paths"
fi

# ---------------------------------------------------------------- MySQL / MariaDB
if [ -n "$PII_DB_USER" ]; then
    # newer MariaDB (Debian 13, RHEL 10) may ship only the "mariadb" client name
    MYSQL_BIN=$(command -v mariadb 2>/dev/null || command -v mysql 2>/dev/null)
    if [ -z "$MYSQL_BIN" ]; then
        echo "[-] PII_DB_USER is set but no mysql/mariadb client is installed, skipping database check"
    else
        echo "[+] Checking MySQL databases for PII."
        # credentials go in an owner-only option file, not on the command line (visible in ps)
        cnf=$WORK/client.cnf
        esc_user=$(printf '%s' "$PII_DB_USER" | sed 's/\\/\\\\/g; s/"/\\"/g')
        esc_pass=$(printf '%s' "$PII_DB_PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')
        (umask 077; printf '[client]\nuser="%s"\npassword="%s"\n' "$esc_user" "$esc_pass" > "$cnf")
        # --defaults-extra-file must be the FIRST option or the client rejects it
        q() { "$MYSQL_BIN" --defaults-extra-file="$cnf" -N -B -e "$1" 2>/dev/null; }

        if ! q 'SELECT 1;' >/dev/null; then
            echo "[-] Could not log in to MySQL as $PII_DB_USER, skipping database check"
        else
            q 'SHOW DATABASES;' > "$WORK/dbs"
            while IFS= read -r db; do
                case $db in information_schema|performance_schema|mysql|sys|test) continue ;; esac
                echo "[+] Checking database $db for PII."
                q "SHOW TABLES FROM \`$db\`;" > "$WORK/tables"
                while IFS= read -r table; do
                    q "SELECT * FROM \`$db\`.\`$table\`;" > "$WORK/dump"
                    [ -s "$WORK/dump" ] && scan_text "$WORK/dump" "$db.$table"
                done < "$WORK/tables"
            done < "$WORK/dbs"
        fi
    fi
fi
exit 0
