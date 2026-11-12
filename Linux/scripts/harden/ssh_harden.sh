#!/bin/sh
# SSH Hardening Script
# @d_tranman/Nigel Gerald/Nigerald
# Compatible with: RHEL, Debian, Ubuntu, BSD (FreeBSD, OpenBSD), Alpine Linux
#
# NOTE: this deliberately keeps root password login ON and turns pubkey auth
# OFF (keys are a red-team persistence vector; we rotate passwords instead).
# If you run coordinate with -k (keys), switch to passwords before running this.
#
# How it works:
#   - sshd uses the FIRST value it sees for an option, and Debian/Ubuntu/RHEL9
#     `Include /etc/ssh/sshd_config.d/*.conf` at the TOP of sshd_config. So we
#     comment the managed options out of the main file AND every drop-in.
#   - Our block is inserted BEFORE the first `Match` line; anything after a
#     Match only applies to that match.
#   - Config is validated with `sshd -t`; on failure everything is restored.

# Color codes (only when on a terminal; coordinate output is not a TTY)
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

log_info()  { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
log_warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }

BEGIN_MARK="# BEGIN COORD SSH HARDEN"
END_MARK="# END COORD SSH HARDEN"

# Settings we enforce. "Option value" per line.
SETTINGS="AllowTcpForwarding no
X11Forwarding no
PermitRootLogin yes
PermitEmptyPasswords no
PubkeyAuthentication no
AuthorizedKeysFile none
PasswordAuthentication yes
PermitUserEnvironment no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no"

# Options to comment out everywhere (persistence vectors) without replacement
STRIP_ONLY="AuthorizedKeysCommand AuthorizedKeysCommandUser"

# Detect OS type
detect_os() {
    case "$(uname -s)" in
        FreeBSD) OS="freebsd"; OS_FAMILY="bsd" ;;
        OpenBSD) OS="openbsd"; OS_FAMILY="bsd" ;;
        NetBSD)  OS="netbsd";  OS_FAMILY="bsd" ;;
        *)
            if [ -f /etc/os-release ]; then
                OS=$(. /etc/os-release; echo "$ID")
                OS_FAMILY=$(. /etc/os-release; echo "${ID_LIKE:-$ID}")
            elif [ -f /etc/redhat-release ]; then
                OS="rhel"; OS_FAMILY="rhel fedora"
            else
                OS="unknown"; OS_FAMILY="unknown"
            fi
            ;;
    esac
    log_info "Detected OS: $OS (Family: $OS_FAMILY)"
}

# Find SSH config file and drop-in dir
find_ssh_config() {
    if [ -f /etc/ssh/sshd_config ]; then
        SSHD_CONFIG="/etc/ssh/sshd_config"
    elif [ -f /usr/local/etc/ssh/sshd_config ]; then
        SSHD_CONFIG="/usr/local/etc/ssh/sshd_config"
    else
        log_error "Could not find sshd_config file"
        exit 1
    fi
    DROPIN_DIR="$(dirname "$SSHD_CONFIG")/sshd_config.d"
    log_info "Using SSH config: $SSHD_CONFIG"
    [ -d "$DROPIN_DIR" ] && log_info "Drop-in dir: $DROPIN_DIR"
}

find_sshd() {
    SSHD_BIN=$(command -v sshd 2>/dev/null)
    for c in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
        [ -n "$SSHD_BIN" ] && break
        [ -x "$c" ] && SSHD_BIN=$c
    done
}

# Backup main config + drop-ins
backup_config() {
    BACKUP_DIR="${BCK:-/root/.cache}/ssh_backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR" || { log_error "Cannot create $BACKUP_DIR"; exit 1; }
    cp -p "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config" || { log_error "Backup failed"; exit 1; }
    if [ -d "$DROPIN_DIR" ]; then
        cp -Rp "$DROPIN_DIR" "$BACKUP_DIR/sshd_config.d"
    fi
    log_info "Backup created: $BACKUP_DIR"
}

restore_config() {
    cat "$BACKUP_DIR/sshd_config" > "$SSHD_CONFIG"
    if [ -d "$BACKUP_DIR/sshd_config.d" ]; then
        for f in "$BACKUP_DIR"/sshd_config.d/*; do
            [ -f "$f" ] && cat "$f" > "$DROPIN_DIR/$(basename "$f")"
        done
    fi
}

# Rewrite a file in place (keeps owner/perms/inode). Usage: rewrite FILE AWKPROG
rewrite() {
    _f=$1; shift
    _tmp="$_f.coordtmp.$$"
    if awk "$@" "$_f" > "$_tmp"; then
        cat "$_tmp" > "$_f"
    fi
    rm -f "$_tmp"
}

# Comment out every managed option (case-insensitive, handles `Opt=val`)
comment_out_options() {
    _file=$1
    OPTS_LC=$(printf '%s\n%s\n' "$SETTINGS" "$(echo "$STRIP_ONLY" | tr ' ' '\n')" \
        | awk '{print tolower($1)}' | tr '\n' ' ')
    export OPTS_LC BEGIN_MARK END_MARK   # read via ENVIRON in awk
    rewrite "$_file" '
        BEGIN { n = split(ENVIRON["OPTS_LC"], a, " "); for (i = 1; i <= n; i++) o[a[i]] = 1 }
        # drop any block from a previous run
        $0 == ENVIRON["BEGIN_MARK"] { skip = 1; next }
        $0 == ENVIRON["END_MARK"]   { skip = 0; next }
        skip { next }
        {
            line = $0; sub(/^[ \t]+/, "", line)
            split(line, f, /[ \t=]+/)
            if (tolower(f[1]) in o) print "#COORD# " $0; else print
        }'
}

insert_block() {
    BLOCK=$(printf '%s\n%s\n%s' "$BEGIN_MARK" "$SETTINGS" "$END_MARK")
    export BLOCK
    rewrite "$SSHD_CONFIG" '
        !done && tolower($1) == "match" { print ENVIRON["BLOCK"]; done = 1 }
        { print }
        END { if (!done) print ENVIRON["BLOCK"] }'
}

apply_hardening() {
    log_info "Applying SSH hardening configurations..."

    comment_out_options "$SSHD_CONFIG"
    if [ -d "$DROPIN_DIR" ]; then
        for f in "$DROPIN_DIR"/*; do
            [ -f "$f" ] || continue
            comment_out_options "$f"
            log_info "Neutralized managed options in drop-in: $f"
        done
    fi
    insert_block

    printf '%s\n' "$SETTINGS" | while read -r k v; do
        log_info "Set $k to $v"
    done

    if grep -iq '^[[:space:]]*ForceCommand' "$SSHD_CONFIG" "$DROPIN_DIR"/* 2>/dev/null; then
        log_warn "ForceCommand present — review it (could be legit internal-sftp or a backdoor):"
        grep -in '^[[:space:]]*ForceCommand' "$SSHD_CONFIG" "$DROPIN_DIR"/* 2>/dev/null
    fi
}

validate_config() {
    log_info "Validating SSH configuration..."

    if [ -z "$SSHD_BIN" ]; then
        log_warn "Could not find sshd binary to validate config"
        return 0
    fi

    # Debian/Ubuntu: sshd -t fails if the privsep dir is missing (socket-activated ssh)
    [ "$OS_FAMILY" != "bsd" ] && [ -d /run ] && mkdir -p /run/sshd 2>/dev/null

    if "$SSHD_BIN" -t -f "$SSHD_CONFIG"; then
        log_info "Configuration validation successful"
        if "$SSHD_BIN" -T -C user=root,host=localhost,addr=127.0.0.1 >/dev/null 2>&1; then
            log_info "Effective settings:"
            "$SSHD_BIN" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | \
                grep -iE '^(permitrootlogin|pubkeyauthentication|passwordauthentication|authorizedkeysfile|authorizedkeyscommand|allowtcpforwarding|x11forwarding|permitemptypasswords) '
        fi
        return 0
    fi

    log_error "Configuration validation failed!"
    log_error "Restoring from backup..."
    restore_config
    exit 1
}

restart_ssh() {
    log_info "Restarting SSH service (existing sessions survive)..."

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            log_info "SSH service restarted via systemctl"
            return 0
        fi
    fi

    if command -v rcctl >/dev/null 2>&1 && rcctl restart sshd; then
        log_info "SSH service restarted via rcctl"
        return 0
    fi

    if command -v rc-service >/dev/null 2>&1 && rc-service sshd restart 2>/dev/null; then
        log_info "SSH service restarted via rc-service"
        return 0
    fi

    if command -v service >/dev/null 2>&1; then
        if service sshd restart 2>/dev/null || service ssh restart 2>/dev/null; then
            log_info "SSH service restarted via service"
            return 0
        fi
    fi

    for RC_PATH in /etc/rc.d/sshd /etc/rc.d/rc.sshd /usr/local/etc/rc.d/sshd /etc/init.d/sshd /etc/init.d/ssh; do
        if [ -x "$RC_PATH" ] && "$RC_PATH" restart; then
            log_info "SSH service restarted via $RC_PATH"
            return 0
        fi
    done

    # Last resort: HUP the listener (re-reads config) via its pidfile
    for PIDF in /var/run/sshd.pid /run/sshd.pid; do
        if [ -f "$PIDF" ] && kill -HUP "$(cat "$PIDF")" 2>/dev/null; then
            log_info "Sent HUP to sshd (pidfile $PIDF)"
            return 0
        fi
    done

    log_error "Could not restart SSH service. Please restart manually."
    return 1
}

main() {
    log_info "Starting SSH hardening script..."

    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi

    detect_os
    find_ssh_config
    find_sshd
    backup_config
    apply_hardening
    validate_config
    restart_ssh || exit 1

    log_info "SSH hardening completed successfully!"
    log_info "Backup saved to: $BACKUP_DIR"
}

main
