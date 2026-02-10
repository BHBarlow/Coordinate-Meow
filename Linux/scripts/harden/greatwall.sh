#!/bin/sh
# ============================================================================
#  greatwall.sh  —  "Drop Curtain"
#  One-shot cleanup: stop services, kill processes, delete malware, purge
#  persistence. Fill in the arrays on competition day, then run as root.
# ============================================================================

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { printf "${GREEN}[+]${NC} %s\n" "$1"; }
log_warn()  { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
log_error() { printf "${RED}[-]${NC} %s\n" "$1"; }
log_step()  { printf "\n${CYAN}=== %s ===${NC}\n" "$1"; }

# ── Root check ──────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    log_error "Run as root."
    exit 1
fi

# ============================================================================
#  FILL THESE IN ON COMPETITION DAY
# ============================================================================

# Malicious systemd services (unit name WITHOUT .service)
SERVICES=(
    # "cryptominer"
    # "backdoor-listener"
    # "evilsvc"
)

# Malicious binaries / files to delete
BINARIES=(
    # "/usr/local/bin/ncat"
    # "/tmp/.hidden/miner"
    # "/var/tmp/payload"
)

# Suspicious process names to kill (matched with pgrep)
PROCESSES=(
    # "xmrig"
    # "kworkerds"
    # "kdevtmpfsi"
)

# Rogue cron files to remove (full path)
CRONJOBS=(
    # "/etc/cron.d/evilcron"
    # "/var/spool/cron/crontabs/www-data"
)

# Users whose shells should be set to nologin  (NOT root or your user)
LOCK_USERS=(
    # "nobody"
    # "www-data"
)

# ============================================================================
#  1.  STOP  &  REMOVE  SERVICES
# ============================================================================
drop_services() {
    log_step "Stopping & removing malicious services"

    if [ ${#SERVICES[@]} -eq 0 ]; then
        log_warn "No services listed — skipping."
        return
    fi

    for SVC in "${SERVICES[@]}"; do
        log_info "Stopping: $SVC"
        systemctl stop    "$SVC"   2>/dev/null
        systemctl disable "$SVC"   2>/dev/null
        systemctl mask    "$SVC"   2>/dev/null   # prevent restart

        # Remove unit files wherever they might live
        for UNIT_DIR in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system; do
            if [ -f "$UNIT_DIR/${SVC}.service" ]; then
                rm -f "$UNIT_DIR/${SVC}.service"
                log_info "Deleted unit file: $UNIT_DIR/${SVC}.service"
            fi
            # Also check for timer units (some malware uses timers)
            if [ -f "$UNIT_DIR/${SVC}.timer" ]; then
                rm -f "$UNIT_DIR/${SVC}.timer"
                log_info "Deleted timer file: $UNIT_DIR/${SVC}.timer"
            fi
        done
    done

    systemctl daemon-reload
    systemctl reset-failed
    log_info "systemd reloaded."
}

# ============================================================================
#  2.  KILL  SUSPICIOUS  PROCESSES
# ============================================================================
drop_processes() {
    log_step "Killing suspicious processes"

    if [ ${#PROCESSES[@]} -eq 0 ]; then
        log_warn "No processes listed — skipping."
        return
    fi

    for PROC in "${PROCESSES[@]}"; do
        PIDS=$(pgrep -x "$PROC" 2>/dev/null)
        if [ -n "$PIDS" ]; then
            log_info "Killing $PROC (PIDs: $PIDS)"
            pkill -9 -x "$PROC" 2>/dev/null
        else
            log_warn "Process not found: $PROC"
        fi
    done
}

# ============================================================================
#  3.  DELETE  MALICIOUS  BINARIES / FILES
# ============================================================================
drop_binaries() {
    log_step "Deleting malicious binaries & files"

    if [ ${#BINARIES[@]} -eq 0 ]; then
        log_warn "No binaries listed — skipping."
        return
    fi

    for BIN in "${BINARIES[@]}"; do
        if [ -e "$BIN" ]; then
            # Remove immutable bit if set (common malware trick)
            chattr -i "$BIN" 2>/dev/null
            rm -rf "$BIN"
            log_info "Deleted: $BIN"
        else
            log_warn "Not found: $BIN"
        fi
    done
}

# ============================================================================
#  4.  PURGE  ROGUE  CRON  JOBS
# ============================================================================
drop_crons() {
    log_step "Purging rogue cron jobs"

    if [ ${#CRONJOBS[@]} -eq 0 ]; then
        log_warn "No cron files listed — skipping."
        return
    fi

    for CRON in "${CRONJOBS[@]}"; do
        if [ -f "$CRON" ]; then
            chattr -i "$CRON" 2>/dev/null
            rm -f "$CRON"
            log_info "Removed cron file: $CRON"
        else
            log_warn "Cron file not found: $CRON"
        fi
    done
}

# ============================================================================
#  5.  LOCK  USER  SHELLS
# ============================================================================
drop_shells() {
    log_step "Locking user shells"

    if [ ${#LOCK_USERS[@]} -eq 0 ]; then
        log_warn "No users listed — skipping."
        return
    fi

    NOLOGIN=$(command -v nologin 2>/dev/null || echo "/usr/sbin/nologin")

    for USR in "${LOCK_USERS[@]}"; do
        if id "$USR" >/dev/null 2>&1; then
            usermod -s "$NOLOGIN" "$USR"
            log_info "Shell locked: $USR -> $NOLOGIN"
        else
            log_warn "User not found: $USR"
        fi
    done
}

# ============================================================================
#  6.  SWEEP  COMMON  PERSISTENCE  PATHS
# ============================================================================
drop_persistence() {
    log_step "Sweeping common persistence locations"

    # ── Authorized keys (red team backdoor) ──
    log_info "Clearing all authorized_keys files..."
    find / -name "authorized_keys" -type f 2>/dev/null | while read -r KEYFILE; do
        log_info "  Emptied: $KEYFILE"
        : > "$KEYFILE"
    done

    # ── /etc/ld.so.preload (LD_PRELOAD rootkit) ──
    if [ -s /etc/ld.so.preload ]; then
        log_warn "Non-empty /etc/ld.so.preload detected — clearing."
        : > /etc/ld.so.preload
    fi

    # ── World-writable SUID binaries (shouldn't exist) ──
    log_info "Checking for world-writable SUID binaries..."
    find / -perm -4002 -type f 2>/dev/null | while read -r SUID; do
        log_warn "  Suspicious SUID: $SUID"
        chmod o-w "$SUID"
        log_info "  Removed world-write on: $SUID"
    done

    # ── /tmp & /var/tmp & /dev/shm cleanup tip ──
    log_info "Listing executables in /tmp, /var/tmp, /dev/shm:"
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | while read -r F; do
        log_warn "  Executable found: $F  (review manually or add to BINARIES)"
    done
}

# ============================================================================
#  MAIN
# ============================================================================
main() {
    log_step "GREAT WALL — DROP CURTAIN"
    log_info "Starting full sweep at $(date)"

    drop_services
    drop_processes
    drop_binaries
    drop_crons
    drop_shells
    drop_persistence

    log_step "SWEEP COMPLETE"
    log_info "Finished at $(date)"
    log_warn "Review output above for any warnings."
    log_warn "Remember to re-run 'crontab -l' and 'systemctl list-units' to verify."
}

main
