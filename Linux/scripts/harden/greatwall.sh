#!/bin/sh
# ============================================================================
#  greatwall.sh  —  "Drop Curtain"
#  One-shot cleanup: stop services, purge cron, kill processes, delete malware,
#  lock users. Fill in the lists on competition day, then run as root.
#
#  POSIX sh (works on Debian dash, RHEL, Alpine, FreeBSD/OpenBSD sh).
#  Lists are whitespace/comma separated. Edit the defaults below, or override
#  them from coordinate with -E, e.g.:
#    coordinate -t HOSTS -u root -p PASS -E GW_SERVICES=evilsvc,miner \
#      -E GW_PROCESSES=xmrig Linux/scripts/harden/greatwall.sh
# ============================================================================

# ── Colors (only on a terminal; coordinate output is not a TTY) ─────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

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
#  FILL THESE IN ON COMPETITION DAY  (or pass GW_* with -E)
# ============================================================================

# Malicious services (unit/rc name WITHOUT .service)
SERVICES="${GW_SERVICES:-
    # cryptominer
    # backdoor-listener
}"

# Malicious binaries / files / directories to delete
BINARIES="${GW_BINARIES:-
    # /usr/local/bin/ncat
    # /tmp/.hidden/miner
}"

# Suspicious process names to kill (exact name; set GW_PKILL_FULL=1 to match
# against the full command line instead)
PROCESSES="${GW_PROCESSES:-
    # xmrig
    # kdevtmpfsi
}"

# Rogue cron files to remove (full path)
CRONJOBS="${GW_CRONJOBS:-
    # /etc/cron.d/evilcron
    # /var/spool/cron/crontabs/www-data
}"

# Users whose shells should be set to nologin and passwords locked
# (NOT root or your own user)
LOCK_USERS="${GW_LOCK_USERS:-
    # www-data
}"

# Strip comment lines and turn commas into spaces -> one word per item.
# (Items can't contain spaces; malware paths with spaces: delete by hand.)
list() {
    printf '%s\n' "$1" | sed -e 's/#.*$//' | tr ',' ' '
}

is_empty() {
    [ -z "$(list "$1" | tr -d ' \t\n')" ]
}

# Clear immutable / append-only flags (common malware trick)
unflag() {
    if command -v chattr >/dev/null 2>&1; then
        chattr -R -i -a "$1" 2>/dev/null
    elif command -v chflags >/dev/null 2>&1; then
        chflags -R noschg,nouchg,nosappnd,nouappnd "$1" 2>/dev/null
    fi
}

# ============================================================================
#  1.  STOP  &  REMOVE  SERVICES
# ============================================================================
drop_services() {
    log_step "Stopping & removing malicious services"

    if is_empty "$SERVICES"; then
        log_warn "No services listed — skipping."
        return
    fi

    for SVC in $(list "$SERVICES"); do
        SVC=${SVC%.service}
        log_info "Stopping: $SVC"

        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            for U in "$SVC.service" "$SVC.timer" "$SVC.socket" "$SVC.path"; do
                systemctl stop    "$U" 2>/dev/null
                systemctl disable "$U" 2>/dev/null
            done

            # Remove unit files (and drop-in dirs) wherever they might live
            for UNIT_DIR in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
                            /run/systemd/system /usr/local/lib/systemd/system; do
                for EXT in service timer socket path; do
                    F="$UNIT_DIR/$SVC.$EXT"
                    if [ -e "$F" ] || [ -L "$F" ]; then
                        unflag "$F"
                        rm -f "$F"
                        log_info "Deleted unit file: $F"
                    fi
                    if [ -d "$F.d" ]; then
                        unflag "$F.d"
                        rm -rf "$F.d"
                        log_info "Deleted drop-in dir: $F.d"
                    fi
                done
            done

            systemctl daemon-reload
            # Mask after removal so the /dev/null symlink isn't deleted above
            systemctl mask "$SVC.service" "$SVC.timer" >/dev/null 2>&1
        elif command -v rc-service >/dev/null 2>&1; then
            # OpenRC (Alpine, Gentoo)
            rc-service "$SVC" stop 2>/dev/null
            rc-update del "$SVC" 2>/dev/null
            if [ -f "/etc/init.d/$SVC" ]; then
                unflag "/etc/init.d/$SVC"; rm -f "/etc/init.d/$SVC"
                log_info "Deleted /etc/init.d/$SVC"
            fi
        else
            # BSD rc / SysV
            service "$SVC" onestop 2>/dev/null || service "$SVC" stop 2>/dev/null
            command -v sysrc >/dev/null 2>&1 && sysrc -x "${SVC}_enable" 2>/dev/null
            command -v rcctl >/dev/null 2>&1 && rcctl disable "$SVC" 2>/dev/null
            for RC in "/etc/rc.d/$SVC" "/usr/local/etc/rc.d/$SVC" "/etc/init.d/$SVC"; do
                if [ -f "$RC" ]; then
                    unflag "$RC"; rm -f "$RC"
                    log_info "Deleted $RC"
                fi
            done
        fi
    done

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl reset-failed 2>/dev/null
        log_info "systemd reloaded."
    fi
}

# ============================================================================
#  2.  PURGE  ROGUE  CRON  JOBS   (before killing, so nothing respawns them)
# ============================================================================
drop_crons() {
    log_step "Purging rogue cron jobs"

    if is_empty "$CRONJOBS"; then
        log_warn "No cron files listed — skipping."
        return
    fi

    for CRON in $(list "$CRONJOBS"); do
        if [ -f "$CRON" ]; then
            unflag "$CRON"
            rm -f "$CRON"
            log_info "Removed cron file: $CRON"
        else
            log_warn "Cron file not found: $CRON"
        fi
    done
}

# ============================================================================
#  3.  KILL  SUSPICIOUS  PROCESSES
# ============================================================================
drop_processes() {
    log_step "Killing suspicious processes"

    if is_empty "$PROCESSES"; then
        log_warn "No processes listed — skipping."
        return
    fi

    # pgrep -x only compares the first 15 chars of the process name on Linux
    if [ -n "$GW_PKILL_FULL" ]; then MATCH="-f"; else MATCH="-x"; fi

    for PROC in $(list "$PROCESSES"); do
        PIDS=$(pgrep $MATCH "$PROC" 2>/dev/null | grep -v "^$$\$" | tr '\n' ' ')
        if [ -n "$PIDS" ]; then
            log_info "Killing $PROC (PIDs: $PIDS)"
            # shellcheck disable=SC2086
            kill -9 $PIDS 2>/dev/null
        else
            log_warn "Process not found: $PROC"
        fi
    done
}

# ============================================================================
#  4.  DELETE  MALICIOUS  BINARIES / FILES
# ============================================================================
drop_binaries() {
    log_step "Deleting malicious binaries & files"

    if is_empty "$BINARIES"; then
        log_warn "No binaries listed — skipping."
        return
    fi

    for BIN in $(list "$BINARIES"); do
        case "$BIN" in
            /|/bin|/sbin|/usr|/usr/bin|/usr/sbin|/etc|/lib|/lib64|/home|/root|/var)
                log_error "Refusing to delete $BIN"; continue ;;
        esac
        if [ -e "$BIN" ] || [ -L "$BIN" ]; then
            unflag "$BIN"
            rm -rf "$BIN"
            if [ -e "$BIN" ]; then
                log_error "Failed to delete: $BIN"
            else
                log_info "Deleted: $BIN"
            fi
        else
            log_warn "Not found: $BIN"
        fi
    done
}

# ============================================================================
#  5.  LOCK  USER  SHELLS
# ============================================================================
drop_shells() {
    log_step "Locking user shells"

    if is_empty "$LOCK_USERS"; then
        log_warn "No users listed — skipping."
        return
    fi

    NOLOGIN=$(command -v nologin 2>/dev/null)
    for c in /usr/sbin/nologin /sbin/nologin /usr/bin/false /bin/false; do
        [ -n "$NOLOGIN" ] && break
        [ -x "$c" ] && NOLOGIN=$c
    done

    for USR in $(list "$LOCK_USERS"); do
        if [ "$USR" = root ]; then
            log_error "Refusing to lock root"; continue
        fi
        if id "$USR" >/dev/null 2>&1; then
            if command -v usermod >/dev/null 2>&1; then
                usermod -s "$NOLOGIN" "$USR" && usermod -L "$USR"
            elif command -v pw >/dev/null 2>&1; then
                # FreeBSD
                pw usermod "$USR" -s "$NOLOGIN" && pw lock "$USR" 2>/dev/null
            elif command -v chsh >/dev/null 2>&1; then
                chsh -s "$NOLOGIN" "$USR"
                command -v passwd >/dev/null 2>&1 && passwd -l "$USR"
            fi
            log_info "Shell locked: $USR -> $NOLOGIN (password locked)"
        else
            log_warn "User not found: $USR"
        fi
    done
}

# ============================================================================
#  MAIN
# ============================================================================
main() {
    log_step "GREAT WALL"
    log_info "Starting full sweep at $(date)"

    drop_services
    drop_crons
    drop_processes
    drop_binaries
    drop_shells

    log_step "SWEEP COMPLETE"
    log_info "Finished at $(date)"
    log_warn "Review output above for any warnings."
    log_warn "Remember to re-run 'crontab -l' and 'systemctl list-units' to verify."
}

main
