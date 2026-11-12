#!/bin/sh
# KaliPatriot | TTU CCDC | Landon Byrge
# NightWalk3r | Behnjamin Barlow | TTU CCDC
#
# audit.sh - show the most recent auth/system log lines. Read-only.
#
# Settings (environment variables, so they work with coordinate -E):
#   AUDIT_N        lines of each log to show (default 150; old name N still works)
#   AUDIT_SESSION  also show the lines containing this text - a session id, user
#                  name or IP (old name SESSION still works). Only the last
#                  AUDIT_MATCHES matching lines are shown (default 1000).
#
# When none of the classic log files exist (Debian 12+, minimal RHEL with only
# journald) it reads the systemd journal instead.

N=${AUDIT_N:-${N:-150}}
case $N in ''|*[!0-9]*) N=150 ;; esac
SESSION=${AUDIT_SESSION:-$SESSION}
MATCHES=${AUDIT_MATCHES:-1000}
case $MATCHES in ''|*[!0-9]*) MATCHES=1000 ;; esac

show_matches() {
    [ -n "$SESSION" ] || return 0
    echo "---------- lines containing '$SESSION' (last $MATCHES)"
    grep -F -- "$SESSION" | tail -n "$MATCHES"
}

show_log() {
    [ -f "$1" ] || return 1
    echo "=========="
    echo "$1 (last $N lines)"
    tail -n "$N" "$1"
    show_matches < "$1"
    echo "=========="
    return 0
}

found=0
for log in /var/log/secure /var/log/auth.log /var/log/messages; do
    show_log "$log" && found=1
done

if [ "$found" -eq 0 ]; then
    if command -v journalctl >/dev/null 2>&1; then
        echo "=========="
        echo "journal - auth/authpriv (last $N lines)"
        journalctl --no-pager -n "$N" SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 2>/dev/null
        echo "=========="
        echo "journal - everything (last $N lines)"
        journalctl --no-pager -n "$N" 2>/dev/null
        journalctl --no-pager 2>/dev/null | show_matches
        echo "=========="
    else
        echo "No /var/log/secure, auth.log, messages or journalctl found on this host"
    fi
fi
exit 0
