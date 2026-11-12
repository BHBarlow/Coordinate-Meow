#!/bin/sh
#############################################
# SUID Removal Script
# Removes SUID/SGID bits from GTFOBins-style binaries that should never have
# them, then reports any other SUID/SGID files and file capabilities.
# Must be run with root privileges. POSIX sh (Linux + BSD).
#
# Env vars (coordinate -E):
#   SUID_BINARIES="find,vim,..."  override the default list below
#   SUID_REPORT=0                 skip the SUID/SGID + capabilities report
#############################################

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

say() { printf "$1%s${NC} %s\n" "$2" "$3"; }

if [ "$(id -u)" -ne 0 ]; then
    say "$RED" "[ERROR]" "This script must be run as root (use sudo)"
    exit 1
fi

say "$GREEN" "[INFO]" "Starting SUID removal process..."
echo ""

# None of these are SUID on a stock install; a SUID bit on any = root shell.
# Do NOT add sudo, su, passwd, mount, ping, pkexec, etc. - those are legit.
DEFAULT_BINARIES="find vim vim.basic vim.tiny vi nano less more python python2 python3 \
perl ruby php lua node awk gawk mawk nawk bash sh dash zsh ksh csh tcsh env nmap \
cp mv tar zip unzip gdb socat nc ncat netcat tee xxd base64 dd wget curl sed ed \
rsync git make strace screen tmux expect"

BINARIES=$(printf '%s' "${SUID_BINARIES:-$DEFAULT_BINARIES}" | tr ',' ' ')

BIN_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"

# Fix every copy of the binary, not just the first one in PATH
remove_suid() {
    name="$1"
    found=""
    for d in $BIN_DIRS; do
        for path in "$d/$name" "$d/$name"[0-9]*; do
            [ -e "$path" ] || continue
            # chmod and -u/-g follow symlinks; report the real target
            real=$(readlink -f "$path" 2>/dev/null || echo "$path")
            case " $found " in *" $real "*) continue ;; esac
            found="$found $real"

            if [ -u "$real" ] || [ -g "$real" ]; then
                say "$YELLOW" "[ACTION]" "Removing SUID/SGID from: $real"
                chmod u-s,g-s "$real"
                if [ -u "$real" ] || [ -g "$real" ]; then
                    say "$RED" "[ERROR]" "Failed to remove SUID/SGID from $real (immutable?)"
                else
                    say "$GREEN" "[SUCCESS]" "SUID/SGID removed from $real"
                fi
            fi
        done
    done
    [ -n "$found" ] || return 1
    return 0
}

for binary in $BINARIES; do
    remove_suid "$binary"
done
echo ""

if [ "$SUID_REPORT" != "0" ]; then
    say "$GREEN" "[INFO]" "Remaining SUID/SGID files (review anything unfamiliar):"
    find $BIN_DIRS /usr/lib /usr/libexec /usr/local/lib /opt /tmp /var/tmp /dev/shm /home /root \
        -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | sort -u -k9
    echo ""

    if command -v getcap >/dev/null 2>&1; then
        say "$GREEN" "[INFO]" "File capabilities (cap_setuid / cap_dac_* on interpreters = backdoor):"
        getcap -r $BIN_DIRS /usr/lib /usr/local/lib /opt /tmp /home 2>/dev/null
        echo ""
    fi
fi

say "$GREEN" "[COMPLETE]" "SUID removal process finished"
