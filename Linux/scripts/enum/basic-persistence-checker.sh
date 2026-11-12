#!/bin/bash
# NightWalk3r | TTU CCDC | Behnjamin Barlow
#
# basic-persistence-checker.sh - one-pass Linux persistence & rootkit threat hunt
#
# Combines bashrc.sh + cron.sh + ld-lkm.sh + ssh/pam checks and adds:
#   - SSH authorized_keys across every home + odd locations (display only)
#   - PAM backdoors (pam_exec, pam_succeed_if, nullok, deny/permit order, unowned modules)
#   - alias / function / "declare -f" hijacks in shell startup files
#   - immutable & append-only files (chattr +i / +a)
#   - SUID / SGID binaries (+ package checksum verify) and file capabilities
#   - processes running from deleted, memfd (fileless) or temp-dir binaries
#   - brute-force hidden PID and hidden kernel module detection
#
# READ-ONLY: nothing on the box is changed. Fix commands are printed, not run.
#
# ============================================================================
# SECTIONS  (choose with -s a,b,c  or  PC_SECTIONS=a,b,c ; default = all)
# ----------------------------------------------------------------------------
#   procs      processes running from deleted / memfd (fileless) / temp-dir binaries
#   shell      shell rc & profile backdoors: alias/function hijacks, declare -f,
#              PROMPT_COMMAND/BASH_ENV hooks, history evasion, world-writable rc
#   cron       cron (user/system/periodic), at jobs, systemd units & timers,
#              rc.local, init.d, udev RUN+=, update-motd, XDG autostart
#   ssh        authorized_keys in every home + odd disk locations, and the
#              effective sshd config (DISPLAY ONLY - never removes a key)
#   pam        PAM backdoors: pam_exec, pam_succeed_if, nullok, permit-before-deny
#              ordering, PAM modules unowned by a package or with a changed checksum
#   preload    LD_PRELOAD / LD_AUDIT / ld.so.preload rootkits, suspicious library
#              maps, hidden files/PIDs (libc view vs static busybox)
#   kernel     LKM rootkits, kernel taint, hidden/unpackaged modules, modprobe
#              hooks, ftrace/kprobe/eBPF hooks, brute-force hidden-PID probe
#   immutable  immutable / append-only files (chattr +i / +a)
#   suid       SUID/SGID binaries (location, GTFOBins, package checksum) + capabilities
#
#   Each line is tagged [ALERT] (act now) / [WARN] (verify) / [INFO] / [OK].
#   The run ends with a per-section ALERT/WARN table and one PERSIST-SUMMARY line.
# ============================================================================
#
# Usage: sudo ./basic-persistence-checker.sh [-q] [-v] [-n] [-s sections]
#   -q        quiet - hide [INFO]/[OK] lines, show only [WARN] and [ALERT]
#   -v        verbose - show [INFO]/[OK] lines too (default when run in a terminal)
#   -n        no colour (automatic when output is not a terminal)
#   -s list   comma-separated sections from the table above (default: all)
#   -h        help
#
# Same settings as environment variables (for coordinate, which can't pass args):
#   PC_SECTIONS=shell,cron   PC_QUIET=0|1   PC_COLOR=0|1   PC_MAX_LINES=3000
#   When stdout is not a terminal (coordinate, pipes) it defaults to quiet + no colour.
#
# Local:      sudo ./basic-persistence-checker.sh | tee /root/persist-$(hostname).log
# Coordinate: coordinate -t <targets> -u <user> -p <pass> -S -T 600 \
#                 -o '%h%/%s%.txt' Linux/scripts/enum/basic-persistence-checker.sh
#             add -E PC_SECTIONS=procs,shell,cron for a fast pass, -E PC_QUIET=0 for everything
#             grep PERSIST-SUMMARY output/*/* for a one-line-per-host overview

ALL_SECTIONS="shell cron ssh pam preload kernel immutable suid procs"
SECTIONS=${PC_SECTIONS:-$ALL_SECTIONS}
SECTIONS=${SECTIONS//,/ }
if [[ -t 1 ]]; then QUIET=${PC_QUIET:-0}; COLOR=${PC_COLOR:-1}
else                QUIET=${PC_QUIET:-1}; COLOR=${PC_COLOR:-0}; fi
# coordinate fails a host whose output exceeds 1 MiB - stop printing non-ALERT lines past this
MAX_LINES=${PC_MAX_LINES:-3000}
[[ $QUIET =~ ^[01]$ ]] || QUIET=1
[[ $COLOR =~ ^[01]$ ]] || COLOR=0
[[ $MAX_LINES =~ ^[0-9]+$ ]] || MAX_LINES=3000

usage() { awk 'NR>2 && /^#/ {sub(/^# ?/, ""); print; next} NR>2 {exit}' "$0"; exit "${1:-0}"; }

while getopts ":qvns:h" opt; do
    case $opt in
        q) QUIET=1 ;;
        v) QUIET=0 ;;
        n) COLOR=0 ;;
        s) SECTIONS=${OPTARG//,/ } ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done
for s in $SECTIONS; do
    [[ " $ALL_SECTIONS " == *" $s "* ]] || { echo "Unknown section: $s" >&2; usage 1; }
done
want() { [[ " $SECTIONS " == *" $1 "* ]]; }

if ((COLOR)) && [[ -z ${NO_COLOR:-} ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'
    MAGENTA=$'\033[0;35m'; CYAN=$'\033[0;36m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; DIM=""; BOLD=""; NC=""
fi

# ============================================================================
# Output helpers
# ============================================================================
ALERTS=0; WARNS=0; CUR_SEC=init
declare -A SEC_A SEC_W
RAN_SECTIONS=()

# Output budget: ALERTs always print; everything else stops once MAX_LINES is reached.
OUT_LINES=0; CAPPED=0
room() {
    ((MAX_LINES == 0 || OUT_LINES < MAX_LINES)) && { ((OUT_LINES++)); return 0; }
    ((CAPPED)) || { CAPPED=1; printf '[NOTE]  Output limit (%s lines) reached - only ALERT lines from here on. Use PC_SECTIONS to narrow or PC_MAX_LINES=0 to disable.\n' "$MAX_LINES"; }
    return 1
}
alert()  { ((ALERTS++)); ((SEC_A[$CUR_SEC]++)); ((OUT_LINES++)); printf '%s[ALERT]%s %s\n' "$RED$BOLD" "$NC" "$*"; }
warn()   { ((WARNS++));  ((SEC_W[$CUR_SEC]++)); room && printf '%s[WARN]%s  %s\n' "$YELLOW" "$NC" "$*"; return 0; }
info()   { ((QUIET)) || { room && printf '%s[INFO]%s  %s\n' "$CYAN" "$NC" "$*"; }; return 0; }
ok()     { ((QUIET)) || { room && printf '%s[OK]%s    %s\n' "$GREEN" "$NC" "$*"; }; return 0; }
note()   { room && printf '%s[NOTE]%s  %s\n' "$BLUE" "$NC" "$*"; return 0; }
detail() { room && printf '          %s%s%s\n' "$DIM" "$*" "$NC"; return 0; }
# report <0|1|2> msg  -> info / warn / alert
report() { local s=$1; shift; case $s in 2) alert "$@" ;; 1) warn "$@" ;; *) info "$@" ;; esac; }
section() {
    CUR_SEC=$1; SEC_A[$1]=0; SEC_W[$1]=0; RAN_SECTIONS+=("$1")
    printf '\n%s%s======== [%s] %s ========%s\n' "$BOLD" "$MAGENTA" "$1" "$2" "$NC"
}
sub()   { printf '\n%s[*] %s%s\n' "$BLUE$BOLD" "$*" "$NC"; }
trunc() { local s=$1 n=${2:-200}; ((${#s} > n)) && s="${s:0:n}..."; printf '%s' "$s"; }
has()   { command -v "$1" >/dev/null 2>&1; }
fmeta() { stat -L -c '%U:%G %a %y' "$1" 2>/dev/null | cut -d. -f1; }

pid_desc() { local c=""; read -r c 2>/dev/null < "/proc/$1/comm"; printf '%s(%s)' "$1" "${c:-?}"; }
pidlist() {
    local -a a=($1); local out="" i
    for ((i = 0; i < ${#a[@]} && i < 6; i++)); do out+="$(pid_desc "${a[i]}") "; done
    ((${#a[@]} > 6)) && out+="+$((${#a[@]} - 6)) more"
    printf '%s' "$out"
}

# ============================================================================
# Pre-flight
# ============================================================================
if [[ $EUID -ne 0 ]]; then
    echo "${RED}[!] Must be run as root:${NC} sudo $0 $*   (with coordinate: add -S, or log in as root)"
    echo "PERSIST-SUMMARY host=$(hostname) status=NOT-ROOT"
    exit 1
fi

WORKDIR=$(mktemp -d /tmp/persist-check.XXXXXX) || { echo "mktemp failed"; exit 1; }
trap 'rm -rf "$WORKDIR"' EXIT

printf '%s%s==================================================%s\n' "$BOLD" "$CYAN" "$NC"
printf '%s%s  Basic Persistence Checker  -  %s  -  %s%s\n' "$BOLD" "$CYAN" "$(hostname)" "$(date '+%F %T')" "$NC"
printf '%s%s==================================================%s\n' "$BOLD" "$CYAN" "$NC"
note "Sections: $SECTIONS | quiet=$QUIET | read-only - nothing will be modified"

# ---------------------------------------------------------------- BusyBox
# A *static* busybox does not go through libc, so LD_PRELOAD rootkits can't hook it.
BB=""; BB_STATIC=0; BB_INIT=0
init_busybox() {
    ((BB_INIT)) && return; BB_INIT=1
    BB=$(command -v busybox 2>/dev/null) || { BB=""; return; }
    if has ldd && LC_ALL=C ldd "$BB" 2>&1 | grep -qiE 'not a dynamic|statically linked'; then
        BB_STATIC=1
    fi
}

# ---------------------------------------------------------------- package DB
# Builds a list of every file owned by a package (dpkg / rpm / apk) once, so we
# can cheaply ask "was this file installed by a package or dropped by someone?"
PKG_DB=""; PKG_TRIED=0
AWK_NORM='function norm(p) { if (p ~ /^\/usr\/(bin|sbin|lib|lib32|lib64|libx32)\//) return substr(p, 5); return p }'
build_pkg_db() {
    ((PKG_TRIED)) && return; PKG_TRIED=1
    local out=$WORKDIR/pkgfiles
    {
        if compgen -G '/var/lib/dpkg/info/*.list' >/dev/null; then
            cat /var/lib/dpkg/info/*.list
        elif has rpm; then
            rpm -qa --qf '[%{FILENAMES}\n]'
        elif [[ -f /lib/apk/db/installed ]]; then
            awk -F: '/^F:/ {d=$2} /^R:/ {print "/" d "/" $2}' /lib/apk/db/installed
        fi
    } 2>/dev/null | awk "$AWK_NORM"'{print norm($0)}' | sort -u > "$out"
    if [[ -s $out ]]; then PKG_DB=$out
    else note "No package database found - 'not owned by any package' checks are skipped"; fi
}
# stdin: paths -> stdout: those NOT owned by any package
unowned() {
    build_pkg_db
    [[ -z $PKG_DB ]] && { cat >/dev/null; return 1; }
    awk "$AWK_NORM"'NR==FNR {own[$0]=1; next} $0 != "" && !(norm($0) in own)' "$PKG_DB" -
}
declare -A UNOWNED
mark_unowned() {   # mark_unowned files...  -> fills UNOWNED[path]=1
    UNOWNED=()
    (($#)) || return
    build_pkg_db
    local p
    while IFS= read -r p; do UNOWNED[$p]=1; done < <(printf '%s\n' "$@" | unowned)
}
# returns 0 if the package manager says the file's checksum changed (trojaned binary)
pkg_modified() {
    local f=$1 nf=$1 pkg=""
    [[ $nf =~ ^/usr/(bin|sbin|lib|lib32|lib64|libx32)/ ]] && nf=${nf#/usr}
    if compgen -G '/var/lib/dpkg/info/*.list' >/dev/null && has dpkg; then
        pkg=$(dpkg -S "$f" 2>/dev/null | head -n1)
        [[ -z $pkg ]] && pkg=$(dpkg -S "$nf" 2>/dev/null | head -n1)
        [[ -z $pkg ]] && pkg=$(dpkg -S "/usr$nf" 2>/dev/null | head -n1)
        pkg=${pkg%%: *}; pkg=${pkg%%,*}
        [[ -z $pkg ]] && return 1
        dpkg -V "$pkg" 2>/dev/null | awk -v f="$nf" "$AWK_NORM"'norm($NF) == f && $1 ~ /5/ {m=1} END {exit !m}'
    elif has rpm; then
        rpm -Vf "$f" 2>/dev/null | awk -v f="$nf" "$AWK_NORM"'norm($NF) == f && $1 ~ /5/ {m=1} END {exit !m}'
    else
        return 1
    fi
}

# ---------------------------------------------------------------- user homes
HOMES=(); declare -A HOME_USER
get_homes() {
    ((${#HOMES[@]})) && return
    local user uid home
    while IFS=: read -r user _ uid _ _ home _; do
        [[ -z $home || ! -d $home || -n ${HOME_USER[$home]} ]] && continue
        HOME_USER[$home]=$user; HOMES+=("$home")
    done < /etc/passwd
    [[ -d /root && -z ${HOME_USER[/root]} ]] && { HOME_USER[/root]=root; HOMES+=(/root); }
}

# ---------------------------------------------------------------- filesystem walk
# One pass over / that collects SUID/SGID files, kernel modules and files named
# like known LD_PRELOAD rootkits. Shared by the preload, kernel and suid sections.
RK_LIB_GLOBS=('*father*.so*' 'libprocesshider*' '*processhider*.so*' '*azazel*.so*' '*jynx*.so*'
              '*bdvl*.so*' '*beurk*.so*' '*vlany*.so*' 'libhide*.so*' 'lib_preload*.so*' '*rootkit*.so*')
FSWALK=""
fs_walk() {
    [[ -n $FSWALK ]] && return
    FSWALK=$WORKDIR/fswalk
    init_busybox
    local -a prune=(/proc /sys /snap /var/lib/snapd/snap /var/lib/docker /var/lib/containers /var/lib/lxcfs)
    local _d mp fs _r
    while read -r _d mp fs _r; do
        case $fs in nfs|nfs4|cifs|smb3|smbfs|fuse.sshfs|9p|ceph|glusterfs|fuse.s3fs|fuse.rclone|autofs) prune+=("$mp") ;; esac
    done < /proc/mounts
    local -a expr=('(' -path "${prune[0]}")
    local x
    for x in "${prune[@]:1}"; do expr+=(-o -path "$x"); done
    expr+=(')' -prune -o -type f '(' -perm -4000 -o -perm -2000 -o -name '*.ko' -o -name '*.ko.xz' -o -name '*.ko.zst' -o -name '*.ko.gz')
    for x in "${RK_LIB_GLOBS[@]}"; do expr+=(-o -name "$x"); done
    expr+=(')' -print)
    local -a finder=(find)
    if [[ -n $BB ]] && ((BB_STATIC)) && "$BB" find /proc -maxdepth 0 '(' -path /proc -o -path /x ')' -prune -o -type f -perm -4000 -print >/dev/null 2>&1; then
        finder=("$BB" find)
    fi
    note "Walking the filesystem once (SUID/SGID, .ko modules, rootkit libs) with '${finder[*]}' - may take a minute..."
    note "Skipping: ${prune[*]}"
    "${finder[@]}" / "${expr[@]}" > "$FSWALK" 2>/dev/null
}

# ============================================================================
# Suspicious-content patterns (bash ERE, matched case-insensitively)
# Used for shell rc files, cron entries, systemd Exec lines, at jobs, etc.
# ============================================================================
PAT_NAMES=(); declare -A PAT PSEV
addpat() { PAT_NAMES+=("$1"); PSEV[$1]=$2; PAT[$1]=$3; }

addpat "Pipe-to-shell"      2 '(curl|wget|fetch)[^#]*[|][[:space:]]*(sudo[[:space:]]+(-[a-z]+[[:space:]]+)*)?((ba|da|z|k)?sh|python[0-9.]*|perl|ruby|php)([^[:alnum:]_]|$)'
addpat "Reverse shell"      2 '/dev/(tcp|udp)/|(^|[^[:alnum:]_.-])(nc|ncat|netcat)([[:space:]][^#]*)?[[:space:]]-[a-z]*[ec]([[:space:]]|$)|socat[^#]*(exec|system):|mkfifo|(^|[^[:alnum:]_])(ba|da|z|k)?sh[[:space:]]+-i[[:space:]]*[0-9]*[<>]&'
addpat "Netcat/Socat"       1 '(^|[^[:alnum:]_.-])(nc|ncat|netcat|socat)([[:space:]]|$)'
addpat "Inline interpreter" 2 '(^|[^[:alnum:]_])(python[0-9.]*|perl|ruby|php[0-9.]*|node|lua[0-9.]*)[[:space:]]+-[a-z]*[ecr][[:space:]]'
addpat "Encoded payload"    2 '(base64[[:space:]]+(-[a-z]*d|--decode)|xxd[[:space:]]+-[a-z]*r|openssl[[:space:]]+(enc|base64)[^#]*[[:space:]]-d)[^#]*[|][[:space:]]*((ba|da|z|k)?sh|python[0-9.]*|perl|ruby|php)([^[:alnum:]_]|$)|(\\x[0-9a-f]{2}){4,}'
addpat "Decodes data"       1 'base64[[:space:]]+(-[a-z]*d|--decode)|xxd[[:space:]]+-[a-z]*r|openssl[[:space:]]+(enc|base64)[^#]*[[:space:]]-d'
addpat "Eval of payload"    2 'eval[[:space:]]+[^#]*(base64|xxd|curl|wget|\\x[0-9a-f])'
addpat "Temp-dir exec"      2 '(/tmp|/var/tmp|/dev/shm)/[^[:space:]]*\.(sh|py|pl|rb|elf|bin|so|php)([^[:alnum:]]|$)|(/tmp|/var/tmp|/dev/shm)/\.[^/[:space:]]|(^|[;&|`(]|then|do|exec|nohup|setsid)[[:space:]]*(/tmp|/var/tmp|/dev/shm)/[^[:space:]]'
addpat "Runs script"        1 '^/[^[:space:]]+\.(sh|py|pl|rb|bin|elf)([[:space:]]|$)'
addpat "Download"           1 '(^|[^[:alnum:]_])(curl|wget)[[:space:]]'
addpat "Detached process"   1 '(^|[^[:alnum:]_])(nohup|setsid|disown)([[:space:]]|$)|screen[[:space:]]+-[a-z]*d|tmux[^#]*new[^#]*-d'
addpat "Dangerous chmod"    2 'chmod[[:space:]]+(-[a-z]+[[:space:]]+)*([0-7]?777|[ugoa]*\+[rwxt]*s|[2-7][0-7]{3})([^0-9]|$)'
addpat "chattr"             2 '(^|[^[:alnum:]_])chattr[[:space:]]'
addpat "SSH key injection"  2 '(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp[0-9]+)[[:space:]]+AAAA|authorized_keys'
addpat "Linker hijack"      2 'LD_PRELOAD|LD_AUDIT|ld\.so\.preload'
addpat "LD_LIBRARY_PATH"    1 'LD_LIBRARY_PATH'
addpat "Shell hook"         1 'PROMPT_COMMAND|trap[[:space:]][^#]*[[:space:]](DEBUG|ERR|RETURN)([[:space:]]|;|$)|(^|[^[:alnum:]_])BASH_ENV|(^|[^[:alnum:]_])ENV=|PS[0-4]=[^#]*(\$\(|`)'
addpat "declare -f / export -f" 1 '(^|[^[:alnum:]_])(declare|typeset)[[:space:]]+-[a-z]*f|export[[:space:]]+-[a-z]*f'
addpat "Builtin tamper"     2 '(^|[^[:alnum:]_])enable[[:space:]]+-[a-z]*n|unalias[[:space:]]+-a|unset[[:space:]]+-f[[:space:]]+(command|builtin)'
addpat "History evasion"    2 "HISTFILE=(/dev/null|[\"']{0,2}([[:space:]]|;|\$))|unset[[:space:]]+[^#]*HIST|HIST(FILE)?SIZE=[\"']?0([^0-9]|\$)|set[[:space:]]+\+o[[:space:]]+history|history[[:space:]]+-c"
addpat "Credential capture" 2 'read[[:space:]]+(-[a-z]*s|-[a-z]+[[:space:]]+-[a-z]*s)|stty[[:space:]]+-echo|/etc/shadow'
addpat "PATH hijack"        2 "(^|[^[:alnum:]_])PATH=[\"']?:|(^|[^[:alnum:]_])PATH=[^#]*::|(^|[^[:alnum:]_])PATH=([^#]*:)?[\"']?(\\.|/tmp|/var/tmp|/dev/shm)(/[^:\"'[:space:]]*)?([:\"'[:space:]]|\$)"

# scan_line <text>  -> sets HIT_SEV (0/1/2) and HIT_TAGS
scan_line() {
    local line=$1 name
    HIT_SEV=0; HIT_TAGS=""
    shopt -s nocasematch
    for name in "${PAT_NAMES[@]}"; do
        if [[ $line =~ ${PAT[$name]} ]]; then
            HIT_TAGS+="${HIT_TAGS:+, }$name"
            ((PSEV[$name] > HIT_SEV)) && HIT_SEV=${PSEV[$name]}
        fi
    done
    shopt -u nocasematch
}

# ============================================================================
# Alias / function analysis
# ============================================================================
# Commands an attacker would want to wrap (steal sudo passwords, hide procs, etc.)
SENSITIVE_CMDS=" sudo su ssh scp sftp passwd login ls dir ps top htop pgrep pstree netstat ss lsof kill pkill killall who w last lastlog id whoami groups cat less more head tail find grep cd echo printf history unset alias unalias declare typeset type command builtin enable exec eval source exit logout chattr lsattr crontab at systemctl service journalctl iptables ip6tables nft ufw firewall-cmd ip ifconfig route mount umount rm mv cp chmod chown useradd usermod userdel adduser deluser chpasswd getent sh bash dash zsh env strings ldd readlink stat file which whereis apt apt-get yum dnf rpm dpkg tcpdump nmap wget curl nc sed awk tee touch md5sum sha256sum "
BUILTINS=""
is_sensitive() { [[ $SENSITIVE_CMDS == *" $1 "* ]]; }
is_cmd() { [[ -z $BUILTINS ]] && BUILTINS=" $(compgen -b | tr '\n' ' ') "; type -P "$1" >/dev/null 2>&1 || [[ $BUILTINS == *" $1 "* ]]; }

ALIAS_RE='(^|[;&|[:space:]])alias[[:space:]]+(-[a-zA-Z]+[[:space:]]+)*(--[[:space:]]+)?([^=[:space:]]+)=(.*)$'
FUNC_RE='^(function[[:space:]]+([A-Za-z_][A-Za-z0-9_:.@+-]*)|([A-Za-z_][A-Za-z0-9_:.@+-]*)[[:space:]]*\(\))'
META_RE='[;|&`<>]|\$\('

# classify_alias <name> <raw value> <file>  -> A_SEV, A_TAG
classify_alias() {
    local name=$1 val=$2 file=$3 raw0 cmd0 compound=0
    case $val in
        \'*) val=${val#\'}; val=${val%%\'*} ;;
        \"*) val=${val#\"}; val=${val%%\"*} ;;
        *)   val=${val%%[[:space:]]*} ;;
    esac
    read -r raw0 cmd0 _ <<< "$val"
    case $raw0 in command|builtin|exec|nice|nohup) ;; *) cmd0=$raw0 ;; esac
    raw0=${cmd0#\\}; raw0=${raw0%%[;|&]*}; cmd0=${raw0##*/}
    [[ $val =~ $META_RE ]] && compound=1
    A_SEV=0; A_TAG="alias $name"

    # well-known distro defaults
    case "$name=$cmd0" in vi=vim|view=vim|vi=nvim|vim=nvim) return ;; esac
    [[ $name == alert && $val == notify-send* ]] && return            # Ubuntu ~/.bashrc
    [[ $name == which && $val == *"/usr/bin/which --tty-only"* ]] && return   # RHEL which2.sh
    [[ $name == mc && $val == *mc-wrapper* ]] && return               # RHEL mc

    if [[ $raw0 == */* && ! $raw0 =~ ^/(usr/)?(local/)?s?bin/ ]]; then
        A_SEV=2; A_TAG="alias '$name' runs binary from odd path: $raw0"
    elif is_sensitive "$name" && [[ $cmd0 != "$name" ]]; then
        A_SEV=2; A_TAG="alias HIJACKS '$name' -> '$cmd0'"
    elif is_sensitive "$name" && ((compound)); then
        A_SEV=2; A_TAG="alias '$name' wraps a compound command"
    elif ((compound)); then
        A_SEV=1; A_TAG="alias '$name' runs a compound command"
    elif [[ $cmd0 != "$name" ]] && is_cmd "$name"; then
        A_SEV=1; A_TAG="alias shadows command '$name' -> '$cmd0'"
    fi
}

# classify_func <name> <file>  -> F_SEV, F_TAG
classify_func() {
    local name=$1 file=$2
    F_SEV=0; F_TAG="function $name()"
    case $name in
        command_not_found_handle|command_not_found_handler)
            F_SEV=1; F_TAG="$name() runs on every unknown command (Debian/Ubuntu default in /etc/bash.bashrc - verify body)"; return ;;
    esac
    [[ $name == which && $file == */which2.* ]] && return
    if is_sensitive "$name"; then
        F_SEV=2; F_TAG="function HIJACKS '$name'"
    elif is_cmd "$name"; then
        F_SEV=1; F_TAG="function shadows command '$name'"
    fi
}

# scan_file <file> <owner-label> <rc|script>
#   rc     = shell startup file: patterns + alias/function analysis
#   script = any other script: patterns only
SCANNED=0
scan_file() {
    local f=$1 who=$2 mode=${3:-rc} minsev=${4:-0}
    [[ -f $f ]] || return 0
    if [[ ! -r $f ]]; then warn "Cannot read $f"; return 0; fi
    ((SCANNED++))
    local owner perm mdate mtime hdr=0 n=0 raw line sev tags is_def
    read -r owner perm mdate mtime _ <<< "$(stat -L -c '%U %a %y' "$f" 2>/dev/null)"
    local hdrtxt="$f  (owner=$owner perm=$perm modified=$mdate ${mtime%%.*})"
    _fh() { ((hdr)) && return; hdr=1; printf '  %s>> %s%s\n' "$DIM" "$hdrtxt" "$NC"; }

    if [[ $perm =~ ^[0-9]+$ ]] && (( ${perm: -1} & 2 )); then
        _fh; alert "$f is WORLD-WRITABLE ($perm) - anyone can inject commands. Fix: chmod o-w '$f'"
    fi
    if [[ $mode == rc && $who != system && $owner != "$who" && $owner != root ]]; then
        _fh; warn "$f belongs to '$who' but is owned by '$owner'"
    fi

    while IFS= read -r raw || [[ -n $raw ]]; do
        ((n++))
        line=${raw#"${raw%%[![:space:]]*}"}
        [[ -z $line || $line == \#* ]] && continue
        scan_line "$line"; sev=$HIT_SEV; tags=$HIT_TAGS; is_def=0
        if [[ $mode == rc ]]; then
            if [[ $line =~ $ALIAS_RE ]]; then
                is_def=1
                classify_alias "${BASH_REMATCH[4]}" "${BASH_REMATCH[5]}" "$f"
                tags+="${tags:+, }$A_TAG"; ((A_SEV > sev)) && sev=$A_SEV
            elif [[ $line =~ $FUNC_RE ]]; then
                is_def=1
                classify_func "${BASH_REMATCH[2]:-${BASH_REMATCH[3]}}" "$f"
                tags+="${tags:+, }$F_TAG"; ((F_SEV > sev)) && sev=$F_SEV
            fi
        fi
        ((sev < minsev)) && continue
        if ((sev > 0)) || ((is_def && !QUIET)); then
            _fh; report "$sev" "$f:$n [$tags] $(trunc "$line" 160)"
        fi
    done < "$f"
}

# ============================================================================
# SECTION: shell - rc / profile files, aliases, functions
# ============================================================================
RC_FILES=(.bashrc .bash_profile .bash_login .profile .bash_logout .bash_aliases
          .zshrc .zprofile .zlogin .zshenv .zlogout .kshrc .mkshrc .cshrc .tcshrc .login
          .config/fish/config.fish .xprofile .xinitrc .xsessionrc .ssh/rc)

run_shell() {
    section shell "Shell startup files - patterns, aliases, functions, declare -f"
    SCANNED=0
    local f h

    sub "System-wide startup files (/etc/profile*, bash.bashrc, zsh, skel, sshrc)"
    shopt -s nullglob dotglob
    local -a sysfiles=(/etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/bash.bash_logout
        /etc/environment /etc/zsh/* /etc/zshrc /etc/zprofile /etc/zshenv /etc/zlogin /etc/zlogout
        /etc/csh.cshrc /etc/csh.login /etc/ksh.kshrc /etc/mkshrc /etc/fish/config.fish /etc/ssh/sshrc
        /etc/skel/* /etc/skel/.config/fish/config.fish)
    shopt -u dotglob
    mark_unowned /etc/profile.d/*
    for f in "${sysfiles[@]}"; do
        [[ -f $f ]] || continue
        # package-owned profile.d snippets (vte, systemd...) set PROMPT_COMMAND etc. - only show ALERT-level hits there
        if [[ $f == /etc/profile.d/* && -n $PKG_DB && -z ${UNOWNED[$f]} ]]; then scan_file "$f" system rc 2
        else scan_file "$f" system rc; fi
    done
    if [[ -f /etc/ssh/sshrc ]]; then
        warn "/etc/ssh/sshrc exists - it runs for EVERY ssh login ($(fmeta /etc/ssh/sshrc))"
    fi
    for f in "${!UNOWNED[@]}"; do
        warn "Not installed by any package: $f ($(fmeta "$f"))"
    done
    shopt -u nullglob

    sub "Per-user startup files (every home dir in /etc/passwd)"
    get_homes
    for h in "${HOMES[@]}"; do
        for f in "${RC_FILES[@]}"; do scan_file "$h/$f" "${HOME_USER[$h]}" rc; done
        if [[ -f $h/.ssh/rc ]]; then
            warn "$h/.ssh/rc exists - runs on every ssh login as ${HOME_USER[$h]} ($(fmeta "$h/.ssh/rc"))"
        fi
        for f in "$h/.bash_history" "$h/.zsh_history"; do
            if [[ -L $f && $(readlink "$f") == /dev/null ]]; then
                warn "$f is symlinked to /dev/null (history being hidden)"
            fi
        done
    done
    info "Scanned $SCANNED startup files"
}

# ============================================================================
# SECTION: cron - crontabs, periodic scripts, at, systemd, boot/login hooks
# ============================================================================
# cron_entry <label> <line> <has_user_field 0|1> <base_sev>
cron_entry() {
    local label=$1 line=$2 hu=$3 base=$4 cmd sev
    local -a w
    if [[ $line =~ ^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*= ]]; then
        cmd=$line                                    # VAR=value line
    else
        read -r -a w <<< "$line"
        if [[ ${w[0]} == @* ]]; then cmd=${w[*]:$((1 + hu))}; else cmd=${w[*]:$((5 + hu))}; fi
    fi
    scan_line "$cmd"
    sev=$base; ((HIT_SEV > sev)) && sev=$HIT_SEV
    report "$sev" "$label: $(trunc "$line")${HIT_TAGS:+  [$HIT_TAGS]}"
}

# active_lines <file>  -> non-blank, non-comment lines (trimmed)
active_lines() {
    local raw line acc=""
    while IFS= read -r raw || [[ -n $raw ]]; do
        line=${raw#"${raw%%[![:space:]]*}"}
        if [[ -z $acc ]]; then [[ -z $line || $line == \#* ]] && continue; fi
        if [[ $line == *\\ ]]; then acc+="${line%\\} "; continue; fi
        printf '%s\n' "$acc$line"; acc=""
    done < "$1"
    [[ -n $acc ]] && printf '%s\n' "$acc"
}

run_cron() {
    section cron "Scheduled tasks, services & boot/login hooks"
    local f d u line n
    shopt -s nullglob

    # ---------------------------------------------------------------- user crontabs
    sub "User crontabs"
    local found=0
    for d in /var/spool/cron/crontabs /var/spool/cron/tabs /var/spool/cron /etc/crontabs; do
        [[ -d $d ]] || continue
        for f in "$d"/*; do
            [[ -f $f ]] || continue
            found=1; u=${f##*/}; n=0
            getent passwd "$u" >/dev/null || alert "Crontab for a user that is NOT in /etc/passwd: $f"
            while IFS= read -r line; do
                ((n++)); cron_entry "crontab[$u]" "$line" 0 1
            done < <(active_lines "$f")
            ((n)) || info "crontab[$u] exists but has no active entries ($f)"
        done
    done
    if ((!found)); then
        # no spool dir found - fall back to asking crontab for every user
        while IFS=: read -r u _; do
            while IFS= read -r line; do
                line=${line#"${line%%[![:space:]]*}"}
                [[ -z $line || $line == \#* ]] && continue
                found=1; cron_entry "crontab[$u]" "$line" 0 1
            done < <(crontab -u "$u" -l 2>/dev/null)
        done < /etc/passwd
    fi
    ((found)) || ok "No user crontabs"

    # ---------------------------------------------------------------- system crontabs
    sub "System crontabs (/etc/crontab, /etc/cron.d, anacrontab)"
    local -a sysc=(/etc/crontab /etc/cron.d/*)
    mark_unowned "${sysc[@]}"
    for f in "${sysc[@]}"; do
        [[ -f $f ]] || continue
        local base=0
        [[ -n ${UNOWNED[$f]} ]] && { base=1; warn "Not installed by any package: $f ($(fmeta "$f"))"; }
        while IFS= read -r line; do cron_entry "$f" "$line" 1 "$base"; done < <(active_lines "$f")
    done
    if [[ -f /etc/anacrontab ]]; then
        while IFS= read -r line; do
            scan_line "$line"; report "$HIT_SEV" "/etc/anacrontab: $(trunc "$line")${HIT_TAGS:+  [$HIT_TAGS]}"
        done < <(active_lines /etc/anacrontab)
    fi

    # ---------------------------------------------------------------- periodic scripts
    sub "Periodic scripts (/etc/cron.{hourly,daily,weekly,monthly}, /etc/periodic)"
    local -a per=()
    for f in /etc/cron.{hourly,daily,weekly,monthly,yearly}/* /etc/periodic/*/*; do
        [[ -f $f && ${f##*/} != .placeholder ]] && per+=("$f")
    done
    mark_unowned "${per[@]}"
    for f in "${per[@]}"; do
        if [[ -n ${UNOWNED[$f]} ]]; then
            warn "Periodic script not from any package: $f ($(fmeta "$f"))"; scan_file "$f" "${f%/*}" script
        else
            info "$f"; scan_file "$f" "${f%/*}" script 2
        fi
    done

    # ---------------------------------------------------------------- at
    sub "at jobs"
    local id rest cmd sev atfound=0
    if has atq; then
        while read -r id rest; do
            [[ -z $id ]] && continue
            atfound=1
            cmd=$(at -c "$id" 2>/dev/null | sed -n '/^cd /,$p' |
                  grep -vE '^cd |DELIMITER|Execution directory inaccessible|^[[:space:]]*exit 1$|^\}$|^[[:space:]]*$' |
                  head -n 5 | tr '\n' ';')
            scan_line "$cmd"; sev=1; ((HIT_SEV > sev)) && sev=$HIT_SEV
            report "$sev" "at job $id ($rest): $(trunc "$cmd")${HIT_TAGS:+  [$HIT_TAGS]}"
        done < <(atq 2>/dev/null)
    fi
    for d in /var/spool/cron/atjobs /var/spool/at /var/spool/atjobs; do
        for f in "$d"/*; do
            [[ -f $f && ${f##*/} != .SEQ ]] || continue
            ((atfound)) || { atfound=1; warn "at spool file present: $f ($(fmeta "$f"))"; }
        done
    done
    ((atfound)) || ok "No at jobs"

    # ---------------------------------------------------------------- systemd
    sub "systemd units/timers not shipped by a package (or admin/user-created)"
    if [[ -d /run/systemd/system ]] || has systemctl; then
        get_homes
        local -a sdirs=() units=(); declare -A sseen
        local r
        for d in /etc/systemd/system /etc/systemd/user /usr/local/lib/systemd/system \
                 /lib/systemd/system /usr/lib/systemd/system /lib/systemd/user /usr/lib/systemd/user; do
            [[ -d $d ]] || continue
            r=$(readlink -f "$d"); [[ -n ${sseen[$r]} ]] && continue; sseen[$r]=1; sdirs+=("$r")
        done
        for d in "${HOMES[@]}"; do [[ -d $d/.config/systemd/user ]] && sdirs+=("$d/.config/systemd/user"); done
        while IFS= read -r -d '' f; do units+=("$f"); done < <(find "${sdirs[@]}" -type f \( -name '*.service' -o \
            -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -path '*.d/*.conf' \) -print0 2>/dev/null)
        mark_unowned "${units[@]}"

        local vendor usev en l v exe ucount=0
        for f in "${units[@]}"; do
            vendor=0; case $f in /lib/*|/usr/lib/*) vendor=1 ;; esac
            if [[ -n $PKG_DB ]]; then [[ -z ${UNOWNED[$f]} ]] && continue
            else ((vendor)) && continue; fi
            ((ucount++))
            usev=1; en=""
            case $f in
                */.config/systemd/user/*) en="user unit" ;;
                *.d/*.conf) en="drop-in override" ;;
                *) en="enabled=$(systemctl is-enabled "${f##*/}" 2>/dev/null)" ;;
            esac
            [[ ${f##*/} == snap.* ]] && grep -q '/usr/bin/snap' "$f" 2>/dev/null && usev=0
            local -a dl=()
            while IFS= read -r l; do
                l=${l#"${l%%[![:space:]]*}"}
                if [[ $l == Exec* ]]; then
                    v=${l#*=}
                    while [[ $v == [-@:+!]* ]]; do v=${v:1}; done
                    exe=${v%%[[:space:]]*}
                    scan_line "$v"
                    case $exe in
                        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/run/user/*)
                            HIT_SEV=2; HIT_TAGS+="${HIT_TAGS:+, }runs from temp/home dir" ;;
                    esac
                    [[ $exe == */.* ]] && { HIT_SEV=2; HIT_TAGS+="${HIT_TAGS:+, }hidden path"; }
                    [[ $exe == /* && ! -e $exe ]] && HIT_TAGS+="${HIT_TAGS:+, }binary missing"
                    ((HIT_SEV > usev)) && usev=$HIT_SEV
                    dl+=("$l${HIT_TAGS:+   <-- $HIT_TAGS}")
                else
                    dl+=("$l")
                fi
            done < <(grep -E '^[[:space:]]*(Exec[A-Za-z]*|OnCalendar|OnBootSec|OnStartupSec|OnUnitActiveSec|ListenStream|ListenDatagram|PathChanged|PathModified|PathExists|Unit|User)=' "$f" 2>/dev/null)
            report "$usev" "Unit: $f ($en, $(fmeta "$f"))"
            if ((usev || !QUIET)); then for l in "${dl[@]}"; do detail "$l"; done; fi
        done
        ((ucount)) || ok "No unpackaged/admin-created systemd units"

        while IFS= read -r -d '' l; do
            r=$(readlink -f "$l")
            case $r in /dev/null|/lib/systemd/*|/usr/lib/systemd/*|/etc/systemd/*|/run/systemd/*|/usr/local/lib/systemd/*|"") ;;
                *) alert "systemd unit symlink points outside systemd dirs: $l -> $r" ;;
            esac
        done < <(find /etc/systemd/system /etc/systemd/user -type l -print0 2>/dev/null)

        if ((!QUIET)) && has systemctl; then
            info "Active timers (systemctl list-timers):"
            systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print "          " $0}' | head -n 40
        fi
    else
        info "systemd not running - skipped"
    fi

    # ---------------------------------------------------------------- boot / login hooks
    sub "Boot & login hooks (rc.local, init.d, update-motd.d, udev RUN+=, XDG autostart)"
    for f in /etc/rc.local /etc/rc.d/rc.local; do
        [[ -f $f ]] || continue
        n=0
        while IFS= read -r line; do
            [[ $line == "exit 0" ]] && continue
            ((n++)); scan_line "$line"; sev=1; ((HIT_SEV > sev)) && sev=$HIT_SEV
            report "$sev" "$f: $(trunc "$line")${HIT_TAGS:+  [$HIT_TAGS]}"
        done < <(active_lines "$f")
        ((n)) || info "$f exists but has no commands"
    done

    local -a hooks=(/etc/init.d/* /etc/update-motd.d/* /etc/xdg/autostart/*.desktop)
    mark_unowned "${hooks[@]}"
    for f in "${hooks[@]}"; do
        [[ -f $f ]] || continue
        [[ -n ${UNOWNED[$f]} ]] && warn "Not installed by any package: $f ($(fmeta "$f"))"
        if [[ -n ${UNOWNED[$f]} ]]; then scan_file "$f" hook script
        elif [[ $f == /etc/update-motd.d/* ]]; then scan_file "$f" hook script 2; fi   # motd runs as root on login
    done
    get_homes
    for d in "${HOMES[@]}"; do
        for f in "$d"/.config/autostart/*.desktop; do
            warn "User autostart entry: $f -> $(grep -m1 '^Exec=' "$f" 2>/dev/null)"
        done
    done

    for f in /etc/udev/rules.d/*.rules; do
        while IFS= read -r line; do
            [[ $line == *RUN* ]] || continue
            scan_line "$line"; sev=1; ((HIT_SEV > sev)) && sev=$HIT_SEV
            report "$sev" "udev rule runs a command: $f: $(trunc "$line")${HIT_TAGS:+  [$HIT_TAGS]}"
        done < <(active_lines "$f")
    done
    local -a urules=(/lib/udev/rules.d/*.rules /usr/lib/udev/rules.d/*.rules)
    mark_unowned "${urules[@]}"
    for f in "${!UNOWNED[@]}"; do warn "udev rule not from any package: $f ($(fmeta "$f"))"; done
    shopt -u nullglob
}

# ============================================================================
# SECTION: preload - LD_PRELOAD / userland rootkits
# ============================================================================
run_preload() {
    section preload "LD_PRELOAD / userland rootkits"
    init_busybox
    local f l pid k p
    shopt -s nullglob

    if [[ -z $BB ]]; then
        warn "BusyBox not found - libc-bypass comparisons skipped (install busybox-static before comp if allowed)"
    elif ((BB_STATIC)); then
        ok "Static BusyBox found ($BB) - used to see past libc hooks"
    else
        warn "BusyBox ($BB) is dynamically linked - LD_PRELOAD can hook it too, comparisons are less trustworthy"
    fi

    # ---------------------------------------------------------------- env
    sub "LD_* variables in this shell"
    local any=0
    for k in LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH; do
        [[ -n ${!k} ]] && { any=1; alert "$k is set in the current environment: ${!k}"; }
    done
    ((any)) || ok "LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH not set"

    # ---------------------------------------------------------------- ld.so.preload
    sub "/etc/ld.so.preload"
    local seen_libc=0 seen_bb=0 content=""
    [[ -e /etc/ld.so.preload ]] && seen_libc=1
    [[ -n $BB ]] && "$BB" ls -a /etc 2>/dev/null | grep -qx 'ld.so.preload' && seen_bb=1
    if ((seen_bb && !seen_libc)); then
        alert "/etc/ld.so.preload is HIDDEN from libc but visible to BusyBox - active LD_PRELOAD rootkit!"
    fi
    if ((seen_libc || seen_bb)); then
        [[ -n $BB ]] && content=$("$BB" cat /etc/ld.so.preload 2>/dev/null)
        [[ -z $content ]] && content=$(< /etc/ld.so.preload) 2>/dev/null
        if [[ -n ${content//[[:space:]]/} ]]; then
            alert "/etc/ld.so.preload exists and is NOT empty ($(fmeta /etc/ld.so.preload)) - every program loads:"
            while IFS= read -r l; do
                [[ -z $l || $l == \#* ]] && continue
                if [[ -e $l ]]; then detail "$l  ($(fmeta "$l"))"; else detail "$l  (file not visible - hidden?)"; fi
            done <<< "$content"
            if has od; then od -A x -t x1z -v /etc/ld.so.preload 2>/dev/null | head -n 4 | while IFS= read -r l; do detail "hex: $l"; done; fi
            note "Fix: cp /etc/ld.so.preload /root/evidence/ && : > /etc/ld.so.preload, then remove the .so and restart services"
        else
            warn "/etc/ld.so.preload exists but is empty ($(fmeta /etc/ld.so.preload))"
        fi
    else
        ok "/etc/ld.so.preload does not exist"
    fi

    # ---------------------------------------------------------------- ld.so.conf
    sub "Dynamic linker search paths (/etc/ld.so.conf, /etc/ld.so.conf.d)"
    local -a ldc=(/etc/ld.so.conf /etc/ld.so.conf.d/*)
    mark_unowned "${ldc[@]}"
    for f in "${ldc[@]}"; do
        [[ -f $f ]] || continue
        [[ -n ${UNOWNED[$f]} ]] && warn "Not installed by any package: $f ($(fmeta "$f"))"
        while IFS= read -r l; do
            [[ $l == include* ]] && continue
            if [[ $l =~ ^/(tmp|var/tmp|dev/shm|home|root|run/user)(/|$) || $l == */.* ]]; then
                alert "Library search path in a user/temp/hidden dir: $f: $l"
            else
                info "$f: $l"
            fi
        done < <(active_lines "$f")
    done

    # ---------------------------------------------------------------- process env
    sub "Process environments (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, BASH_ENV, exported functions)"
    declare -A ENVHIT
    local kv
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        [[ -r $p/environ ]] || continue
        while IFS= read -r -d '' kv; do
            case $kv in
                LD_PRELOAD=*|LD_AUDIT=*|LD_LIBRARY_PATH=*|BASH_ENV=*) k=$kv ;;
                BASH_FUNC_*) k=${kv%%=*} ;;
                *) continue ;;
            esac
            ENVHIT[$k]+=" $pid"
        done 2>/dev/null < "$p/environ"
    done
    if ((${#ENVHIT[@]} == 0)); then
        ok "No process has LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH/BASH_ENV/exported functions"
    fi
    for k in "${!ENVHIT[@]}"; do
        case $k in
            LD_PRELOAD=*|LD_AUDIT=*) alert "Processes running with $(trunc "$k" 150): $(pidlist "${ENVHIT[$k]}")" ;;
            BASH_FUNC_which%%) info "Exported function 'which' (RHEL which2.sh default): $(pidlist "${ENVHIT[$k]}")" ;;
            BASH_FUNC_*) warn "Exported bash function ${k#BASH_FUNC_} (declare -fx / export -f) in: $(pidlist "${ENVHIT[$k]}")" ;;
            *) warn "Processes running with $(trunc "$k" 150): $(pidlist "${ENVHIT[$k]}")" ;;
        esac
    done

    # ---------------------------------------------------------------- maps
    sub "Executable libraries mapped into running processes"
    declare -A LIBP
    while IFS=$'\t' read -r pid l; do LIBP[$l]+=" $pid"; done < <(
        grep -HE '\.so|/memfd:|\(deleted\)' /proc/[0-9]*/maps 2>/dev/null |
        awk '$2 ~ /x/ && NF >= 6 { split($1, a, "/"); p = $6; for (i = 7; i <= NF; i++) p = p " " $i
                                   k = a[3] "\t" p; if (!(k in s)) { s[k] = 1; print k } }')
    local maps_hit=0
    for l in "${!LIBP[@]}"; do
        if [[ $l == /memfd:JITCode* || $l == /memfd:doublemapper* ]]; then
            maps_hit=1; warn "Executable memfd JIT region (normal for Qt/.NET - verify the process): $l in $(pidlist "${LIBP[$l]}")"
        elif [[ $l == /memfd:* ]]; then
            maps_hit=1; alert "Executable code from memfd (fileless): $l in $(pidlist "${LIBP[$l]}")"
        elif [[ ${l,,} =~ (father|processhider|azazel|jynx|bdvl|beurk|vlany|rootkit|backdoor|libhide|hide\.so|preload\.so) ]]; then
            maps_hit=1; alert "Library with rootkit-like name loaded: $l in $(pidlist "${LIBP[$l]}")"
        elif [[ $l == *"(deleted)" ]]; then
            [[ $l == *.so* ]] || continue
            maps_hit=1; warn "Deleted library still mapped (package upgrade OR removed implant): $l in $(pidlist "${LIBP[$l]}")"
        elif [[ $l == *.so* && ! $l =~ ^/(usr/)?(lib|lib32|lib64|libx32|libexec)/ && ! $l =~ ^/(snap|var/lib/snapd)/ ]]; then
            maps_hit=1; warn "Library loaded from non-standard path: $l in $(pidlist "${LIBP[$l]}")"
        fi
    done
    ((maps_hit)) || ok "No suspicious executable mappings"

    # ---------------------------------------------------------------- hidden pids/files via busybox
    sub "Hiding check: libc view vs BusyBox view"
    if [[ -n $BB ]]; then
        local -a only_bb=()
        local bbl=$WORKDIR/bb_proc libcl=$WORKDIR/libc_proc
        "$BB" ls /proc 2>/dev/null | grep -E '^[0-9]+$' | LC_ALL=C sort > "$bbl"
        command ls /proc 2>/dev/null | grep -E '^[0-9]+$' | LC_ALL=C sort > "$libcl"
        mapfile -t only_bb < <(LC_ALL=C comm -23 "$bbl" "$libcl")
        local hid=0
        for pid in "${only_bb[@]}"; do
            # re-check to rule out a process that just started
            command ls /proc 2>/dev/null | grep -qx "$pid" && continue
            "$BB" ls /proc 2>/dev/null | grep -qx "$pid" || continue
            hid=1; alert "PID $pid visible to BusyBox but hidden from libc 'ls /proc' - LD_PRELOAD process hiding"
            detail "cmdline: $("$BB" cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')"
        done
        ((hid)) || ok "Process lists match (libc vs BusyBox)"

        hid=0
        for d in /tmp /var/tmp /dev/shm /root /etc /usr/bin /usr/sbin /usr/lib /lib /usr/local/bin /usr/local/lib; do
            [[ -d $d ]] || continue
            while IFS= read -r f; do
                [[ -z $f ]] && continue
                hid=1; alert "File hidden from libc but visible to BusyBox: $d/$f"
            done < <(LC_ALL=C comm -23 <("$BB" ls -A "$d" 2>/dev/null | LC_ALL=C sort) <(command ls -A "$d" 2>/dev/null | LC_ALL=C sort))
        done
        ((hid)) || ok "Directory listings match (libc vs BusyBox) in temp, /etc, /root and lib/bin dirs"
    else
        info "Skipped (no busybox)"
    fi

    # ---------------------------------------------------------------- rootkit libs on disk
    sub "Known rootkit library names on disk"
    fs_walk
    local rk=0
    while IFS= read -r f; do
        case $f in *.ko|*.ko.xz|*.ko.zst|*.ko.gz) continue ;; esac
        [[ -u $f || -g $f ]] && continue
        rk=1; alert "Rootkit-like library file: $f ($(fmeta "$f"))"
    done < "$FSWALK"
    ((rk)) || ok "None of: ${RK_LIB_GLOBS[*]}"
    shopt -u nullglob
}

# ============================================================================
# SECTION: kernel - LKM rootkits
# ============================================================================
RK_MODULES=" diamorphine reptile reptile_module suterusu kovid adore adore_ng enyelkm kbeast ipsecs_kbeast_v1 nuk3gh0st rkduck khook singularity puszek bds_lkm "

run_kernel() {
    section kernel "Kernel modules / LKM rootkits / hidden processes"
    local f l m t pid
    shopt -s nullglob

    # ---------------------------------------------------------------- taint
    sub "Kernel taint"
    read -r t 2>/dev/null < /proc/sys/kernel/tainted
    t=${t:-0}
    if ((t == 0)); then
        ok "Kernel is not tainted"
    else
        local -a TN=([0]="P proprietary module" [1]="F module force-loaded" [2]="S out-of-spec system" [3]="R module force-unloaded"
            [4]="M machine check" [5]="B bad page" [6]="U user request" [7]="D kernel died/oops" [8]="A ACPI table overridden"
            [9]="W kernel warning" [10]="C staging driver" [11]="I firmware workaround" [12]="O out-of-tree module"
            [13]="E unsigned module" [14]="L soft lockup" [15]="K live-patched" [16]="X auxiliary" [17]="T randstruct")
        local b sev=0 desc=""
        for b in "${!TN[@]}"; do
            if (( (t >> b) & 1 )); then
                desc+="${desc:+, }${TN[b]}"
                case $b in 1|3|12|13) sev=1 ;; esac
            fi
        done
        report "$sev" "Kernel tainted ($t): $desc"
        ((sev)) && note "F/R/O/E taint = a non-distro module was (force-)loaded - LKM rootkits cause this (so do VirtualBox/NVIDIA drivers)"
    fi
    if has dmesg; then
        while IFS= read -r l; do warn "dmesg: $l"; done < <(dmesg 2>/dev/null |
            grep -Ei 'taints kernel|module verification failed|required key missing|loading out-of-tree' | tail -n 10)
    fi

    # ---------------------------------------------------------------- loaded modules
    sub "Loaded modules"
    declare -A PM
    local cnt=0 mt fn
    while read -r m _; do PM[$m]=1; ((cnt++)); done < /proc/modules
    info "$cnt modules loaded"
    for m in "${!PM[@]}"; do
        [[ $RK_MODULES == *" $m "* ]] && alert "Known rootkit module loaded: $m  (try: rmmod $m ; reboot may be needed)"
        mt=""; read -r mt 2>/dev/null < "/sys/module/$m/taint"
        if [[ -n $mt ]]; then
            fn=$(modinfo -F filename "$m" 2>/dev/null)
            warn "Module '$m' taints kernel [$mt] (O=out-of-tree E=unsigned P=proprietary) file=${fn:-unknown}"
            [[ -n $fn ]] && detail "$(modinfo -F description "$m" 2>/dev/null) | author: $(modinfo -F author "$m" 2>/dev/null)"
        fi
        fn=$(modinfo -F filename "$m" 2>/dev/null)
        if [[ $fn == /* && ! $fn =~ ^/(usr/)?lib/modules/ ]]; then
            alert "Module '$m' loaded from outside /lib/modules: $fn"
        fi
    done

    # ---------------------------------------------------------------- hidden modules
    sub "Hidden modules (/sys/module vs /proc/modules vs lsmod)"
    local hidden=0 d
    for d in /sys/module/*; do
        m=${d##*/}
        [[ -f $d/initstate ]] || continue          # built-in modules have no initstate
        [[ -n ${PM[$m]} ]] || { hidden=1; alert "Module '$m' is in /sys/module but HIDDEN from /proc/modules"; }
    done
    for m in "${!PM[@]}"; do
        [[ -d /sys/module/$m ]] || { hidden=1; alert "Module '$m' in /proc/modules but missing from /sys/module (kobject removed)"; }
    done
    if has lsmod; then
        while IFS= read -r m; do
            hidden=1; alert "Module '$m' in /proc/modules but NOT shown by lsmod (lsmod hooked/replaced?)"
        done < <(LC_ALL=C comm -23 <(awk '{print $1}' /proc/modules | LC_ALL=C sort) <(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | LC_ALL=C sort))
    fi
    ((hidden)) || ok "No module-list discrepancies"

    # ---------------------------------------------------------------- autoload configs
    sub "Module autoload configs & modprobe install hooks"
    for f in /etc/modules /etc/modules-load.d/*.conf /run/modules-load.d/*.conf /usr/lib/modules-load.d/*.conf /lib/modules-load.d/*.conf; do
        [[ -f $f ]] || continue
        while IFS= read -r m; do
            if [[ $RK_MODULES == *" ${m//-/_} "* ]]; then alert "Rootkit module set to autoload: $f: $m"
            else info "Autoload: $f: $m"; fi
        done < <(active_lines "$f")
    done
    local -a modp=(/etc/modprobe.d/*.conf /run/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf /lib/modprobe.d/*.conf)
    local cmd
    for f in "${modp[@]}"; do
        [[ -f $f ]] || continue
        while IFS= read -r l; do
            [[ $l =~ ^(install|remove)[[:space:]]+[^[:space:]]+[[:space:]]+(.*)$ ]] || continue
            cmd=${BASH_REMATCH[2]}
            case $cmd in
                /bin/true|/bin/false|/usr/bin/true|/usr/bin/false|true|false|"/bin/true "*|"/bin/false "*) continue ;;
                *modprobe*) info "$f: $l" ;;
                *) scan_line "$cmd"; alert "modprobe hook runs a command when a module loads: $f: $(trunc "$l")${HIT_TAGS:+  [$HIT_TAGS]}" ;;
            esac
        done < <(active_lines "$f")
    done

    # ---------------------------------------------------------------- .ko on disk
    sub "Kernel module files on disk"
    fs_walk
    local -a kos=()
    while IFS= read -r f; do
        case $f in
            *.ko|*.ko.xz|*.ko.zst|*.ko.gz) ;;
            *) continue ;;
        esac
        if [[ $f == *.ko ]]; then              # skip non-ELF ".ko" files (e.g. Korean docs)
            local magic=""; read -r -n 4 magic 2>/dev/null < "$f"
            [[ $magic == $'\x7fELF' ]] || continue
        fi
        case $f in
            /lib/modules/*|/usr/lib/modules/*) kos+=("$f") ;;
            /usr/src/*|/var/lib/dkms/*|/usr/lib/debug/*) ;;
            *) alert "Kernel module file outside the module tree: $f ($(fmeta "$f"))" ;;
        esac
    done < "$FSWALK"
    mark_unowned "${kos[@]}"
    local un=0
    for f in "${!UNOWNED[@]}"; do
        ((un++ < 25)) && warn "Module in /lib/modules not from any package (DKMS or planted): $f ($(fmeta "$f"))"
    done
    ((un > 25)) && warn "...and $((un - 25)) more unpackaged modules"
    info "${#kos[@]} module files under /lib/modules"

    # ---------------------------------------------------------------- ftrace / kprobes / bpf
    sub "Kernel function hooking (ftrace / kprobes / eBPF)"
    local ef n hooks=0
    for ef in /sys/kernel/tracing/enabled_functions /sys/kernel/debug/tracing/enabled_functions; do
        [[ -r $ef ]] || continue
        n=$(wc -l < "$ef" 2>/dev/null)
        if ((n > 0)); then
            hooks=1; warn "ftrace has $n hooked kernel functions ($ef) - ftrace-based rootkits hook syscalls this way (also livepatch/BPF tools)"
            head -n 10 "$ef" | while IFS= read -r l; do detail "$l"; done
        fi
        break
    done
    for ef in /sys/kernel/debug/kprobes/list /sys/kernel/tracing/kprobe_events; do
        [[ -r $ef && -s $ef ]] || continue
        hooks=1; warn "Active kprobes ($ef):"
        head -n 10 "$ef" | while IFS= read -r l; do detail "$l"; done
    done
    if has bpftool; then
        while IFS= read -r l; do hooks=1; warn "eBPF tracing program: $l"; done < <(bpftool prog show 2>/dev/null |
            grep -E '^[0-9]+: (kprobe|tracing|lsm|raw_tracepoint|tracepoint|perf_event)')
    else
        info "bpftool not installed - eBPF program check skipped"
    fi
    ((hooks)) || ok "No ftrace/kprobe/eBPF hooks seen"

    # ---------------------------------------------------------------- hidden PIDs
    sub "Hidden processes (brute-force PID probe vs /proc directory listing)"
    declare -A VIS
    local maxv=0 last=0 pmax=32768 upper k v tgid
    for d in /proc/[0-9]*; do pid=${d#/proc/}; VIS[$pid]=1; ((pid > maxv)) && maxv=$pid; done
    read -r last 2>/dev/null < /proc/sys/kernel/ns_last_pid
    read -r pmax 2>/dev/null < /proc/sys/kernel/pid_max
    upper=$(( (last > maxv ? last : maxv) + 512 )); ((upper > pmax)) && upper=$pmax
    local -a cand=()
    for ((pid = 1; pid <= upper; pid++)); do
        [[ -n ${VIS[$pid]} ]] && continue
        kill -0 "$pid" 2>/dev/null || [[ -e /proc/$pid/status ]] || continue
        tgid=""
        if [[ -r /proc/$pid/status ]]; then
            while read -r k v _; do [[ $k == Tgid: ]] && { tgid=$v; break; }; done 2>/dev/null < "/proc/$pid/status"
        fi
        [[ -n $tgid && $tgid != "$pid" ]] && continue          # a thread, not a process
        cand+=("$pid")
    done
    local found=0
    if ((${#cand[@]})); then
        declare -A VIS2
        for d in /proc/[0-9]*; do VIS2[${d#/proc/}]=1; done
        for pid in "${cand[@]}"; do
            [[ -n ${VIS2[$pid]} ]] && continue                 # just started - not hidden
            kill -0 "$pid" 2>/dev/null || [[ -e /proc/$pid/status ]] || continue
            found=1
            alert "PID $pid EXISTS but is hidden from the /proc listing (rootkit process hiding)"
            detail "comm: $(cat "/proc/$pid/comm" 2>/dev/null)  exe: $(readlink "/proc/$pid/exe" 2>/dev/null)"
            detail "cmdline: $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        done
    fi
    ((found)) || ok "No hidden PIDs (probed 1-$upper)"
    info "/proc/sys/kernel/modules_disabled = $(cat /proc/sys/kernel/modules_disabled 2>/dev/null)  (1 = no new modules can load until reboot)"
    shopt -u nullglob
}

# ============================================================================
# SECTION: immutable - chattr +i / +a
# ============================================================================
run_immutable() {
    section immutable "Immutable / append-only files (chattr +i / +a)"
    if ! has lsattr; then warn "lsattr not found (e2fsprogs) - skipped"; return; fi
    local d r flags path ni=0 na=0
    local -a dirs=(); declare -A seen
    for d in /etc /root /home /bin /sbin /usr/bin /usr/sbin /usr/local /lib/systemd /usr/lib/systemd \
             /var/spool/cron /var/www /srv /opt /tmp /var/tmp /dev/shm /boot; do
        [[ -d $d ]] || continue
        r=$(readlink -f "$d"); [[ -n ${seen[$r]} ]] && continue; seen[$r]=1; dirs+=("$r")
    done
    note "Scanning: ${dirs[*]}"
    while IFS= read -r l; do
        flags=${l%% *}; path=${l#* }
        if [[ $flags == *i* ]]; then
            ((ni++)); alert "IMMUTABLE    $path  [$flags]  ($(fmeta "$path"))"
        else
            ((na++)); warn "APPEND-ONLY  $path  [$flags]  ($(fmeta "$path"))"
        fi
    done < <(lsattr -Ra "${dirs[@]}" 2>/dev/null | awk '$1 ~ /^[-a-zA-Z]+$/ && $1 ~ /[ia]/ && NF >= 2 && $NF !~ /\/\.\.?$/')
    if ((ni + na == 0)); then
        ok "No immutable or append-only files found"
    else
        note "$ni immutable, $na append-only. Attackers chattr +i backdoors (authorized_keys, cron, binaries) so you can't delete them."
        note "If your team didn't set these: chattr -i -a <file>, then inspect/remove. (lsattr itself can be trojaned - verify with 'dpkg -V e2fsprogs' / 'rpm -V e2fsprogs')"
    fi
}

# ============================================================================
# SECTION: suid - SUID/SGID & capabilities
# ============================================================================
KNOWN_SUID=" sudo sudo.ws sudoedit su passwd chsh chfn chage expiry gpasswd newgrp sg mount umount fusermount fusermount3 pkexec polkit-agent-helper-1 dbus-daemon-launch-helper ssh-keysign ssh-agent ping ping6 arping traceroute6.iputils crontab at unix_chkpwd unix2_chkpwd pam_timestamp_check pam_extrausers_chkpwd utempter wall write write.ul bsd-write mlocate plocate locate dotlockfile dotlock.mailutils mail-lock mail-unlock mail-touchlock Xorg Xorg.wrap snap-confine newuidmap newgidmap mount.nfs mount.nfs4 umount.nfs umount.nfs4 mount.cifs mount.ecryptfs_private ntfs-3g pppd usernetctl userhelper staprun lockdev postdrop postqueue exim4 procmail chrome-sandbox chrome_sandbox ksu screen cockpit-session spice-client-glib-usb-acl-helper qemu-bridge-helper libgtop_server lppasswd fping fping6 mtr-packet vmware-user-suid-wrapper Xvnc suexec nvidia-modprobe netreport sm-notify dmcrypt-get-device gnome-pty-helper login_duo slock "
GTFO_SUID=" aa-exec ab agetty alpine ar arj arp as ascii-xfr ash aspell atobm awk base32 base64 basenc bash bc bridge busybox bzip2 capsh cat chmod chown chroot cmp column comm cp cpio cpulimit csh csplit csvtool cupsfilter curl cut dash date dd debugfs dialog diff dig dmsetup docker ed emacs env eqn espeak expand expect file find fish flock fmt fold gawk gcore gdb genisoimage gimp grep gzip hd head hexdump highlight hping3 iconv install ionice ip ispell jjs join jq jrunscript julia ksh ksshell kubectl ld.so less links logsave look lua make mawk minicom more mosquitto msgattrib msgcat msgconv msgfilter msgmerge msguniq multitime mv nasm nawk nc ncat netcat ncdu nft nice nl nm nmap node nohup od openssl openvpn pandoc paste perf perl pg php pidstat pr ptx python python2 python3 rc readelf restic rev rlwrap rsync rtorrent run-parts rview rvim sash scanmem sed setarch setfacl setlock sh shuf socat soelim softlimit sort sqlite3 ss ssh-keygen ssh-keyscan sshpass start-stop-daemon stdbuf strace strings sysctl systemctl tac tail tar taskset tbl tclsh tcsh tee terraform tftp tic time timeout troff ul unexpand uniq unshare unsquashfs unzip update-alternatives uudecode uuencode vagrant vi view vigr vim vimdiff vipw w3m watch wc wget whiptail xargs xdotool xmodmap xmore xxd xz yash zip zsh zsoelim "
is_gtfo() {
    [[ $GTFO_SUID == *" $1 "* ]] && return 0
    case $1 in python*|perl*|php*|ruby*|node*|lua*|tclsh*|wish*|pypy*) return 0 ;; esac
    return 1
}

run_suid() {
    section suid "SUID / SGID binaries & file capabilities"
    fs_walk
    local f base kind perm sev why
    local -a files=()
    while IFS= read -r f; do [[ -f $f && ( -u $f || -g $f ) ]] && files+=("$f"); done < "$FSWALK"
    mark_unowned "${files[@]}"

    sub "SUID/SGID files (${#files[@]} found) - checking location, GTFOBins, package ownership & checksums"
    for f in "${files[@]}"; do
        base=${f##*/}; sev=0; why=""
        if [[ -u $f && -g $f ]]; then kind="SUID+SGID"; elif [[ -u $f ]]; then kind="SUID"; else kind="SGID"; fi
        perm=$(stat -L -c '%a' "$f" 2>/dev/null)
        case $f in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/run/user/*|/var/www/*|/srv/*)
            sev=2; why+="${why:+; }in user/temp/web dir" ;; esac
        [[ $f == */.* ]] && { sev=2; why+="${why:+; }hidden path"; }
        [[ $perm =~ ^[0-9]+$ ]] && (( ${perm: -1} & 2 )) && { sev=2; why+="${why:+; }WORLD-WRITABLE"; }
        is_gtfo "$base" && { sev=2; why+="${why:+; }GTFOBins - instant root shell"; }
        if [[ -n $PKG_DB ]]; then
            if [[ -n ${UNOWNED[$f]} ]]; then
                sev=2; why+="${why:+; }not installed by any package"
            elif pkg_modified "$f"; then
                sev=2; why+="${why:+; }CHECKSUM DIFFERS from package (trojaned?)"
            fi
        fi
        if ((sev == 0)) && [[ $KNOWN_SUID != *" $base "* ]]; then
            sev=1; why="uncommon SUID/SGID binary - verify it needs the bit"
        fi
        report "$sev" "$kind $(fmeta "$f") $f${why:+  [$why]}"
    done
    note "Remove a bad bit: chmod u-s,g-s <file>   (GTFOBins: https://gtfobins.github.io/#+suid)"

    sub "File capabilities (getcap)"
    if ! has getcap; then info "getcap not installed (libcap2-bin / libcap) - skipped"; return; fi
    local -a cdirs=(); declare -A cseen
    local d r caps line
    for d in /usr /bin /sbin /opt /home /root /tmp /var/tmp /dev/shm /srv /var/www /etc; do
        [[ -d $d ]] || continue
        r=$(readlink -f "$d"); [[ -n ${cseen[$r]} ]] && continue; cseen[$r]=1; cdirs+=("$r")
    done
    local any=0
    while IFS= read -r line; do
        [[ -z $line ]] && continue
        any=1
        f=${line%% *}; caps=${line#* }; caps=${caps#= }
        base=${f##*/}; sev=0; why=""
        [[ $caps != *cap_* ]] && { sev=2; why="ALL capabilities"; }
        [[ $caps =~ cap_(setuid|setgid|sys_admin|sys_ptrace|sys_module|dac_override|dac_read_search|chown|fowner|sys_rawio|bpf|setfcap) ]] &&
            { sev=2; why+="${why:+; }root-equivalent capability"; }
        is_gtfo "$base" && { sev=2; why+="${why:+; }capability on interpreter/GTFOBin"; }
        case $f in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*) sev=2; why+="${why:+; }in user/temp dir" ;; esac
        report "$sev" "CAP $f $caps${why:+  [$why]}"
    done < <(getcap -r "${cdirs[@]}" 2>/dev/null)
    ((any)) || ok "No file capabilities set"
    ((any)) && note "Remove: setcap -r <file>"
}

# ============================================================================
# SECTION: procs - deleted / fileless / temp-dir binaries
# ============================================================================
run_procs() {
    section procs "Running processes from deleted / memfd / temp-dir binaries"
    local p pid exe arg0 sev why comm user ppid k v found=0
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        [[ $pid == "$$" || $pid == "$BASHPID" ]] && continue
        exe=$(readlink "$p/exe" 2>/dev/null)
        [[ -z $exe ]] && continue                    # kernel thread or already gone
        arg0=""; IFS= read -r -d '' arg0 2>/dev/null < "$p/cmdline"
        sev=0; why=""
        case $exe in
            *" (deleted)") sev=2; why="binary was DELETED from disk while running" ;;
            /memfd:*)      sev=2; why="running from memfd - fileless malware" ;;
        esac
        case ${exe% (deleted)} in
            /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*) sev=2; why+="${why:+; }runs from temp dir" ;;
        esac
        if [[ ${exe% (deleted)} == */.* ]] && ((sev < 1)); then sev=1; why+="${why:+; }binary in hidden directory"; fi
        if [[ $arg0 == \[*\] ]]; then sev=2; why+="${why:+; }pretends to be a kernel thread '$arg0' but has a binary"; fi
        ((sev)) || continue
        found=1
        read -r comm 2>/dev/null < "$p/comm"
        user=$(stat -c %U "$p" 2>/dev/null); ppid=""
        while read -r k v _; do [[ $k == PPid: ]] && { ppid=$v; break; }; done 2>/dev/null < "$p/status"
        report "$sev" "PID $pid ($comm) user=$user ppid=$ppid - $why"
        detail "exe: $exe"
        detail "cmd: $(trunc "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" 200)"
        detail "save evidence: cp /proc/$pid/exe /root/evidence/pid$pid.bin ; kill: kill -9 $pid"
    done
    if ((found)); then
        note "Deleted binaries also show up for services not restarted after a package upgrade - check the package log before killing."
    else
        ok "No processes running from deleted, memfd or temp-dir binaries"
    fi
}

# ============================================================================
# SECTION: ssh - authorized_keys & sshd config (DISPLAY ONLY - nothing wiped)
# ============================================================================
# always-visible key line (shows even in quiet/coordinate mode, respects budget)
keyline() { room && printf '  %skey%s %s\n' "$GREEN" "$NC" "$*"; return 0; }

show_akeys() {   # show_akeys <file> <user>
    local f=$1 who=$2 owner perm line n=0
    [[ -f $f ]] || return 0
    read -r owner perm _ <<< "$(stat -L -c '%U %a' "$f" 2>/dev/null)"
    if [[ $perm =~ ^[0-9]+$ ]] && (( ${perm: -1} & 2 )); then
        alert "$f is WORLD-WRITABLE ($perm) - anyone can append a key. Fix: chmod 600 '$f'"
    fi
    if [[ -n $owner && $owner != "$who" && $owner != root ]]; then
        warn "$f is owned by '$owner' but sits in ${who}'s home ($(fmeta "$f"))"
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line#"${line%%[![:space:]]*}"}
        [[ -z $line || $line == \#* ]] && continue
        ((n++, SSH_KEYS++))
        keyline "[$who] $(trunc "$line" 160)"
        # options field present? (anything before the key type is an options list)
        if [[ $line =~ (command|environment|permitopen)=  ]]; then
            warn "  ^ key has a forced-command/environment/permitopen option - read it: $f line $n"
        fi
    done < "$f"
    ((n)) && info "$who: $n authorized key(s) in $f"
}

run_ssh() {
    section ssh "SSH authorized_keys & sshd config (display only - use harden/ssh_key_checker.sh to remove)"
    SSH_KEYS=0
    get_homes
    local h f

    sub "authorized_keys in every home listed in /etc/passwd"
    for h in "${HOMES[@]}"; do
        for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
            show_akeys "$f" "${HOME_USER[$h]}"
        done
    done

    sub "authorized_keys anywhere else on disk (attacker drop points)"
    local other=0
    while IFS= read -r -d '' f; do
        case $f in
            */.ssh/authorized_keys|*/.ssh/authorized_keys2)
                [[ -n ${HOME_USER[${f%/.ssh/*}]} ]] && continue ;;  # already shown above
        esac
        other=1
        alert "authorized_keys in a non-home location: $f ($(fmeta "$f"))"
        show_akeys "$f" unknown
    done < <(find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o \
             -type f -name 'authorized_keys*' -print0 2>/dev/null)
    ((other)) || ok "No authorized_keys outside the standard home .ssh dirs"
    ((SSH_KEYS)) || ok "No authorized keys found anywhere"

    sub "sshd effective configuration (sshd -T)"
    local sshd=""
    sshd=$(command -v sshd 2>/dev/null) ||
        for d in /usr/sbin /sbin /usr/local/sbin; do [[ -x $d/sshd ]] && { sshd=$d/sshd; break; }; done
    if [[ -n $sshd ]]; then
        local line k v
        while IFS= read -r line; do
            k=${line%% *}; v=${line#* }
            case $k in
                permitrootlogin)      [[ $v == yes ]] && warn "PermitRootLogin yes" || info "$line" ;;
                permitemptypasswords) [[ $v == yes ]] && alert "PermitEmptyPasswords yes - accounts with no password can log in" || info "$line" ;;
                authorizedkeyscommand) [[ -n $v && $v != none ]] && warn "AuthorizedKeysCommand=$v - keys can come from this program's output, verify it" || info "$line" ;;
                authorizedkeysfile)   case $v in *%h/.ssh/*|*.ssh/authorized_keys*) info "$line" ;; *) warn "AuthorizedKeysFile is non-standard: $v" ;; esac ;;
                forcecommand)         [[ $v != none ]] && warn "ForceCommand=$v" || info "$line" ;;
                passwordauthentication|pubkeyauthentication|usepam|permittunnel|x11forwarding|gatewayports|allowusers|allowgroups|denyusers|denygroups)
                    info "$line" ;;
            esac
        done < <("$sshd" -T 2>/dev/null | tr 'A-Z' 'a-z')
    else
        warn "sshd binary not found - cannot show effective config; check /etc/ssh/sshd_config by hand"
    fi
}

# ============================================================================
# SECTION: pam - PAM authentication backdoors
# ============================================================================
run_pam() {
    section pam "PAM configuration & module backdoors"
    if [[ ! -d /etc/pam.d ]]; then info "/etc/pam.d not present - skipped"; return; fi
    local f line hit

    sub "Arbitrary command execution (pam_exec.so)"
    hit=0
    while IFS= read -r line; do hit=1; alert "pam_exec.so runs an external program on auth: $line"; done \
        < <(grep -rEn '^[^#]*pam_exec\.so' /etc/pam.d/ 2>/dev/null)
    ((hit)) || ok "No pam_exec.so lines"

    sub "Conditional auth bypass (pam_succeed_if.so)"
    hit=0
    while IFS= read -r line; do hit=1; warn "pam_succeed_if.so (legit for targeting rules, abused to skip auth - read it): $line"; done \
        < <(grep -rEn '^[^#]*pam_succeed_if\.so' /etc/pam.d/ 2>/dev/null)
    ((hit)) || ok "No pam_succeed_if.so lines"

    sub "Empty-password allowance (nullok / nullok_secure)"
    hit=0
    while IFS= read -r line; do hit=1; warn "nullok lets accounts with a blank password authenticate: $line"; done \
        < <(grep -rEn '^[^#]*nullok' /etc/pam.d/ 2>/dev/null)
    ((hit)) || ok "No nullok directives"

    sub "pam_permit.so before pam_deny.so in auth stacks (always-succeed)"
    hit=0
    for f in /etc/pam.d/*-auth /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/login; do
        [[ -f $f ]] || continue
        local deny permit
        deny=$(grep -nE '^[^#]*pam_deny\.so' "$f" 2>/dev/null | head -n1 | cut -d: -f1)
        permit=$(grep -nE '^[^#]*pam_permit\.so' "$f" 2>/dev/null | head -n1 | cut -d: -f1)
        if [[ -n $permit && -n $deny ]] && ((permit < deny)); then
            hit=1; alert "$f: pam_permit.so (line $permit) is reached before pam_deny.so (line $deny) - auth can always succeed"
        fi
    done
    ((hit)) || ok "No permit-before-deny ordering found"

    sub "PAM modules not owned by a package / with a changed checksum"
    local -a pamso=()
    while IFS= read -r f; do pamso+=("$f"); done < <(
        find /lib /lib64 /lib32 /usr/lib /usr/lib64 /usr/lib32 -type f -name 'pam_*.so' 2>/dev/null)
    if ((${#pamso[@]} == 0)); then
        info "No pam_*.so modules found in the usual lib dirs"
    else
        mark_unowned "${pamso[@]}"
        local bad=0
        for f in "${pamso[@]}"; do
            if [[ -n ${UNOWNED[$f]} ]]; then
                bad=1; alert "PAM module not installed by any package: $f ($(fmeta "$f"))"
            elif pkg_modified "$f"; then
                bad=1; alert "PAM module CHECKSUM DIFFERS from its package (trojaned?): $f ($(fmeta "$f"))"
            fi
        done
        ((bad)) || ok "All ${#pamso[@]} pam_*.so modules are package-owned and unmodified"
    fi
}

# ============================================================================
# Main
# ============================================================================
want procs     && run_procs
want shell     && run_shell
want cron      && run_cron
want ssh       && run_ssh
want pam       && run_pam
want preload   && run_preload
want kernel    && run_kernel
want immutable && run_immutable
want suid      && run_suid

printf '\n%s%s==================================================%s\n' "$BOLD" "$GREEN" "$NC"
printf '%s%s  Summary  (%ss)%s\n' "$BOLD" "$GREEN" "$SECONDS" "$NC"
printf '%s%s==================================================%s\n' "$BOLD" "$GREEN" "$NC"
for s in "${RAN_SECTIONS[@]}"; do
    printf '  %-10s %s%3d ALERT%s  %s%3d WARN%s\n' "$s" "$RED" "${SEC_A[$s]:-0}" "$NC" "$YELLOW" "${SEC_W[$s]:-0}" "$NC"
done
printf '  %-10s %s%3d ALERT%s  %s%3d WARN%s\n' "TOTAL" "$RED$BOLD" "$ALERTS" "$NC" "$YELLOW$BOLD" "$WARNS" "$NC"
((CAPPED)) && printf '  %s(output was capped at %s lines - some WARN/INFO lines not shown)%s\n' "$YELLOW" "$MAX_LINES" "$NC"
((QUIET)) || cat <<EOF

${BOLD}Remediation quick reference${NC}
  - Save evidence first: cp the file / cp /proc/PID/exe into /root/evidence
  - LD_PRELOAD rootkit: : > /etc/ld.so.preload ; delete the .so ; restart services (or reboot)
  - Kernel module:      rmmod <name> ; remove it from /etc/modules* and /etc/modprobe.d ; delete the .ko
  - Immutable file:     chattr -i -a <file>  then fix/delete it
  - SUID backdoor:      chmod u-s,g-s <file>  (or delete if it was planted)
  - Cron/systemd/at:    crontab -u <user> -r | systemctl disable --now <unit> | atrm <id>
  - Shell rc backdoor:  remove the line, then check the other rc files too - attackers drop more than one
  - Restore binaries from packages: apt install --reinstall <pkg> / dnf reinstall <pkg>
EOF

# one greppable line per host:  grep -h PERSIST-SUMMARY output/*/*
ip=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "PERSIST-SUMMARY host=$(hostname) ip=${ip:-?} alerts=$ALERTS warns=$WARNS sections=${SECTIONS// /,} secs=$SECONDS"
exit 0
