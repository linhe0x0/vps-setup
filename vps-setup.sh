#!/usr/bin/env bash
#=============================================================================
# vps-setup.sh
#
# Interactive one-shot bootstrap and security hardening for a fresh Linux
# server (AWS EC2 or any cloud VPS).
#
# Supported distributions:
#   - Debian / Ubuntu (ufw based firewall)
#   - CentOS / RHEL / Rocky / AlmaLinux / Amazon Linux (firewalld based)
#
# What this script can do (final plan is shown before anything is changed):
#   1.  Update base packages and apply a full system upgrade
#   2.  Enforce a password quality policy (pwquality)
#   3.  Log every sudo command to /var/log/sudo.log
#   4.  Create a dedicated admin (sudo) user and install SSH keys
#   5.  Harden file permissions (/etc/passwd, /etc/shadow, ~/.ssh)
#   6.  Configure a default-deny firewall (ufw / firewalld)
#   7.  Harden SSH: disable root login and password auth, optional port change
#   8.  Install and configure fail2ban (aggressive SSH jail)
#   9.  Enable automatic security updates
#   10. Ensure time synchronization is active
#   11. Scan for insecure listening ports (FTP, Telnet, SMTP, SMB, RDP, ...)
#   12. Print a final verification report of the effective configuration
#
# Design goals:
#   - Idempotent: safe to re-run; every already-satisfied step is reported
#     as an explicit SKIP with its reason.
#   - Transparent: each step logs [✓] / [→] SKIP / [i] / [!] / [✗] results.
#   - Lockout-safe: existing config is backed up, SSH changes are validated
#     with `sshd -t` before restart, confirmed interactively afterwards, and
#     guarded by a 15-minute dead-man switch that auto-rolls back if the
#     confirmation gate is never reached (e.g. the session dies).
#   - Concurrency-safe: a non-blocking flock prevents two parallel runs from
#     interleaving changes; the lock is released automatically on any exit.
#   - Auditable: every run writes a timestamped execution report under
#     /var/vps-setup/reports/, and edited files are backed up under
#     /var/vps-setup/backups/.
#
# Usage:
#   sudo bash vps-setup.sh
#
# HIGH-IMPACT side effects (also shown interactively before execution):
#   - Root SSH login is permanently disabled.
#   - SSH password authentication is disabled (key-only access). Without a
#     key the user must explicitly choose to keep password auth enabled.
#   - Incoming traffic is denied by default; only listed ports stay open.
#   - Failed SSH logins are banned by fail2ban.
#   - A full package upgrade is performed; a reboot may be required.
#=============================================================================

set -uo pipefail
# SC2317/SC2329 (unreachable / never-invoked functions) are suppressed in
# .shellcheckrc: task_* functions are dispatched indirectly via run_task
# ("$3") and trap handlers are referenced inside quoted strings, neither of
# which shellcheck can see. All other findings stay enabled.
export LC_ALL=C
umask 077

#=============================================================================
# Constants
# NOTE: do NOT use the name VERSION — sourcing /etc/os-release defines it.
#=============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly BASE_DIR="/var/vps-setup"
readonly BK_DIR="${BASE_DIR}/backups"
readonly RESULT_DIR="${BASE_DIR}/reports"
readonly LOCK_FILE="${BASE_DIR}/lock"
readonly CONFIRM_FLAG="${BASE_DIR}/.ssh-confirmed"
readonly DMS_UNIT_BASE="vps-setup-dms"
readonly STEP_TOTAL=12
# Hard bound on the post-restart confirmation gate. A silently dropped SSH
# connection keeps the server-side pty open, so an unbounded read would block
# the run forever — and the dead-man switch keeps yielding while this process
# holds the lock. The bound is what makes the auto-rollback promise true.
readonly GATE_TIMEOUT=900
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly SSHD_DROPIN="${SSHD_DROPIN_DIR}/00-vps-setup-hardening.conf"
# Files whose Port directives were stripped for this run. Rollback restores
# them from $BK_DIR; the list is removed once the change is confirmed.
readonly PORT_STRIP_LIST="${BASE_DIR}/ssh-port-strip.list"
readonly F2B_JAIL_LOCAL="/etc/fail2ban/jail.local"
readonly PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly SUDOERS_FILE="/etc/sudoers"
readonly SUDOERS_LOGGING_DROPIN="/etc/sudoers.d/60-vps-setup-logging"
readonly ROOT_KEYS_FILE="/root/.ssh/authorized_keys"
readonly AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"

if [ -t 1 ]; then
    GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[1;31m'
    CYAN=$'\033[1;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; YELLOW=""; RED=""; CYAN=""; BOLD=""; NC=""
fi

#=============================================================================
# State (globals filled during detection / input collection / execution)
#=============================================================================
OK_N=0; SKIP_N=0; WARN_N=0; ERR_N=0
REPORT_FINALIZED=0

FAMILY=""            # debian | rhel
DISTRO_PRETTY="unknown"
PKG="apt-get"        # apt-get | dnf | yum
ADMIN_GROUP="sudo"   # sudo (Debian/Ubuntu) | wheel (RHEL family)
FW_KIND="ufw"        # ufw | firewalld
SSHD_BIN="/usr/sbin/sshd"
SSH_UNIT="ssh.service"
KBD_KEYWORD="KbdInteractiveAuthentication"
SSH_SOCKET_MODE=0    # 1 = sshd is systemd socket-activated (ssh.socket)
ALL_SSH_PORTS=(22)   # every Port currently configured in sshd
SSH_PORT_ORIG=22
SSH_PORT_FINAL=22
SSH_PORT_CHANGED=0
DROPIN_SUPPORTED=0

NEW_USER=""
USER_EXISTS=0
ADMIN_PW=""
SSH_KEYS_CONTENT=""
NO_KEY_AVAILABLE=0
EXTRA_PORTS=()
DO_UPGRADE=1
DO_AUTOUPDATES=1
PKG_INDEX_UPDATED=0

SSH_HARDEN_APPLIED=0
DMS_UNIT=""
DMS_SCRIPT=""
PROMPT_TTY=""        # set when stdin is piped: prompts read from /dev/tty
RESULT_FILE=""

#=============================================================================
# Logging helpers — every result is printed in a uniform, greppable format
# AND mirrored (plain text, no colors) into the persistent execution report.
#=============================================================================
_log_append() { # $1 = tag, rest = message
    local tag="$1"
    shift
    if [ -n "${RESULT_FILE:-}" ]; then
        printf '%s [%s] %s\n' "$(date '+%F %T')" "$tag" "$*" >> "$RESULT_FILE"
    fi
}
log_ok()     { OK_N=$((OK_N + 1));     printf '%s[✓]%s %s\n'       "$GREEN"  "$NC" "$*"; _log_append "OK"    "$*"; }
log_skip()   { SKIP_N=$((SKIP_N + 1)); printf '%s[→] SKIP:%s %s\n' "$CYAN"   "$NC" "$*"; _log_append "SKIP"  "$*"; }
log_warn()   { WARN_N=$((WARN_N + 1)); printf '%s[!]%s %s\n'       "$YELLOW" "$NC" "$*"; _log_append "WARN"  "$*"; }
log_error()  { ERR_N=$((ERR_N + 1));   printf '%s[✗]%s %s\n'       "$RED"    "$NC" "$*" >&2; _log_append "ERROR" "$*"; }
log_info()   { printf '%s[i]%s %s\n'   "$CYAN"   "$NC" "$*"; _log_append "INFO" "$*"; }
subheader()  { printf '\n%s%s── %s ──%s\n' "$BOLD" "$CYAN" "$1" "$NC"; _log_append "----" "$1"; }
step()       { printf '\n%s%s=== [%s/%s] %s ===%s\n' "$BOLD" "$CYAN" "$1" "$STEP_TOTAL" "$2" "$NC"; _log_append "STEP" "[$1/$STEP_TOTAL] $2"; }

die() {
    log_error "$*"
    exit 1
}

on_interrupt() {
    printf '\n'
    log_warn "Interrupted — configuration may be partial. Re-run this script to resume safely (idempotent)."
    exit 130    # the EXIT trap finalizes the report
}

on_exit() {
    local rc=$?
    if [ "$REPORT_FINALIZED" -eq 0 ] && [ -n "${RESULT_FILE:-}" ] && [ -f "$RESULT_FILE" ]; then
        _log_append "STATUS" "run ended early (exit ${rc}) — partial state possible"
        finalize_report
    fi
}

#=============================================================================
# Persistent execution report (audit trail under /var/vps-setup/reports/)
#=============================================================================
init_report() {
    mkdir -p "$RESULT_DIR"
    RESULT_FILE="${RESULT_DIR}/report-$(date '+%Y%m%d-%H%M%S').log"
    {
        printf '# vps-setup execution report\n'
        printf '# Host    : %s\n' "$(hostname 2>/dev/null || printf 'unknown')"
        printf '# Started : %s\n' "$(date '+%F %T')"
    } > "$RESULT_FILE"
    chmod 600 "$RESULT_FILE"
}

# Record the user-approved decisions once. Secrets (passwords) are NEVER
# written to the report; only key fingerprints, never key material.
report_decisions() {
    local n_keys=0 fp
    if [ -n "$SSH_KEYS_CONTENT" ]; then
        n_keys=$(printf '%s\n' "$SSH_KEYS_CONTENT" | grep -cvE '^(#|$)')
    fi
    {
        printf '\n== Approved plan (user typed yes) ==\n'
        printf 'Admin user        : %s%s\n' "$NEW_USER" "$([ "$USER_EXISTS" -eq 1 ] && printf ' (existing user reused)')"
        printf 'SSH port          : %s -> %s\n' "$SSH_PORT_ORIG" "$SSH_PORT_FINAL"
        printf 'SSH password auth : %s\n' "$([ "$NO_KEY_AVAILABLE" -eq 1 ] && printf 'kept ENABLED (no key)' || printf 'disabled (key-only)')"
        printf 'Extra open ports  : %s\n' "${EXTRA_PORTS[*]:-none}"
        printf 'System upgrade    : %s\n' "$([ "$DO_UPGRADE" -eq 1 ] && printf 'yes' || printf 'no')"
        printf 'Automatic updates : %s\n' "$([ "$DO_AUTOUPDATES" -eq 1 ] && printf 'yes' || printf 'no')"
        printf 'SSH keys for %s: %s\n' "$NEW_USER" "$n_keys"
        if [ -n "$SSH_KEYS_CONTENT" ]; then
            while IFS= read -r k; do
                [ -z "$k" ] && continue
                case "$k" in \#*) continue ;; esac
                fp=$(ssh-keygen -lf /dev/stdin <<< "$k" 2>/dev/null | awk '{print $2}')
                [ -n "$fp" ] && printf '  - %s\n' "$fp"
            done <<< "$SSH_KEYS_CONTENT"
        fi
    } >> "$RESULT_FILE"
}

# Closing block for the report: counters, endpoint, backups, final status.
finalize_report() {
    local b
    {
        printf '\n== Result ==\n'
        printf 'Applied: %s  Skipped: %s  Warnings: %s  Errors: %s\n' "$OK_N" "$SKIP_N" "$WARN_N" "$ERR_N"
        printf 'Final SSH endpoint : ssh -p %s %s@%s\n' "$SSH_PORT_FINAL" "$NEW_USER" "$(ssh_address_hint)"
        printf 'Config backups dir : %s\n' "$BK_DIR"
        if [ -d "$BK_DIR" ]; then
            for b in "$BK_DIR"/*; do
                [ -e "$b" ] && printf '  - %s\n' "$b"
            done
        fi
        [ -f /var/run/reboot-required ] && printf 'Reboot required    : yes (packages flagged /var/run/reboot-required)\n'
        printf 'Status             : %s\n' "$([ "$ERR_N" -gt 0 ] && printf 'COMPLETED WITH ERRORS' || printf 'OK')"
        printf '# Finished: %s\n' "$(date '+%F %T')"
    } >> "$RESULT_FILE"
    REPORT_FINALIZED=1
}

#=============================================================================
# Small utility helpers
#=============================================================================
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

pkg_installed() {
    case "$FAMILY" in
        debian) dpkg -s "$1" >/dev/null 2>&1 ;;
        rhel)   rpm -q "$1" >/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

# Non-blocking concurrency guard: never waits, so it can never deadlock.
# fd 9 is released automatically on ANY exit path (INT/TERM/kill -9 included).
acquire_lock() {
    local lock_dir
    lock_dir=$(dirname "$LOCK_FILE")
    if ! mkdir -p "$lock_dir"; then
        die "Cannot create $lock_dir"
    fi
    if ! cmd_exists flock; then
        die "flock(1) is required to guard against concurrent runs (util-linux) but was not found."
    fi
    exec 9>>"$LOCK_FILE"
    if ! flock -n 9; then
        die "Another vps-setup run appears to be active (lock: $LOCK_FILE). If you are sure no other run exists, remove the lock file and retry."
    fi
}

# Back up a file once per host so the FIRST pre-script state is always kept.
backup_file() {
    local f="$1"
    local target
    target="${BK_DIR}/$(printf '%s' "$f" | tr '/' '_').bak"
    if [ ! -f "$target" ] && [ -f "$f" ]; then
        mkdir -p "$BK_DIR"
        cp -a "$f" "$target"
        log_info "Backed up $f -> $target"
    fi
}

# M5: every interactive read goes through here. EOF (Ctrl-D) is fatal —
# it must never spin in a tight error loop. When executed through a pipe
# (curl | sudo bash), reads are served from the controlling terminal.
prompt_read() { # $1 prompt, $2 varname, [$3 = 1 for silent input]
    local rc
    if [ -n "$PROMPT_TTY" ]; then
        if [ "${3:-0}" = "1" ]; then
            read -r -s -p "$1" "$2" < "$PROMPT_TTY"
        else
            read -r -p "$1" "$2" < "$PROMPT_TTY"
        fi
    else
        if [ "${3:-0}" = "1" ]; then
            read -r -s -p "$1" "$2"
        else
            read -r -p "$1" "$2"
        fi
    fi
    rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '\n'
        die "Input stream closed (EOF/Ctrl-D). Aborting — no further changes will be made."
    fi
}

# Bounded variant used by the confirmation gate. The plain read in prompt_read
# never returns when the TCP flow is black-holed (the pty stays open).
# Returns 0 on a line, 1 on EOF, >128 on timeout.
prompt_read_timeout() { # $1 prompt, $2 varname, $3 timeout in seconds
    if [ -n "$PROMPT_TTY" ]; then
        read -r -t "$3" -p "$1" "$2" < "$PROMPT_TTY"
    else
        read -r -t "$3" -p "$1" "$2"
    fi
}

confirm_yn() { # $1 question, $2 default: y|n
    local ans
    if [ "${2:-y}" = "y" ]; then
        prompt_read "$1 [Y/n]: " ans
        ans="${ans:-y}"
    else
        prompt_read "$1 [y/N]: " ans
        ans="${ans:-n}"
    fi
    case "$ans" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

validate_pubkey() {
    local key="$1" tmp
    tmp=$(mktemp) || return 1
    printf '%s\n' "$key" > "$tmp"
    if ssh-keygen -lf "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# M3: recover a dpkg state left broken by a previously interrupted upgrade.
ensure_dpkg_recovered() {
    local audit
    cmd_exists dpkg || return 0
    audit=$(dpkg --audit 2>/dev/null)
    [ -n "$audit" ] || return 0
    log_warn "dpkg reports an interrupted state from a previous run — running 'dpkg --configure -a'"
    if DEBIAN_FRONTEND=noninteractive dpkg --configure -a; then
        log_ok "dpkg state recovered"
        return 0
    fi
    log_error "'dpkg --configure -a' failed — fix manually, then re-run this script"
    return 1
}

wait_for_apt_lock() {
    local i=0
    while :; do
        if ! pgrep -f '(^|/)apt-get|(^|/)dpkg|(^|/)unattended-upgrade' >/dev/null 2>&1 \
            && ! { cmd_exists fuser && fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; }; then
            return 0
        fi
        i=$((i + 1))
        if [ "$i" -gt 40 ]; then
            log_warn "apt/dpkg is still busy after ~10 minutes; continuing anyway"
            return 1
        fi
        [ "$i" -eq 1 ] && log_info "Waiting for a running apt/dpkg process to finish..."
        sleep 15
    done
}

# Refresh the package index once per run. Debian uses apt-get update; the
# RHEL family uses makecache (yum and dnf both support it). A failure is
# reported but not fatal: the install attempt may still work with cached data.
refresh_pkg_index() {
    [ "$PKG_INDEX_UPDATED" -eq 1 ] && return 0
    case "$FAMILY" in
        debian)
            wait_for_apt_lock || true
            ensure_dpkg_recovered || true
            log_info "Updating package index..."
            if apt-get update -y >/dev/null 2>&1; then
                log_ok "Package index updated"
                PKG_INDEX_UPDATED=1
                return 0
            fi
            log_warn "apt-get update failed — continuing with the existing index"
            ;;
        rhel)
            log_info "Refreshing package metadata..."
            if "$PKG" makecache >/dev/null 2>&1; then
                log_ok "Package metadata refreshed"
                PKG_INDEX_UPDATED=1
                return 0
            fi
            log_warn "$PKG makecache failed — continuing with the existing metadata"
            ;;
    esac
    return 1
}

# Install packages one by one so a single unavailable package cannot block
# the others. Refreshes the index first (once per run). Returns 2 when
# nothing was missing, 0 when every missing package was installed, and 1
# when at least one installation failed.
install_pkgs() {
    local missing=() failed=() p
    for p in "$@"; do
        pkg_installed "$p" || missing+=("$p")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        log_skip "all required packages already installed: $*"
        return 2
    fi

    refresh_pkg_index || true

    log_info "Installing: ${missing[*]}"
    for p in "${missing[@]}"; do
        log_info "Installing $p..."
        case "$FAMILY" in
            debian)
                if DEBIAN_FRONTEND=noninteractive apt-get install -y "$p"; then
                    log_ok "Installed $p"
                else
                    log_error "Failed to install $p"
                    failed+=("$p")
                fi
                ;;
            rhel)
                if "$PKG" install -y "$p"; then
                    log_ok "Installed $p"
                else
                    log_error "Failed to install $p"
                    failed+=("$p")
                fi
                ;;
        esac
    done
    if [ "${#failed[@]}" -gt 0 ]; then
        log_error "Packages that could not be installed: ${failed[*]}"
        return 1
    fi
    return 0
}

# Public IP hint for the interactive SSH test. Cloudflare's trace endpoint
# reports the address the request came from, so it works on any provider.
# The routing-table fallback only helps when the host itself has a public
# address; on EIP/NAT setups it returns the private VPC address.
public_ip_hint() {
    local ip=""
    if cmd_exists curl; then
        ip=$(curl -4 -s --connect-timeout 3 --max-time 5 \
            https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
            | sed -n 's/^ip=//p')
    fi
    if [ -z "$ip" ]; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i+1); exit}}')
    fi
    [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    printf '%s' "$ip"
}

# True for addresses that cannot be reached from the internet: RFC1918,
# CGNAT, loopback, link-local. The routing-table fallback returns one of
# these on NAT/EIP hosts, where it is useless as an SSH target.
is_private_address() { # $1 IPv4/IPv6 address
    case "$1" in
        10.*|127.*|0.*|192.168.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
        ::1|fe80:*|fc*:*|fd*:*) return 0 ;;
    esac
    return 1
}

# Address used in the "ssh ..." hints. A private address is replaced by a
# placeholder so the script never prints a command that cannot work.
ssh_address_hint() {
    local ip
    ip=$(public_ip_hint)
    if [ -n "$ip" ] && ! is_private_address "$ip"; then
        printf '%s' "$ip"
    else
        printf '<your-server-public-ip>'
    fi
}

#=============================================================================
# Environment detection
#=============================================================================
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This script must run as root. Try: sudo bash $0"
    fi
}

require_tty() {
    if [ -t 0 ]; then
        return 0
    fi
    # Piped execution (e.g. curl | sudo bash): the script itself keeps
    # reading from stdin; only the interactive prompts are bound to the
    # controlling terminal, so a prompt can never consume the script source.
    if (exec 0</dev/tty) 2>/dev/null && [ -c /dev/tty ]; then
        PROMPT_TTY="/dev/tty"
        log_info "Piped stdin detected — interactive prompts bound to /dev/tty"
        return 0
    fi
    die "No interactive terminal detected. Run this script directly in an SSH session: sudo bash $0"
}

# Pick the keyword this OpenSSH build understands. `sshd -T` emits only the
# canonical name (kbdinteractiveauthentication) on 8.7+, so grepping its
# output through a pipe is fragile: `grep -q` exits early and the resulting
# SIGPIPE can make the pipeline fail under `pipefail`. Cache the output and
# match it with a here-string instead.
detect_kbd_keyword() {
    local dump
    dump=$("$SSHD_BIN" -T 2>/dev/null) || dump=""
    [ -n "$dump" ] || return 0
    if grep -qi '^[[:space:]]*kbdinteractiveauthentication' <<< "$dump"; then
        KBD_KEYWORD="KbdInteractiveAuthentication"
    else
        KBD_KEYWORD="ChallengeResponseAuthentication"
    fi
}

detect_os() {
    local id="" version_id=""
    if [ ! -r /etc/os-release ]; then
        die "/etc/os-release not found — unsupported or unknown system."
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    version_id="${VERSION_ID:-}"
    DISTRO_PRETTY="${PRETTY_NAME:-$id $version_id}"

    case "$id" in
        ubuntu|debian|linuxmint|devuan)
            FAMILY="debian"; PKG="apt-get"; ADMIN_GROUP="sudo"; FW_KIND="ufw"
            ;;
        centos|rhel|rocky|almalinux|ol|amzn|fedora|anolis)
            FAMILY="rhel"; ADMIN_GROUP="wheel"; FW_KIND="firewalld"
            if cmd_exists dnf; then PKG="dnf"; else PKG="yum"; fi
            ;;
        *)
            die "Unsupported distribution '$id'. Supported: Debian, Ubuntu, CentOS/RHEL, Rocky, AlmaLinux, Amazon Linux."
            ;;
    esac

    if [ "$FAMILY" = "rhel" ] && [ "${version_id%%.*}" = "7" ]; then
        log_warn "${DISTRO_PRETTY} is EOL. Package installs may fail against archived mirrors; steps continue best-effort."
    fi

    if ! cmd_exists systemctl; then
        die "systemd is required but 'systemctl' was not found."
    fi

    SSHD_BIN="$(command -v sshd || printf '/usr/sbin/sshd')"

    # Detect the SSH unit: prefer whichever is actually running.
    local u
    SSH_UNIT=""
    for u in ssh.service sshd.service; do
        if systemctl is-active --quiet "$u" 2>/dev/null; then SSH_UNIT="$u"; break; fi
    done
    if [ -z "$SSH_UNIT" ]; then
        for u in ssh.service sshd.service; do
            if systemctl cat "$u" >/dev/null 2>&1; then SSH_UNIT="$u"; break; fi
        done
    fi
    [ -z "$SSH_UNIT" ] && SSH_UNIT="ssh.service"

    # H3: Ubuntu 22.10+ / Debian 13+ socket-activate sshd. In that mode the
    # listening port is owned by ssh.socket (ListenStream) and the Port
    # directive is ignored, so it must be detected — never guessed by version.
    SSH_SOCKET_MODE=0
    if systemctl is-enabled ssh.socket >/dev/null 2>&1 \
        || systemctl is-active --quiet ssh.socket 2>/dev/null; then
        SSH_SOCKET_MODE=1
    fi

    # Older OpenSSH (< 8.7) only knows ChallengeResponseAuthentication.
    detect_kbd_keyword

    # All currently configured SSH ports (first one is the managed default).
    local p valid=()
    mapfile -t ALL_SSH_PORTS < <(effective_ssh_ports | tr ' ' '\n' | grep -E '^[0-9]+$')
    for p in ${ALL_SSH_PORTS[@]+"${ALL_SSH_PORTS[@]}"}; do
        if [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; then
            valid+=("$p")
        fi
    done
    ALL_SSH_PORTS=(${valid[@]+"${valid[@]}"})
    if [ "${#ALL_SSH_PORTS[@]}" -eq 0 ]; then
        ALL_SSH_PORTS=(22)
    fi
    SSH_PORT_ORIG="${ALL_SSH_PORTS[0]}"
    if [ "${#ALL_SSH_PORTS[@]}" -gt 1 ]; then
        log_warn "Multiple SSH ports configured: ${ALL_SSH_PORTS[*]} — managing '${SSH_PORT_ORIG}'; the others are removed from sshd and closed in the firewall once confirmed."
    fi
    SSH_PORT_FINAL="$SSH_PORT_ORIG"

    # Drop-ins only take effect reliably when the Include sits at the top of
    # sshd_config (sshd uses first-match-wins).
    DROPIN_SUPPORTED=0
    if [ -d "$SSHD_DROPIN_DIR" ]; then
        local inc_line first_line
        inc_line=$(grep -niE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$SSHD_CONFIG" 2>/dev/null | head -1 | cut -d: -f1)
        first_line=$(grep -nvE '^[[:space:]]*(#|$)' "$SSHD_CONFIG" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -n "$inc_line" ] && [ -n "$first_line" ] && [ "$inc_line" -le "$first_line" ]; then
            DROPIN_SUPPORTED=1
        elif [ -n "$inc_line" ]; then
            log_warn "Include of sshd_config.d is not the first directive in $SSHD_CONFIG — editing the main file instead."
        fi
    fi
}

sshd_effective() { # $1 keyword -> prints effective value
    local kw="$1" val
    val=$("$SSHD_BIN" -T 2>/dev/null | awk -v k="$kw" 'tolower($1)==tolower(k){print $2; exit}')
    # `sshd -T` only echoes the canonical name. Configs written with the
    # deprecated alias still take effect, so fall back to the canonical key
    # when the alias is not reported.
    if [ -z "$val" ] && [ "$kw" = "ChallengeResponseAuthentication" ]; then
        val=$("$SSHD_BIN" -T 2>/dev/null | awk 'tolower($1)=="kbdinteractiveauthentication"{print $2; exit}')
    fi
    printf '%s' "$val"
}

# Ports sshd actually listens on, sorted and space-separated. With socket
# activation sshd_config's Port is ignored because ssh.socket owns the port,
# so sshd -T would report the wrong number.
effective_ssh_ports() {
    local ports=""
    if [ "$SSH_SOCKET_MODE" -eq 1 ]; then
        ports=$(systemctl show ssh.socket -p Listen 2>/dev/null \
            | grep -oE ':[0-9]+ \(Stream\)' | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')
    fi
    if [ -z "$ports" ]; then
        ports=$("$SSHD_BIN" -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}' | sort -un | tr '\n' ' ')
    fi
    printf '%s' "${ports% }"
}

#=============================================================================
# Input collection (all user data is gathered BEFORE anything is changed)
#=============================================================================
ask_username() {
    while :; do
        prompt_read "Admin username to create: " NEW_USER
        if ! printf '%s' "$NEW_USER" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$'; then
            log_error "Invalid username '$NEW_USER'. Use lowercase letters, digits, '-' or '_' (max 32 chars)."
            continue
        fi
        if id -u "$NEW_USER" >/dev/null 2>&1; then
            local uid
            uid=$(id -u "$NEW_USER")
            if [ "$uid" -lt 1000 ]; then
                log_error "'$NEW_USER' is a system account (uid < 1000) and cannot be used."
                continue
            fi
            if confirm_yn "User '$NEW_USER' already exists. Reuse it (ensure sudo group + SSH key)?" "y"; then
                USER_EXISTS=1
                break
            fi
            continue
        fi
        USER_EXISTS=0
        break
    done
    log_ok "Admin user: $NEW_USER"
}

# H2: the local prompt enforces the exact same policy pwquality will enforce
# at chpasswd time (min 14 chars, ALL four character classes required).
prompt_valid_password() { # sets ADMIN_PW
    local pw1 pw2 cls
    while :; do
        prompt_read "Password for '$NEW_USER' (min 14 chars, ALL 4 character classes): " pw1 1
        printf '\n'
        prompt_read "Confirm password: " pw2 1
        printf '\n'
        if [ "$pw1" != "$pw2" ]; then
            log_error "Passwords do not match. Try again."
            continue
        fi
        if [ "${#pw1}" -lt 14 ]; then
            log_error "Password too short (minimum 14 characters). Try again."
            continue
        fi
        cls=0
        printf '%s' "$pw1" | grep -q '[0-9]'        && cls=$((cls + 1))
        printf '%s' "$pw1" | grep -q '[a-z]'        && cls=$((cls + 1))
        printf '%s' "$pw1" | grep -q '[A-Z]'        && cls=$((cls + 1))
        printf '%s' "$pw1" | grep -q '[^0-9A-Za-z]' && cls=$((cls + 1))
        if [ "$cls" -lt 4 ]; then
            log_error "Password must contain ALL of: digits, lowercase, uppercase, symbols (pwquality enforces each)."
            continue
        fi
        ADMIN_PW="$pw1"
        return 0
    done
}

verify_password_hash_strength() { # $1 user
    local hash
    hash=$(getent shadow "$1" 2>/dev/null | cut -d: -f2)
    # shellcheck disable=SC2016  # case patterns: literal '$' is intentional
    case "$hash" in
        '$y$'*|'$gy$'*|'$6$'*|'$5$'*|'$7$'*|'$2b$'*|'$2a$'*|'$2y$'*)
            log_ok "Password stored with a strong hash algorithm"
            ;;
        *)
            log_warn "Unexpected password hash prefix — verify /etc/shadow manually"
            ;;
    esac
}

ask_password() {
    if [ "$USER_EXISTS" -eq 1 ]; then
        local hash
        hash=$(getent shadow "$NEW_USER" 2>/dev/null | cut -d: -f2)
        case "$hash" in
            ""|"!"|"!!"|"*"|'!'*|'*'*)
                log_warn "User '$NEW_USER' exists WITHOUT a usable password (shadow field is empty or locked)."
                log_warn "Without a password, 'sudo' will not work for this user."
                if confirm_yn "Set a password for '$NEW_USER' now?" "y"; then
                    prompt_valid_password
                else
                    ADMIN_PW=""
                    log_warn "Continuing without setting a password for '$NEW_USER'."
                fi
                ;;
            *)
                log_info "Existing user kept as-is; its password is not modified."
                ADMIN_PW=""
                ;;
        esac
        return 0
    fi
    prompt_valid_password
    log_ok "Password accepted (validated locally; pwquality enforces the same policy)."
}

ask_ssh_key() {
    local line choice
    subheader "SSH login key"
    NO_KEY_AVAILABLE=0
    if [ -s "$ROOT_KEYS_FILE" ] && grep -Eq '^(ssh-|ecdsa-|sk-)' "$ROOT_KEYS_FILE"; then
        log_info "Key(s) currently authorized for root:"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in \#*) continue ;; esac
            ssh-keygen -lf /dev/stdin <<< "$line" 2>/dev/null | awk '{print "  - " $0}'
        done < "$ROOT_KEYS_FILE"
        if confirm_yn "Reuse these key(s) for the new admin user?" "y"; then
            SSH_KEYS_CONTENT=$(cat "$ROOT_KEYS_FILE")
        fi
    fi
    if [ -z "$SSH_KEYS_CONTENT" ]; then
        while :; do
            prompt_read "Paste an SSH public key (empty = other options): " line
            [ -z "$line" ] && break
            if validate_pubkey "$line"; then
                SSH_KEYS_CONTENT="$line"
                break
            fi
            log_error "That does not look like a valid public key (ssh-keygen rejected it). Try again."
        done
    fi
    # H1: with no key anywhere, disabling password auth would lock the user
    # out. Make the decision explicit instead of silently proceeding.
    if [ -z "$SSH_KEYS_CONTENT" ]; then
        while :; do
            printf '\n'
            log_warn "No SSH public key is available. Disabling password auth without a key WILL lock you out."
            printf '  [1] Re-read %s — finish uploading a key from another session first\n' "$ROOT_KEYS_FILE"
            printf '  [2] Skip — keep SSH password authentication ENABLED (re-run this script later)\n'
            prompt_read "Choose 1/2: " choice
            case "$choice" in
                1)
                    if [ -s "$ROOT_KEYS_FILE" ] && grep -Eq '^(ssh-|ecdsa-|sk-)' "$ROOT_KEYS_FILE"; then
                        SSH_KEYS_CONTENT=$(cat "$ROOT_KEYS_FILE")
                        log_ok "Found key(s) in $ROOT_KEYS_FILE — full SSH hardening will be applied"
                        break
                    fi
                    log_error "Still no key in $ROOT_KEYS_FILE. Upload it first, then choose 1 again."
                    ;;
                2)
                    NO_KEY_AVAILABLE=1
                    log_warn "OK — password authentication stays ENABLED. Add a key and re-run this script to finish hardening."
                    break
                    ;;
                *)
                    log_error "Please answer 1 or 2."
                    ;;
            esac
        done
    fi
}

ask_ssh_port() {
    local ans unpriv_start
    subheader "SSH port"
    log_info "Current SSH port: $SSH_PORT_ORIG"
    unpriv_start=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || printf '1024')
    while :; do
        prompt_read "SSH port — press Enter to keep $SSH_PORT_ORIG, or type a new port: " ans
        if [ -z "$ans" ]; then
            SSH_PORT_FINAL="$SSH_PORT_ORIG"
            SSH_PORT_CHANGED=0
            break
        fi
        if ! printf '%s' "$ans" | grep -Eq '^[0-9]+$' || [ "$ans" -lt 1 ] || [ "$ans" -gt 65535 ]; then
            log_error "Invalid port '$ans'."
            continue
        fi
        if [ "$ans" = "$SSH_PORT_ORIG" ]; then
            SSH_PORT_FINAL="$SSH_PORT_ORIG"
            SSH_PORT_CHANGED=0
            break
        fi
        if [ "$ans" -ge "$unpriv_start" ]; then
            log_warn "Ports >= $unpriv_start are 'unprivileged'; the community VPS audit marks such SSH ports as unsafe."
            log_warn "A non-standard port BELOW $unpriv_start (e.g. 222) passes the audit cleanly."
            confirm_yn "Use unprivileged port $ans anyway?" "n" || continue
        fi
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ":${ans}$"; then
            log_error "Port $ans is already in use by another service."
            continue
        fi
        SSH_PORT_FINAL="$ans"
        SSH_PORT_CHANGED=1
        break
    done
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        log_ok "SSH will move to port $SSH_PORT_FINAL (update your cloud provider's security group!)"
    else
        log_skip "SSH port stays at $SSH_PORT_FINAL"
    fi
}

ask_extra_ports() {
    local ans p seen
    subheader "Additional firewall ports"
    prompt_read "Additional TCP ports to allow (e.g. 80,443 — empty for none): " ans
    EXTRA_PORTS=()
    seen=""
    IFS=',' read -r -a _parts <<< "$ans"
    for p in ${_parts[@]+"${_parts[@]}"}; do
        p=$(printf '%s' "$p" | tr -d '[:space:]')
        [ -z "$p" ] && continue
        if ! printf '%s' "$p" | grep -Eq '^[0-9]+$' || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ] 2>/dev/null; then
            log_error "Ignoring invalid port '$p'."
            continue
        fi
        if [ "$p" = "$SSH_PORT_FINAL" ]; then
            log_warn "Port $p equals the SSH port; not adding it twice."
            continue
        fi
        case ",$seen," in *",$p,"*) continue ;; esac
        seen="${seen},${p}"
        EXTRA_PORTS+=("$p")
    done
    if [ "${#EXTRA_PORTS[@]}" -gt 0 ]; then
        log_ok "Extra ports to allow: ${EXTRA_PORTS[*]}"
    else
        log_info "No extra ports will be opened."
    fi
}

ask_toggles() {
    subheader "Optional actions"
    if confirm_yn "Run a full system package upgrade now (recommended, may take a while)?" "y"; then
        DO_UPGRADE=1
    else
        DO_UPGRADE=0
    fi
    if confirm_yn "Enable automatic security updates (unattended-upgrades / dnf-automatic)?" "y"; then
        DO_AUTOUPDATES=1
    else
        DO_AUTOUPDATES=0
    fi
}

collect_all_inputs() {
    subheader "User account"
    ask_username
    ask_password
    ask_ssh_key
    ask_ssh_port
    ask_extra_ports
    ask_toggles
}

#=============================================================================
# Plan display + final confirmation
#=============================================================================
show_plan() {
    local ip
    ip=$(ssh_address_hint)
    local pwauth_line socket_line
    if [ "$NO_KEY_AVAILABLE" -eq 1 ]; then
        pwauth_line="PasswordAuthentication stays ENABLED (no SSH key — your explicit choice)"
    else
        pwauth_line="PasswordAuthentication=no, ${KBD_KEYWORD}=no (key-only access)"
    fi
    if [ "$SSH_SOCKET_MODE" -eq 1 ] && [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        socket_line="ssh.socket activation detected -> will migrate to classic ssh.service"
    elif [ "$SSH_SOCKET_MODE" -eq 1 ]; then
        socket_line="ssh.socket activation detected (kept as-is; port unchanged)"
    else
        socket_line="$SSH_UNIT (classic mode)"
    fi
    printf '\n%s%s=====================================================================%s\n' "$BOLD" "$CYAN" "$NC"
    printf '%s%s UPCOMING CHANGES — PLEASE REVIEW CAREFULLY%s\n' "$BOLD" "$CYAN" "$NC"
    printf '%s%s=====================================================================%s\n' "$BOLD" "$CYAN" "$NC"
    local upgrade_line autoupdate_line port_line
    if [ "$DO_UPGRADE" -eq 1 ]; then
        upgrade_line="ensure base packages, then run a FULL system upgrade"
    else
        upgrade_line="ensure base packages (upgrade skipped by user choice)"
    fi
    if [ "$DO_AUTOUPDATES" -eq 1 ]; then
        autoupdate_line="enabled"
    else
        autoupdate_line="disabled (user choice)"
    fi
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        port_line="SSH MOVES TO PORT ${SSH_PORT_FINAL}. You MUST open TCP ${SSH_PORT_FINAL} in your cloud provider's security group or you WILL lose access."
    else
        port_line="SSH port stays at ${SSH_PORT_FINAL}."
    fi
    cat <<EOF
 Detected system : $DISTRO_PRETTY
 Server address  : ${ip:-<unresolved>}   (SSH test hint, verify yourself too)
 SSH service     : ${socket_line}
 Execution log   : $RESULT_FILE

 Planned actions:
   1.  Package management: ${upgrade_line}
   2.  Password policy: pwquality minlen=14 + ALL four character classes required
   3.  sudo audit logging: every sudo command logged to /var/log/sudo.log
   4.  Admin user: $NEW_USER (sudo/wheel group, bash shell, SSH key installed)
   5.  Permissions: /etc/passwd=644, /etc/shadow=600, ~/.ssh=700, authorized_keys=600
   6.  Firewall ($FW_KIND): DEFAULT DENY incoming; allow SSH${EXTRA_PORTS[*]:+ + extra ports ${EXTRA_PORTS[*]}}
   7.  SSH hardening: PermitRootLogin=no, port ${SSH_PORT_FINAL},
       ${pwauth_line}
   8.  fail2ban: sshd jail enabled=true, mode=aggressive, port=${SSH_PORT_FINAL}
       (bantime=3600s, findtime=600s, maxretry=5)
   9.  Automatic security updates: ${autoupdate_line}
   10. Time synchronization: ensured active
   11. Insecure listening port scan (report only)
   12. Final verification report of the effective configuration
EOF
    printf '\n%s%s!!! HIGH-RISK / DESTRUCTIVE OPERATIONS !!!%s\n' "$BOLD" "$RED" "$NC"
    cat <<EOF
 * ROOT SSH LOGIN WILL BE PERMANENTLY DISABLED (PermitRootLogin=no).
$([ "$NO_KEY_AVAILABLE" -eq 1 ] || printf ' * SSH PASSWORD LOGIN WILL BE DISABLED — only key-based access remains.\n   Verify your key works BEFORE confirming, or you can lock yourself out.\n')
 * ${port_line}
 * The firewall will DENY ALL incoming traffic except SSH and the extra
   ports listed above, and this applies after every reboot.
 * fail2ban will BAN IP addresses with repeated failed SSH logins —
   that can include your own IP if you mistype your key/password repeatedly.
 * A full system upgrade may install a new kernel: A REBOOT MAY BE REQUIRED.
 * Edited files are backed up once under $BK_DIR before modification.
 * The script is idempotent — re-running it is always safe.
 * SSH changes arm a 15-minute watchdog: if they are never confirmed at the
   verification gate (e.g. the session dies), they are rolled back
   automatically.

 >>> KEEP THIS SSH SESSION OPEN UNTIL THE SCRIPT HAS FINISHED. <<<
 The script will pause after applying SSH changes so you can verify a new
 login from a second terminal; if it fails, the change is rolled back.
EOF
    printf '%s[!]%s %s\n' "$YELLOW" "$NC" "If anything above is unacceptable, abort now — nothing has been changed yet."
}

final_confirm() {
    local ans
    printf '\n'
    prompt_read "Type 'yes' to APPLY all planned changes (anything else aborts): " ans
    [ "$ans" = "yes" ]
}

#=============================================================================
# Task 1 — base packages + system upgrade
#=============================================================================
task_system_update() {
    local rc=0 cnt=0

    if [ "$FAMILY" = "debian" ]; then
        refresh_pkg_index || true
        install_pkgs sudo openssh-server ufw iproute2 libpam-pwquality fail2ban python3-systemd
        rc=$?
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
            log_ok "Base packages present (ufw, fail2ban, pwquality, ...)"
        else
            log_error "Some base packages failed to install — review the errors above and re-run this script"
        fi
        if [ "$DO_UPGRADE" -ne 1 ]; then
            log_skip "System upgrade disabled by user input"
            return 0
        fi
        wait_for_apt_lock || true
        ensure_dpkg_recovered || true
        cnt=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true)
        if [ "${cnt:-0}" -eq 0 ]; then
            log_skip "System already fully upgraded (0 pending packages)"
            return 0
        fi
        log_info "Upgrading $cnt package(s)..."
        if DEBIAN_FRONTEND=noninteractive apt-get -y \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold upgrade; then
            log_ok "System upgrade complete ($cnt packages)"
        else
            log_error "apt-get upgrade failed — check 'apt-get -f install' manually"
        fi
    else
        refresh_pkg_index || true
        install_pkgs sudo openssh-server firewalld iproute pwquality
        rc=$?
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
            log_ok "Base packages present (firewalld, pwquality, ...)"
        else
            log_error "Some base packages failed to install — review the errors above and re-run this script"
        fi
        if [ "$DO_UPGRADE" -ne 1 ]; then
            log_skip "System upgrade disabled by user input"
            return 0
        fi
        log_info "Running $PKG upgrade (this can take a while)..."
        if "$PKG" -y upgrade; then
            log_ok "System upgrade complete"
        else
            log_error "$PKG upgrade failed (EOL mirrors may be the cause on EL7)"
        fi
    fi
}

#=============================================================================
# Task 2 — password quality policy
#=============================================================================
ensure_pwquality_line() { # $1 key, $2 value
    local key="$1" val="$2"
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*${val}[[:space:]]*$" "$PWQUALITY_CONF"; then
        log_skip "pwquality ${key} already set to ${val}"
        return 0
    fi
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "$PWQUALITY_CONF"; then
        sed -ri "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$PWQUALITY_CONF"
        log_ok "pwquality ${key} set to ${val}"
    else
        printf '%s = %s\n' "$key" "$val" >> "$PWQUALITY_CONF"
        log_ok "pwquality ${key} appended (${val})"
    fi
}

task_password_policy() {
    if [ ! -f "$PWQUALITY_CONF" ]; then
        log_error "$PWQUALITY_CONF missing — libpam-pwquality is not installed (see the package errors above)"
        return 0
    fi
    backup_file "$PWQUALITY_CONF"
    ensure_pwquality_line minlen 14
    ensure_pwquality_line dcredit -1
    ensure_pwquality_line ucredit -1
    ensure_pwquality_line lcredit -1
    ensure_pwquality_line ocredit -1
}

#=============================================================================
# Task 3 — sudo audit logging
#=============================================================================
task_sudo_logging() {
    local line='Defaults logfile="/var/log/sudo.log"'
    local tmp n

    if [ -f "$SUDOERS_LOGGING_DROPIN" ] && grep -qxF "$line" "$SUDOERS_LOGGING_DROPIN"; then
        log_skip "sudo logging already configured ($SUDOERS_LOGGING_DROPIN)"
        return 0
    fi
    if grep -q '^Defaults.*logfile' "$SUDOERS_FILE"; then
        log_skip "sudo logging already configured in $SUDOERS_FILE"
        return 0
    fi

    if grep -Eq '^[@#]includedir[[:space:]]+/etc/sudoers\.d' "$SUDOERS_FILE"; then
        # Prefer a validated drop-in: smaller diff, trivially reversible.
        tmp=$(mktemp) || return 0
        printf '%s\n' "$line" > "$tmp"
        if ! visudo -cf "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"
            log_error "sudoers drop-in failed validation — nothing changed"
            return 0
        fi
        install -m 0440 "$tmp" "$SUDOERS_LOGGING_DROPIN"
        rm -f "$tmp"
        if visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
            log_ok "sudo commands are now logged to /var/log/sudo.log ($SUDOERS_LOGGING_DROPIN)"
        else
            rm -f "$SUDOERS_LOGGING_DROPIN"
            log_error "aggregate sudoers validation failed — drop-in removed"
        fi
    else
        # Legacy fallback: no includedir — edit the main file with validation.
        backup_file "$SUDOERS_FILE"
        tmp=$(mktemp) || return 0
        n=$(grep -n '^Defaults' "$SUDOERS_FILE" | tail -1 | cut -d: -f1)
        if [ -n "$n" ]; then
            sed "${n}a${line}" "$SUDOERS_FILE" > "$tmp"
        else
            { printf '%s\n' "$line"; cat "$SUDOERS_FILE"; } > "$tmp"
        fi
        if visudo -cf "$tmp" >/dev/null 2>&1; then
            install -m 0440 "$tmp" "$SUDOERS_FILE"
            rm -f "$tmp"
            log_ok "sudo commands are now logged to /var/log/sudo.log"
        else
            rm -f "$tmp"
            log_error "sudoers validation failed — $SUDOERS_FILE left unchanged"
        fi
    fi
}

#=============================================================================
# Task 4 — admin user, sudo group, password, SSH keys
#=============================================================================
install_user_keys() { # $1 user, $2 keys content
    local user="$1" keys="$2" home group line
    home=$(getent passwd "$user" | cut -d: -f6)
    group=$(id -gn "$user")
    [ -n "$home" ] || return 0
    install -d -m 700 -o "$user" -g "$group" "$home/.ssh"
    local ak="$home/.ssh/authorized_keys"
    [ -f "$ak" ] || install -m 600 -o "$user" -g "$group" /dev/null "$ak"
    local added=0 present=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        if grep -qxF "$line" "$ak"; then
            present=$((present + 1))
        else
            if printf '%s\n' "$line" >> "$ak"; then
                added=$((added + 1))
            else
                log_error "Failed to write authorized_keys for $user ($ak)"
                return 1
            fi
        fi
    done <<< "$keys"
    chown "$user:$group" "$ak"
    chmod 600 "$ak"
    if [ "$added" -gt 0 ]; then
        log_ok "Installed $added SSH key(s) for $user ($present already present)"
    else
        log_skip "SSH keys for $user already installed"
    fi
}

task_admin_user() {
    local group="$ADMIN_GROUP"

    if [ "$USER_EXISTS" -eq 1 ]; then
        log_skip "User $NEW_USER already exists — reusing it"
    else
        if useradd -m -s /bin/bash "$NEW_USER"; then
            log_ok "User $NEW_USER created (home=/home/$NEW_USER, shell=/bin/bash)"
        else
            log_error "useradd failed for $NEW_USER — cannot continue with user tasks"
            return 0
        fi
    fi

    # H2: the password is what makes sudo usable — setting it is mandatory.
    # chpasswd goes through PAM, so pwquality re-checks it here; retry with a
    # new prompt instead of failing silently. If it still fails, abort BEFORE
    # SSH hardening so the box can never end up keyless AND passwordless.
    if [ -n "$ADMIN_PW" ]; then
        local attempt=1 pw_ok=0
        while [ "$attempt" -le 3 ]; do
            if printf '%s:%s\n' "$NEW_USER" "$ADMIN_PW" | chpasswd; then
                pw_ok=1
                break
            fi
            log_error "Password rejected by PAM (attempt $attempt/3)."
            if [ "$attempt" -lt 3 ]; then
                log_info "Choose a different password (min 14 chars, all 4 classes, avoid dictionary words)."
                prompt_valid_password
            fi
            attempt=$((attempt + 1))
        done
        if [ "$pw_ok" -eq 1 ]; then
            log_ok "Password set for $NEW_USER"
            verify_password_hash_strength "$NEW_USER"
        else
            die "Could not set a password for $NEW_USER after 3 attempts. Aborting BEFORE SSH hardening to avoid a lockout. The user exists but has no password; re-run this script to set one."
        fi
    fi

    # Valid shell is required by the security audit.
    local shell
    shell=$(getent passwd "$NEW_USER" | cut -d: -f7)
    if [ "$shell" = "/usr/sbin/nologin" ] || [ "$shell" = "/bin/false" ]; then
        usermod -s /bin/bash "$NEW_USER"
        log_ok "Shell for $NEW_USER changed to /bin/bash (was $shell)"
    else
        log_skip "Shell for $NEW_USER already valid ($shell)"
    fi

    if id -nG "$NEW_USER" | tr ' ' '\n' | grep -qx "$group"; then
        log_skip "$NEW_USER already member of '$group'"
    else
        if usermod -aG "$group" "$NEW_USER"; then
            log_ok "$NEW_USER added to '$group' (sudo access)"
        else
            log_error "Failed to add $NEW_USER to '$group'"
        fi
    fi

    if [ -n "$SSH_KEYS_CONTENT" ]; then
        install_user_keys "$NEW_USER" "$SSH_KEYS_CONTENT"
    else
        log_skip "No SSH key provided for $NEW_USER"
    fi

    # Keep root's authorized_keys present: root login stays disabled, but the
    # community audit checks for the file when run via sudo.
    if [ -s "$ROOT_KEYS_FILE" ]; then
        log_skip "Root authorized_keys already exists (root login remains disabled)"
    elif [ -n "$SSH_KEYS_CONTENT" ]; then
        install -d -m 700 /root/.ssh
        printf '%s\n' "$SSH_KEYS_CONTENT" > "$ROOT_KEYS_FILE"
        chmod 600 "$ROOT_KEYS_FILE"
        log_info "Seeded $ROOT_KEYS_FILE for audit compatibility (root login stays disabled)"
    fi
}

#=============================================================================
# Task 5 — file permissions
#=============================================================================
ensure_perm() { # $1 path, $2 mode
    local f="$1" want="$2" cur
    if [ ! -e "$f" ]; then
        log_error "$f does not exist"
        return 0
    fi
    cur=$(stat -c '%a' "$f")
    if [ "$cur" = "$want" ]; then
        log_skip "$f already has mode $want"
    else
        chmod "$want" "$f" && log_ok "$f permissions changed $cur -> $want"
    fi
}

task_permissions() {
    ensure_perm /etc/passwd 644
    ensure_perm /etc/shadow 600
    if [ -n "$NEW_USER" ] && [ -d "/home/$NEW_USER/.ssh" ]; then
        ensure_perm "/home/$NEW_USER/.ssh" 700
        if [ -f "/home/$NEW_USER/.ssh/authorized_keys" ]; then
            ensure_perm "/home/$NEW_USER/.ssh/authorized_keys" 600
        else
            log_skip "/home/$NEW_USER/.ssh/authorized_keys not present (no key installed)"
        fi
    fi
    chown root:root /etc/passwd /etc/shadow 2>/dev/null || true
}

#=============================================================================
# Task 6 — firewall (ufw on Debian/Ubuntu, firewalld on RHEL family)
#=============================================================================
fw_allow_port() { # $1 port — allows tcp/$1; returns 1 on failure (never silent)
    local port="$1"
    if [ "$FW_KIND" = "ufw" ]; then
        if ufw status 2>/dev/null | grep -q "^${port}/tcp"; then
            log_skip "ufw rule for ${port}/tcp already present"
            return 0
        fi
        if ufw allow "${port}/tcp" >/dev/null 2>&1; then
            log_ok "ufw: allowed incoming tcp/$port"
            return 0
        fi
        log_error "ufw failed to allow tcp/$port — do NOT enable default-deny before this is fixed"
        return 1
    fi
    if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
        log_skip "firewalld rule for ${port}/tcp already present"
        return 0
    fi
    if firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 \
        && firewall-cmd --reload >/dev/null 2>&1; then
        log_ok "firewalld: allowed incoming tcp/$port"
        return 0
    fi
    log_error "firewalld failed to allow tcp/$port"
    return 1
}

# Close a single port. Used on paths where the 'ssh' service must NOT be
# touched (reclaims and rollbacks — the original port may still use it).
fw_close_port() { # $1 port
    local port="$1"
    if [ "$FW_KIND" = "ufw" ]; then
        if ufw status 2>/dev/null | grep -q "^${port}/tcp"; then
            if ufw delete allow "${port}/tcp" >/dev/null 2>&1; then
                log_ok "ufw: removed incoming tcp/$port"
            else
                log_warn "ufw: failed to remove tcp/$port (left open)"
            fi
        else
            log_skip "ufw: tcp/$port not open"
        fi
    else
        if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            if firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1; then
                firewall-cmd --reload >/dev/null 2>&1
                log_ok "firewalld: removed incoming tcp/$port"
            else
                log_warn "firewalld: failed to remove tcp/$port (left open)"
            fi
        else
            log_skip "firewalld: tcp/$port not open"
        fi
    fi
}

# Called only AFTER the new SSH port was verified: close an old port and, on
# firewalld, the 'ssh' service that shipped pre-opened on port 22 (only when
# 22 is no longer the managed port).
fw_close_old_ssh() { # $1 old port
    local port="$1"
    fw_close_port "$port"
    if [ "$FW_KIND" != "ufw" ] && [ "$SSH_PORT_FINAL" -ne 22 ] \
        && firewall-cmd --query-service=ssh >/dev/null 2>&1; then
        if firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1; then
            firewall-cmd --reload >/dev/null 2>&1
            log_ok "firewalld: removed 'ssh' service (old port closed)"
        else
            log_warn "firewalld: failed to remove 'ssh' service (old port may stay open)"
        fi
    fi
}

task_firewall() {
    local p
    local ports_to_allow=()
    ports_to_allow+=("${ALL_SSH_PORTS[@]}")
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        ports_to_allow+=("$SSH_PORT_FINAL")
    fi
    ports_to_allow+=("${EXTRA_PORTS[@]+"${EXTRA_PORTS[@]}"}")

    if [ "$FW_KIND" = "ufw" ]; then
        if ! cmd_exists ufw; then
            log_error "ufw not found — ufw is not installed (see the package errors above)"
            return 0
        fi
        # Safety: allow the SSH ports BEFORE enabling default-deny. A failure
        # here is fatal for this task — never deny-by-default with SSH closed.
        for p in "${ports_to_allow[@]}"; do
            if ! fw_allow_port "$p"; then
                log_error "Refusing to enable default-deny: tcp/$p could not be allowed"
                return 0
            fi
        done
        if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
            log_info "Previous SSH port(s) ${ALL_SSH_PORTS[*]} stay allowed until the new port is verified"
        fi
        if ufw status verbose 2>/dev/null | grep 'Default:' | grep -q 'deny (incoming)'; then
            log_skip "ufw default incoming policy already 'deny'"
        else
            ufw default deny incoming >/dev/null 2>&1 && log_ok "ufw default incoming policy set to deny"
        fi
        if ufw status verbose 2>/dev/null | grep 'Default:' | grep -q 'allow (outgoing)'; then
            log_skip "ufw default outgoing policy already 'allow'"
        else
            ufw default allow outgoing >/dev/null 2>&1 && log_ok "ufw default outgoing policy set to allow"
        fi
        if ufw status 2>/dev/null | grep -qw active; then
            log_skip "ufw is already active"
        else
            if ufw --force enable >/dev/null 2>&1; then
                log_ok "ufw enabled (persists across reboots)"
            else
                log_error "Failed to enable ufw"
            fi
        fi
        if ufw status 2>/dev/null | grep -qw active; then
            log_ok "Verified: ufw is active with default-deny incoming"
        else
            log_error "Verified: ufw is NOT active"
        fi
    else
        if ! cmd_exists firewall-cmd; then
            log_error "firewalld not found — install it and re-run this script"
            return 0
        fi
        local firewalld_was_active=0
        if systemctl is-active --quiet firewalld; then
            firewalld_was_active=1
            log_skip "firewalld already running"
        fi
        if [ "$firewalld_was_active" -eq 0 ]; then
            # H4: pre-stage the permanent rules BEFORE first start. Starting
            # firewalld applies its default zone immediately; if that zone has
            # no 'ssh' service, the running session dies mid-script.
            if ! cmd_exists firewall-offline-cmd; then
                log_error "firewalld is inactive and firewall-offline-cmd is missing — refusing to start it (would risk cutting SSH)"
                return 0
            fi
            for p in "${ports_to_allow[@]}"; do
                if firewall-offline-cmd --query-port="${p}/tcp" >/dev/null 2>&1; then
                    log_skip "firewalld (offline): tcp/$p already in permanent config"
                elif firewall-offline-cmd --add-port="${p}/tcp" >/dev/null 2>&1; then
                    log_ok "firewalld (offline): pre-allowed tcp/$p in permanent config"
                else
                    log_error "firewalld (offline): could not pre-allow tcp/$p — NOT starting firewalld"
                    return 0
                fi
            done
            if ! systemctl enable --now firewalld >/dev/null 2>&1; then
                log_error "Failed to enable/start firewalld"
                return 0
            fi
            log_ok "firewalld enabled and started (SSH rules were pre-staged offline)"
            for p in "${ports_to_allow[@]}"; do
                firewall-cmd --query-port="${p}/tcp" >/dev/null 2>&1 \
                    || log_error "firewalld is running but tcp/$p is NOT open — verify before continuing"
            done
        fi
        if ! firewall-cmd --state >/dev/null 2>&1; then
            log_error "firewalld is not running"
            return 0
        fi
        log_ok "Verified: firewalld is active"
        for p in "${ports_to_allow[@]}"; do
            fw_allow_port "$p" || log_error "tcp/$p could not be allowed — verify manually"
        done
        if [ "$(firewall-cmd --get-default-zone 2>/dev/null)" = "public" ]; then
            log_skip "firewalld default zone already 'public' (incoming default-deny)"
        else
            firewall-cmd --set-default-zone=public >/dev/null 2>&1 && log_ok "firewalld default zone set to 'public' (incoming default-deny)"
        fi
    fi
}

#=============================================================================
# Task 7 — SSH hardening (+ optional port change, with watchdog & rollback)
#=============================================================================
# Single source of truth for the hardening targets. Used by the drop-in
# builder, the idempotency check, and the final verification.
hardening_targets() {
    cat <<EOF
Port:${SSH_PORT_FINAL}
PermitRootLogin:no
PermitEmptyPasswords:no
MaxAuthTries:4
LoginGraceTime:30
UsePAM:yes
EOF
    if [ "$NO_KEY_AVAILABLE" -ne 1 ]; then
        printf 'PasswordAuthentication:no\n'
        printf '%s:no\n' "$KBD_KEYWORD"
    fi
}

build_sshd_block() {
    printf '# BEGIN managed by vps-setup.sh v%s on %s\n' "$SCRIPT_VERSION" "$(date '+%F %T')"
    hardening_targets | awk -F: '{printf "%s %s\n", $1, $2}'
    printf 'ClientAliveInterval 300\nClientAliveCountMax 2\nX11Forwarding no\nUseDNS no\n'
    printf '# END managed by vps-setup.sh\n'
}

ssh_harden_already_applied() {
    local kv want got ports
    # Port is cumulative: each declared port adds another listening socket.
    # Require exactly the managed port so a leftover directive cannot hide.
    ports=$(effective_ssh_ports)
    [ "$ports" = "$SSH_PORT_FINAL" ] || return 1
    while IFS=: read -r kv want; do
        [ -n "$kv" ] || continue
        got=$(sshd_effective "$kv")
        [ "$got" = "$want" ] || return 1
    done < <(hardening_targets)
    return 0
}

# Port is a cumulative directive in sshd_config: every Port line is listened
# on. A leftover Port in the main file or in another drop-in would keep the
# old port open even though our drop-in only declares the new one. Back up
# and strip those lines, recording each file so rollback can undo it.
clear_foreign_ssh_ports() {
    local f found=0
    for f in "$SSHD_CONFIG" "$SSHD_DROPIN_DIR"/*.conf; do
        [ -f "$f" ] || continue
        [ "$f" = "$SSHD_DROPIN" ] && continue
        grep -qiE '^[[:space:]]*Port[[:space:]]' "$f" || continue
        backup_file "$f"
        printf '%s\n' "$f" >> "$PORT_STRIP_LIST"
        if ! sed -ri '/^[[:space:]]*Port[[:space:]]/Id' "$f"; then
            log_error "Could not remove Port directives from $f — restoring the files"
            restore_stripped_port_files
            return 1
        fi
        log_ok "Removed active Port directive(s) from $f (Port is cumulative in sshd_config)"
        found=1
    done
    [ "$found" -eq 1 ] || return 0
    "$SSHD_BIN" -t 2>/dev/null && return 0
    log_error "sshd -t failed after removing Port directives — restoring the original files"
    restore_stripped_port_files
    return 1
}

restore_stripped_port_files() {
    local f bak
    [ -f "$PORT_STRIP_LIST" ] || return 0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        bak="${BK_DIR}/$(printf '%s' "$f" | tr '/' '_').bak"
        [ -f "$bak" ] && cp -a "$bak" "$f"
    done < "$PORT_STRIP_LIST"
    rm -f "$PORT_STRIP_LIST"
}

# H3: in socket-activation mode sshd binds the fd handed over by systemd and
# ignores its own Port directive — migrate to the classic unit first.
migrate_off_socket_activation() {
    log_info "Detected systemd socket activation (ssh.socket) — migrating to classic ssh.service mode..."
    if ! systemctl disable --now ssh.socket >/dev/null 2>&1; then
        log_warn "Could not disable ssh.socket"
    fi
    if ! systemctl enable --now ssh.service >/dev/null 2>&1; then
        log_error "Could not enable ssh.service"
        return 1
    fi
    SSH_SOCKET_MODE=0
    SSH_UNIT="ssh.service"
    log_ok "SSH migrated to classic ssh.service mode (existing sessions are unaffected)"
    return 0
}

# SELinux: allow sshd to bind the new port (required on enforcing RHEL family).
selinux_prepare_port() {
    local port="$1"
    cmd_exists getenforce || return 0
    [ "$(getenforce 2>/dev/null)" = "Enforcing" ] || return 0
    log_info "SELinux is enforcing — preparing ssh_port_t for port $port"
    if ! cmd_exists semanage; then
        log_info "Installing SELinux policy tools (policycoreutils)..."
        if [ "$PKG" = "yum" ]; then
            "$PKG" install -y policycoreutils-python >/dev/null 2>&1 || { log_error "Could not install policycoreutils-python"; return 1; }
        else
            "$PKG" install -y policycoreutils-python-utils >/dev/null 2>&1 || { log_error "Could not install policycoreutils-python-utils"; return 1; }
        fi
    fi
    if semanage port -l 2>/dev/null | grep '^ssh_port_t' | grep -qw "$port"; then
        log_skip "SELinux already allows sshd on port $port"
        return 0
    fi
    if semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null \
        || semanage port -m -t ssh_port_t -p tcp "$port" 2>/dev/null; then
        log_ok "SELinux: sshd may bind port $port"
        return 0
    fi
    log_error "semanage could not add port $port to ssh_port_t"
    return 1
}

rollback_ssh_hardening() {
    log_warn "Rolling back SSH configuration to the previous state..."
    local abandoned="$SSH_PORT_FINAL"
    if [ "$DROPIN_SUPPORTED" -eq 1 ]; then
        if [ -f "${SSHD_DROPIN}.pre-vps-setup" ]; then
            mv -f "${SSHD_DROPIN}.pre-vps-setup" "$SSHD_DROPIN"
        else
            rm -f "$SSHD_DROPIN"
        fi
    else
        local bak
        bak="${BK_DIR}/$(printf '%s' "$SSHD_CONFIG" | tr '/' '_').bak"
        [ -f "$bak" ] && cp -a "$bak" "$SSHD_CONFIG"
    fi
    # Undo the Port stripping done by clear_foreign_ssh_ports: without this,
    # a rollback could leave sshd on the default port instead of the original.
    restore_stripped_port_files
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        if [ "$abandoned" != "$SSH_PORT_ORIG" ]; then
            fw_close_port "$abandoned"    # M4: reclaim the never-verified port
        fi
        SSH_PORT_FINAL="$SSH_PORT_ORIG"
        if [ "$FW_KIND" = "ufw" ]; then
            ufw allow "${SSH_PORT_ORIG}/tcp" >/dev/null 2>&1
        else
            firewall-cmd --permanent --add-port="${SSH_PORT_ORIG}/tcp" >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
        fi
        log_ok "Firewall re-allows original SSH port $SSH_PORT_ORIG"
    fi
    if "$SSHD_BIN" -t 2>/dev/null; then
        systemctl restart "$SSH_UNIT" && log_ok "Original SSH configuration restored ($SSH_UNIT restarted on port $SSH_PORT_FINAL)"
    else
        log_error "Restored config still fails 'sshd -t' — inspect $BK_DIR manually!"
    fi
}

# Dead-man switch: a transient systemd timer runs a self-contained rollback
# script unless the user confirms at the gate. The script shares the flock:
# while the main run is alive it just re-arms, so it can never fight with it.
dms_arm() {
    local path ts
    ts=$(date '+%Y%m%d-%H%M%S')
    path="${BASE_DIR}/rollback-ssh-${ts}.sh"
    rm -f "$CONFIRM_FLAG"    # stale marker from a previous run must not mute this run's watchdog
    {
        printf '#!/usr/bin/env bash\n'
        printf '# Auto-generated rollback (dead-man switch) — vps-setup.sh\n'
        printf 'set -u\n'
        printf 'UNIT=%q\n' "$SSH_UNIT"
        printf 'SSHD_BIN=%q\n' "$SSHD_BIN"
        printf 'DROPIN=%q\n' "$SSHD_DROPIN"
        printf 'MAINCONF=%q\n' "$SSHD_CONFIG"
        printf 'DROPIN_SUPPORTED=%d\n' "$DROPIN_SUPPORTED"
        printf 'PORT_STRIP_LIST=%q\n' "$PORT_STRIP_LIST"
        printf 'BAK_DIR=%q\n' "$BK_DIR"
        printf 'LOCK=%q\n' "$LOCK_FILE"
        printf 'CONFIRM_FLAG=%q\n' "$CONFIRM_FLAG"
        printf 'FW_KIND=%q\n' "$FW_KIND"
        printf 'NEW_PORT=%q\n' "$SSH_PORT_FINAL"
        printf 'ORIG_PORT=%q\n' "$SSH_PORT_ORIG"
        printf 'PORT_CHANGED=%d\n' "$SSH_PORT_CHANGED"
        printf 'DMS_BASE=%q\n' "$DMS_UNIT_BASE"
        cat <<'DMS_BODY'
# A confirmed (or already manually rolled back) run leaves this marker: any
# re-armed timer that fires later must no-op instead of reverting live config.
# The marker is deliberately NOT removed here — several re-armed timers may
# be pending, and each must see it. Only the next dms_arm clears it.
if [ -e "$CONFIRM_FLAG" ]; then
    rm -f "$0"
    logger -t vps-setup-dms "changes already confirmed/resolved — nothing to do"
    exit 0
fi
exec 9>>"$LOCK" || exit 0
if ! flock -n 9; then
    logger -t vps-setup-dms "main script still active; re-arming rollback in 10 minutes"
    systemd-run --on-active=10min --unit="${DMS_BASE}-rearm-$(date +%s)" --quiet bash "$0" >/dev/null 2>&1
    exit 0
fi
logger -t vps-setup-dms "confirmation timeout — rolling back SSH configuration"
if [ "$DROPIN_SUPPORTED" = "1" ]; then
    if [ -f "${DROPIN}.pre-vps-setup" ]; then
        mv -f "${DROPIN}.pre-vps-setup" "$DROPIN"
    else
        rm -f "$DROPIN"
    fi
else
    bak="${BAK_DIR}/$(printf '%s' "$MAINCONF" | tr '/' '_').bak"
    [ -f "$bak" ] && cp -a "$bak" "$MAINCONF"
fi
# Restore Port directives stripped by clear_foreign_ssh_ports, otherwise the
# original port may be gone from the main config after the rollback.
if [ -f "$PORT_STRIP_LIST" ]; then
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        bak="${BAK_DIR}/$(printf '%s' "$f" | tr '/' '_').bak"
        [ -f "$bak" ] && cp -a "$bak" "$f"
    done < "$PORT_STRIP_LIST"
    rm -f "$PORT_STRIP_LIST"
fi
if [ "$PORT_CHANGED" = "1" ]; then
    if [ "$FW_KIND" = "ufw" ]; then
        ufw delete allow "${NEW_PORT}/tcp" >/dev/null 2>&1
        ufw allow "${ORIG_PORT}/tcp" >/dev/null 2>&1
    else
        firewall-cmd --permanent --remove-port="${NEW_PORT}/tcp" >/dev/null 2>&1
        firewall-cmd --permanent --add-port="${ORIG_PORT}/tcp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
fi
if "$SSHD_BIN" -t 2>/dev/null; then
    systemctl restart "$UNIT"
    logger -t vps-setup-dms "rollback complete; sshd restarted on port $ORIG_PORT"
else
    logger -t vps-setup-dms "ERROR: restored config still fails sshd -t; inspect $BAK_DIR manually"
fi
rm -f "$0"
DMS_BODY
    } > "$path"
    chmod 700 "$path"
    DMS_SCRIPT="$path"
    DMS_UNIT="${DMS_UNIT_BASE}-${ts}"
    if systemd-run --on-active=15min --unit="$DMS_UNIT" --quiet bash "$path" >/dev/null 2>&1; then
        log_info "Dead-man switch armed: SSH changes auto-rollback in 15 min unless confirmed"
    else
        DMS_UNIT=""
        log_warn "Could not arm the dead-man switch (systemd-run failed) — the confirmation gate is the only safety net"
    fi
}

dms_disarm() {
    [ -n "$DMS_UNIT" ] || return 0
    # Marker first: any re-armed timer that fires later sees it and removes
    # itself instead of reverting confirmed configuration.
    : > "$CONFIRM_FLAG"
    systemctl stop "${DMS_UNIT}.timer" >/dev/null 2>&1
    systemctl stop "${DMS_UNIT}.service" >/dev/null 2>&1
    [ -n "$DMS_SCRIPT" ] && rm -f "$DMS_SCRIPT"
    DMS_UNIT=""
    DMS_SCRIPT=""
}

ssh_confirm_gate() {
    local ip addr ip_line="" ans rc remaining deadline
    ip=$(public_ip_hint)
    if [ -n "$ip" ] && is_private_address "$ip"; then
        addr="<your-server-public-ip>"
        ip_line=$'\n NOTE: this host reports the private address '"$ip"$' (NAT/EIP setup).\n Use the public IP from your cloud console.'
    else
        addr="${ip:-<your-server-public-ip>}"
    fi
    printf '\n%s%sACTION REQUIRED — VERIFY ACCESS NOW%s\n' "$BOLD" "$YELLOW" "$NC"
    cat <<EOF
 SSH has been reconfigured. From a NEW terminal, verify you can log in:

     ssh -p ${SSH_PORT_FINAL} ${NEW_USER}@${addr}${ip_line}

 Then inside that session run:  sudo -v   (must succeed)
 $( [ "$SSH_PORT_CHANGED" -eq 1 ] && printf "NOTE: if this fails, also check that TCP %s is open in your cloud provider's security group." "$SSH_PORT_FINAL" )

 Type 'ok' to keep the new configuration, or 'rollback' to restore the
 previous SSH settings.
 If this session dies before you answer (Ctrl-C, network loss) or no answer
 arrives within $((GATE_TIMEOUT / 60)) minutes, the previous SSH settings are
 restored automatically.
EOF
    deadline=$((SECONDS + GATE_TIMEOUT))
    while :; do
        remaining=$((deadline - SECONDS))
        if [ "$remaining" -le 0 ]; then
            printf '\n'
            log_warn "No confirmation within $((GATE_TIMEOUT / 60)) minutes — rolling back SSH changes"
            rollback_ssh_hardening
            return 1
        fi
        ans=""
        prompt_read_timeout "Verify and type ok / rollback: " ans "$remaining"
        rc=$?
        if [ "$rc" -gt 128 ]; then
            continue
        fi
        if [ "$rc" -ne 0 ]; then
            printf '\n'
            log_warn "Confirmation input closed (session lost) — rolling back SSH changes"
            rollback_ssh_hardening
            return 1
        fi
        case "$ans" in
            ok|OK)
                log_ok "SSH configuration confirmed by user"
                return 0
                ;;
            rollback|ROLLBACK)
                rollback_ssh_hardening
                return 1
                ;;
            *)
                log_error "Please type 'ok' or 'rollback'."
                ;;
        esac
    done
}

task_ssh_hardening() {
    local tmp clean wanted_port="$SSH_PORT_FINAL"

    # Task 1 may have installed openssh-server after detect_os ran, so pick
    # the keyword again against the now-available sshd binary.
    detect_kbd_keyword

    if ssh_harden_already_applied; then
        log_skip "SSH effective configuration already matches all hardening targets (port ${SSH_PORT_FINAL})"
        SSH_HARDEN_APPLIED=1
        return 0
    fi

    # H3: socket-activated sshd ignores Port — migrate before changing it.
    if [ "$SSH_SOCKET_MODE" -eq 1 ] && [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        if ! migrate_off_socket_activation; then
            log_warn "Keeping the original port $SSH_PORT_ORIG instead"
            fw_close_port "$wanted_port"    # M4: reclaim the port we cannot use
            SSH_PORT_FINAL="$SSH_PORT_ORIG"
            SSH_PORT_CHANGED=0
        fi
    elif [ "$SSH_SOCKET_MODE" -eq 1 ]; then
        log_info "ssh.socket activation detected; port unchanged — no migration needed"
    fi

    # Port change on enforcing SELinux requires ssh_port_t preparation first.
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        if ! selinux_prepare_port "$SSH_PORT_FINAL"; then
            log_warn "Keeping the original SSH port $SSH_PORT_ORIG instead"
            fw_close_port "$wanted_port"    # M4: reclaim the abandoned port
            SSH_PORT_FINAL="$SSH_PORT_ORIG"
            SSH_PORT_CHANGED=0
        fi
    fi

    if [ "$NO_KEY_AVAILABLE" -eq 1 ]; then
        log_warn "No SSH key (explicit user choice): PasswordAuthentication stays ENABLED"
    fi

    log_info "Applying SSH hardening (root login off, port ${SSH_PORT_FINAL})..."

    if [ "$DROPIN_SUPPORTED" -eq 1 ]; then
        # Snapshot the previous drop-in, then arm the watchdog BEFORE the
        # first modification: a crash or Ctrl-C from here on must not leave
        # an unconfirmed SSH change behind.
        if [ -f "$SSHD_DROPIN" ] && [ ! -f "${SSHD_DROPIN}.pre-vps-setup" ]; then
            cp -a "$SSHD_DROPIN" "${SSHD_DROPIN}.pre-vps-setup"
        fi
        dms_arm
        if ! clear_foreign_ssh_ports; then
            dms_disarm
            log_error "Could not normalise Port directives — SSH configuration left unchanged"
            if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
                fw_close_port "$wanted_port"    # M4: reclaim the never-used port
                SSH_PORT_FINAL="$SSH_PORT_ORIG"
                SSH_PORT_CHANGED=0
            fi
            return 0
        fi
        build_sshd_block > "$SSHD_DROPIN"
        chmod 600 "$SSHD_DROPIN"
        log_ok "SSH hardening drop-in written: $SSHD_DROPIN"
    else
        backup_file "$SSHD_CONFIG"
        dms_arm
        # Remove any active occurrences of managed keywords (incl. Match
        # blocks), then prepend our block — sshd uses first-match-wins.
        clean=$(mktemp) || { dms_disarm; return 0; }
        sed -r '/^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|UsePAM|PermitEmptyPasswords|MaxAuthTries|LoginGraceTime|ClientAliveInterval|ClientAliveCountMax|X11Forwarding|UseDNS)[[:space:]]/Id' "$SSHD_CONFIG" > "$clean"
        tmp=$(mktemp) || { dms_disarm; rm -f "$clean"; return 0; }
        { build_sshd_block; cat "$clean"; } > "$tmp"
        rm -f "$clean"
        if "$SSHD_BIN" -t -f "$tmp" 2>/dev/null; then
            install -m 600 "$tmp" "$SSHD_CONFIG"
            log_ok "SSH hardening written into $SSHD_CONFIG"
        else
            log_error "Generated sshd config failed validation — $SSHD_CONFIG left unchanged"
            rm -f "$tmp"
            dms_disarm
            return 0
        fi
        rm -f "$tmp"
    fi

    if ! "$SSHD_BIN" -t 2>/dev/null; then
        log_error "sshd -t failed after applying changes — rolling back"
        dms_disarm
        rollback_ssh_hardening
        return 0
    fi
    log_ok "sshd -t: configuration is valid"

    if systemctl restart "$SSH_UNIT"; then
        log_ok "$SSH_UNIT restarted (now listening on port ${SSH_PORT_FINAL})"
    else
        log_error "$SSH_UNIT failed to restart — rolling back"
        dms_disarm
        rollback_ssh_hardening
        return 0
    fi

    sleep 1
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE ":${SSH_PORT_FINAL}$"; then
        log_ok "Verified: sshd is listening on port $SSH_PORT_FINAL"
    else
        log_warn "sshd does not appear to listen on $SSH_PORT_FINAL yet — verify manually at the gate below"
    fi

    if ssh_confirm_gate; then
        dms_disarm
        SSH_HARDEN_APPLIED=1
        # The stripped Port directives are now intended; drop the rollback
        # list so a later run cannot resurrect them. Backups stay in $BK_DIR.
        rm -f "$PORT_STRIP_LIST"
        # The old port is closed at the very end of main(): the session that
        # confirmed the change is still connected on it.
        # Keep the FIRST pre-hardening drop-in in the permanent backup dir and
        # stop leaving stale .pre-vps-setup files next to the live config.
        if [ "$DROPIN_SUPPORTED" -eq 1 ] && [ -f "${SSHD_DROPIN}.pre-vps-setup" ]; then
            mkdir -p "$BK_DIR"
            mv -f "${SSHD_DROPIN}.pre-vps-setup" "${BK_DIR}/$(printf '%s' "$SSHD_DROPIN" | tr '/' '_').first.bak"
            log_info "Archived the original drop-in to $BK_DIR"
        fi
    else
        dms_disarm
        log_warn "SSH changes were rolled back; SSH is back on port ${SSH_PORT_FINAL}"
    fi
}

#=============================================================================
# Task 8 — fail2ban
#=============================================================================
systemd_journal_available_for_f2b() {
    if python3 -c 'import systemd' >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

task_fail2ban() {
    if ! cmd_exists fail2ban-client && ! pkg_installed fail2ban; then
        log_error "fail2ban is not installed — the SSH jail cannot be configured"
        # M9: do not pull EPEL silently — tell the user exactly what to do.
        if [ "$FAMILY" = "rhel" ]; then
            log_warn "On RHEL-family systems fail2ban lives in EPEL. To enable it, run:"
            log_warn "  $PKG install -y epel-release        # RHEL proper: dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"
            log_warn "  $PKG install -y fail2ban fail2ban-firewalld python3-systemd"
            log_warn "Then re-run this script."
        else
            log_info "Install it and re-run this script: $PKG install -y fail2ban"
        fi
        return 0
    fi

    if ! systemd_journal_available_for_f2b; then
        if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
            log_info "python systemd module missing but a syslog auth log exists — using the default backend"
            [ "$FAMILY" = "rhel" ] && log_warn "For a robust setup install: $PKG install -y python3-systemd"
        else
            log_warn "No systemd python module and no syslog auth log — the sshd jail may be ineffective"
            log_warn "Install it and re-run: $PKG install -y python3-systemd"
        fi
    fi

    local content content_changed=0 wanted existing
    content=$(printf '# jail.local generated by vps-setup.sh v%s on %s\n[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\nbantime  = 3600\nfindtime = 600\nmaxretry = 5\n\n[sshd]\nenabled  = true\nmode     = aggressive\nport     = %s\n' \
        "$SCRIPT_VERSION" "$(date '+%F %T')" "$SSH_PORT_FINAL")
    if systemd_journal_available_for_f2b; then
        content="${content}
backend  = systemd"
    fi

    # M2: compare without comments so the generated timestamp cannot make
    # every re-run look "changed" (which rewrote the file and restarted
    # fail2ban, clearing active bans, on every invocation).
    wanted=$(printf '%s\n' "$content" | grep -vE '^[[:space:]]*#' | tr -d '[:space:]')
    existing=$(grep -vE '^[[:space:]]*#' "$F2B_JAIL_LOCAL" 2>/dev/null | tr -d '[:space:]')
    if [ -f "$F2B_JAIL_LOCAL" ] && [ "$existing" = "$wanted" ]; then
        log_skip "$F2B_JAIL_LOCAL already up to date"
    else
        if [ -f "$F2B_JAIL_LOCAL" ]; then
            backup_file "$F2B_JAIL_LOCAL"
            log_info "Existing jail.local backed up and replaced"
        fi
        printf '%s\n' "$content" > "$F2B_JAIL_LOCAL"
        chmod 644 "$F2B_JAIL_LOCAL"
        log_ok "$F2B_JAIL_LOCAL written (sshd jail: enabled=true, mode=aggressive, port=${SSH_PORT_FINAL})"
        content_changed=1
    fi

    if systemctl is-enabled --quiet fail2ban 2>/dev/null; then
        log_skip "fail2ban service already enabled"
    else
        systemctl enable fail2ban >/dev/null 2>&1 && log_ok "fail2ban service enabled at boot"
    fi
    if [ "$content_changed" -eq 1 ] && systemctl is-active --quiet fail2ban; then
        systemctl restart fail2ban
        log_info "fail2ban restarted to pick up the new jail configuration"
    elif ! systemctl is-active --quiet fail2ban; then
        systemctl start fail2ban || { log_error "fail2ban failed to start (check 'journalctl -u fail2ban')"; return 0; }
    fi

    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        fail2ban-client ping >/dev/null 2>&1 && break
        sleep 1
    done
    if ! fail2ban-client ping >/dev/null 2>&1; then
        log_error "fail2ban is not answering 'ping' — check 'journalctl -u fail2ban'"
        return 0
    fi
    if fail2ban-client status 2>/dev/null | grep -qw sshd; then
        log_ok "Verified: fail2ban active with sshd jail (aggressive) covering port $SSH_PORT_FINAL"
    else
        log_error "fail2ban is running but the sshd jail is NOT active"
    fi
}

#=============================================================================
# Task 9 — automatic security updates
#=============================================================================
task_auto_updates() {
    if [ "$DO_AUTOUPDATES" -ne 1 ]; then
        log_skip "Automatic security updates disabled by user input"
        return 0
    fi

    if [ "$FAMILY" = "debian" ]; then
        install_pkgs unattended-upgrades || true
        if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
            log_error "unattended-upgrades package could not be installed"
            return 0
        fi
        local want
        want='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
        if [ -f "$AUTO_UPGRADES_FILE" ] && [ "$(cat "$AUTO_UPGRADES_FILE")" = "$want" ]; then
            log_skip "$AUTO_UPGRADES_FILE already enables automatic updates"
        else
            [ -f "$AUTO_UPGRADES_FILE" ] && backup_file "$AUTO_UPGRADES_FILE"
            mkdir -p "$(dirname "$AUTO_UPGRADES_FILE")"
            printf '%s\n' "$want" > "$AUTO_UPGRADES_FILE"
            log_ok "$AUTO_UPGRADES_FILE written (daily update + unattended upgrade)"
        fi
        if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
            log_skip "unattended-upgrades service already running"
        else
            if systemctl enable --now unattended-upgrades >/dev/null 2>&1; then
                log_ok "unattended-upgrades service enabled and started"
            else
                log_warn "unattended-upgrades service unit not present on this system (timer-based apt-daily still applies)"
            fi
        fi
    else
        local svc
        if [ "$PKG" = "yum" ]; then
            install_pkgs yum-cron || true
            svc="yum-cron"
        else
            install_pkgs dnf-automatic || true
            svc="dnf-automatic"
        fi
        local conf
        if [ "$svc" = "dnf-automatic" ]; then
            conf="/etc/dnf/automatic.conf"
            if [ -f "$conf" ] \
                && grep -Eq '^apply_updates[[:space:]]*=[[:space:]]*yes' "$conf" \
                && grep -Eq '^upgrade_type[[:space:]]*=[[:space:]]*security' "$conf"; then
                log_skip "dnf-automatic already set to apply security updates"
            else
                backup_file "$conf"
                if grep -qE '^[#[:space:]]*apply_updates' "$conf" 2>/dev/null; then
                    sed -ri 's/^[#[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' "$conf"
                else
                    printf 'apply_updates = yes\n' >> "$conf"
                fi
                if grep -qE '^[#[:space:]]*upgrade_type' "$conf" 2>/dev/null; then
                    sed -ri 's/^[#[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/' "$conf"
                else
                    printf 'upgrade_type = security\n' >> "$conf"
                fi
                log_ok "dnf-automatic set to apply SECURITY updates only"
            fi
            systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
            if systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
                log_ok "dnf-automatic.timer enabled"
            else
                log_warn "dnf-automatic.timer could not be enabled"
            fi
        else
            conf="/etc/yum/yum-cron.conf"
            backup_file "$conf"
            sed -ri 's/^apply_updates[[:space:]]*=.*/apply_updates = yes/' "$conf" 2>/dev/null || true
            sed -ri 's/^#*[[:space:]]*update_cmd[[:space:]]*=.*/update_cmd = security/' "$conf" 2>/dev/null || true
            systemctl enable --now "$svc" >/dev/null 2>&1
            if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
                log_ok "yum-cron enabled (security updates)"
            else
                log_warn "yum-cron could not be enabled"
            fi
        fi
    fi
}

#=============================================================================
# Task 10 — time synchronization
#=============================================================================
task_time_sync() {
    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null \
        || systemctl is-active --quiet chronyd 2>/dev/null \
        || systemctl is-active --quiet chrony 2>/dev/null \
        || systemctl is-active --quiet ntp 2>/dev/null; then
        log_skip "Time synchronization already active"
        return 0
    fi
    if systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
        timedatectl set-ntp true 2>/dev/null && log_ok "systemd-timesyncd NTP enabled"
        if systemctl is-active --quiet systemd-timesyncd; then
            log_ok "Verified: time synchronization active (systemd-timesyncd)"
        else
            systemctl enable --now systemd-timesyncd >/dev/null 2>&1 && log_ok "systemd-timesyncd started"
        fi
    elif systemctl list-unit-files chronyd.service >/dev/null 2>&1; then
        systemctl enable --now chronyd >/dev/null 2>&1 && log_ok "chronyd enabled and started"
    else
        log_warn "No NTP unit found (timesyncd/chronyd) — configure time sync manually"
    fi
}

#=============================================================================
# Task 11 — insecure listening port scan (report only)
#=============================================================================
task_port_scan() {
    local ports insecure=0 p
    ports=$(ss -tln 2>/dev/null | awk 'NR>1 {n=split($4, a, ":"); print a[n]}' | sort -un)
    if [ -z "$ports" ]; then
        log_warn "Could not list listening ports (is 'ss' available?)"
        return 0
    fi
    log_info "Listening TCP ports: $(echo "$ports" | tr '\n' ' ')"
    for p in 21 23 25 69 111 135 445 3389; do
        if echo "$ports" | grep -qx "$p"; then
            log_error "Insecure port ${p} is LISTENING (ftp/telnet/smtp/tftp/rpc/msrpc/smb/rdp family)"
            insecure=1
        fi
    done
    if [ "$insecure" -eq 0 ]; then
        log_ok "No insecure services listening (ports 21/23/25/69/111/135/445/3389 all closed)"
    else
        log_warn "Disable the services above or restrict them with the firewall"
    fi
}

#=============================================================================
# Task 12 — final verification report (effective state, like the audits do)
#=============================================================================
task_verify() {
    local kv want got ports
    subheader "Effective SSH configuration (sshd -T)"
    # Port is cumulative, so checking the first value is not enough: a leftover
    # Port directive elsewhere would keep an extra port open.
    ports=$(effective_ssh_ports)
    if [ "$ports" = "$SSH_PORT_FINAL" ]; then
        log_ok "sshd: only port ${SSH_PORT_FINAL} is listened on"
    else
        log_error "sshd: listening ports are '${ports:-<none>}' (expected only '${SSH_PORT_FINAL}')"
    fi
    while IFS=: read -r kv want; do
        [ -n "$kv" ] || continue
        got=$(sshd_effective "$kv")
        if [ "$got" = "$want" ]; then
            log_ok "sshd: ${kv}=${want}"
        else
            log_error "sshd: ${kv} is '${got:-<unset>}' (expected '${want}')"
        fi
    done < <(hardening_targets)

    subheader "Other security controls"
    if [ "$FW_KIND" = "ufw" ]; then
        if ufw status 2>/dev/null | grep -qw active; then
            log_ok "firewall: ufw active, default-incoming=$(ufw status verbose 2>/dev/null | grep 'Default:' | awk '{print $2}')"
        else
            log_error "firewall: ufw is not active"
        fi
    else
        if firewall-cmd --state >/dev/null 2>&1; then
            log_ok "firewall: firewalld active (zone $(firewall-cmd --get-default-zone 2>/dev/null))"
        else
            log_error "firewall: firewalld is not active"
        fi
    fi

    if ! cmd_exists fail2ban-client && ! pkg_installed fail2ban; then
        log_error "fail2ban: not installed — the SSH jail is inactive"
    elif systemctl is-active --quiet fail2ban && fail2ban-client status 2>/dev/null | grep -qw sshd; then
        log_ok "fail2ban: running, jails: $(fail2ban-client status 2>/dev/null | awk -F': ' '/Jail list/{print $2}' | tr -d '\t')"
    else
        log_error "fail2ban: installed but the sshd jail is not active"
    fi

    local sudoers_n
    sudoers_n=$(cat "$SUDOERS_FILE" "$SUDOERS_LOGGING_DROPIN" 2>/dev/null | grep -c '^Defaults.*logfile')
    if [ "${sudoers_n:-0}" -gt 0 ]; then
        log_ok "sudoers: ${sudoers_n} logfile directive(s)"
    else
        log_error "sudoers: no logfile directive found"
    fi

    local mode
    mode=$(stat -c '%a' /etc/passwd 2>/dev/null)
    if [ "$mode" = "644" ]; then
        log_ok "permissions: /etc/passwd=644"
    else
        log_error "permissions: /etc/passwd=${mode:-unknown} (expected 644)"
    fi
    mode=$(stat -c '%a' /etc/shadow 2>/dev/null)
    if [ "$mode" = "600" ]; then
        log_ok "permissions: /etc/shadow=600"
    else
        log_error "permissions: /etc/shadow=${mode:-unknown} (expected 600)"
    fi

    if [ "$FAMILY" = "debian" ]; then
        if [ "$DO_AUTOUPDATES" -eq 1 ]; then
            if grep -q 'APT::Periodic::Unattended-Upgrade "1"' "$AUTO_UPGRADES_FILE" 2>/dev/null; then
                log_ok "auto-updates: enabled ($AUTO_UPGRADES_FILE)"
            else
                log_error "auto-updates: $AUTO_UPGRADES_FILE is not configured"
            fi
        else
            log_skip "auto-updates: disabled by user choice"
        fi
    fi

    if id "$NEW_USER" >/dev/null 2>&1; then
        log_ok "admin user: $(id "$NEW_USER")"
    else
        log_error "admin user: $NEW_USER missing!"
    fi

    local home n_keys=""
    home=$(getent passwd "$NEW_USER" 2>/dev/null | cut -d: -f6)
    if [ -n "$home" ] && [ -f "$home/.ssh/authorized_keys" ]; then
        n_keys=$(grep -cvE '^(#|$)' "$home/.ssh/authorized_keys" 2>/dev/null)
    fi
    if [ "${n_keys:-0}" -gt 0 ]; then
        log_ok "ssh keys: $NEW_USER has ${n_keys} key(s) ($home/.ssh/authorized_keys)"
    elif [ "$NO_KEY_AVAILABLE" -eq 1 ]; then
        log_skip "ssh keys: none installed for $NEW_USER (password auth kept enabled by user choice)"
    else
        log_error "ssh keys: none found for $NEW_USER"
    fi
}

#=============================================================================
# Summary
#=============================================================================
show_summary() {
    local reboot=0
    if [ -f /var/run/reboot-required ]; then
        reboot=1
    fi
    printf '\n%s%s================= SUMMARY =================%s\n' "$BOLD" "$CYAN" "$NC"
    printf '%s[✓]%s applied: %s   %s[→]%s skipped: %s   %s[!]%s warnings: %s   %s[✗]%s errors: %s\n' \
        "$GREEN" "$NC" "$OK_N" "$CYAN" "$NC" "$SKIP_N" "$YELLOW" "$NC" "$WARN_N" "$RED" "$NC" "$ERR_N"

    log_info "Final SSH endpoint: ssh -p ${SSH_PORT_FINAL} ${NEW_USER}@$(ssh_address_hint)"
    log_info "Configuration backups: $BK_DIR"
    log_info "Execution report: $RESULT_FILE"
    if [ "$reboot" -eq 1 ]; then
        log_warn "A package upgrade flagged a REBOOT as required — reboot soon: sudo reboot"
    fi
    if [ "$SSH_PORT_CHANGED" -eq 1 ] && [ "$SSH_HARDEN_APPLIED" -eq 1 ]; then
        log_warn "Remember to open TCP ${SSH_PORT_FINAL} (and close 22) in your cloud provider's security group."
    fi
    if [ "$ERR_N" -gt 0 ]; then
        log_error "Finished WITH ERRORS — review the [✗] lines above, fix, and re-run this script (it is idempotent)."
    else
        log_ok "All tasks completed. Run your security audit script now to confirm everything passes."
        if [ "$reboot" -eq 1 ]; then
            log_warn "After rebooting, re-run this script once to double-check every check reports SKIP (already hardened)."
        fi
    fi
    finalize_report
    printf '%s%s===========================================%s\n\n' "$BOLD" "$CYAN" "$NC"
    if [ "$ERR_N" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

#=============================================================================
# Task runner + main
#=============================================================================
run_task() { # $1 index, $2 title, $3 function
    step "$1" "$2"
    "$3"
}

main() {
    trap 'on_interrupt' INT TERM
    trap 'on_exit' EXIT

    require_root
    require_tty
    acquire_lock
    init_report
    detect_os

    printf '%s%sVPS setup & security hardening v%s%s\n' "$BOLD" "$CYAN" "$SCRIPT_VERSION" "$NC"
    log_info "Detected: ${DISTRO_PRETTY} (${FAMILY} family, firewall=${FW_KIND}, ssh unit=${SSH_UNIT}, socket-mode=${SSH_SOCKET_MODE})"
    log_info "Current SSH port: ${SSH_PORT_ORIG}, OpenSSH keyword mode: ${KBD_KEYWORD}"
    if [ "$SSH_SOCKET_MODE" -eq 1 ]; then
        log_info "systemd socket activation (ssh.socket) in use; port changes will migrate SSH to classic mode"
    fi

    collect_all_inputs
    show_plan
    if ! final_confirm; then
        log_warn "Aborted before any change — nothing was modified."
        _log_append "STATUS" "ABORTED by user before execution"
        exit 0
    fi
    report_decisions

    run_task 1  "System packages & upgrade"      task_system_update
    run_task 2  "Password quality policy"        task_password_policy
    run_task 3  "Sudo audit logging"             task_sudo_logging
    run_task 4  "Admin user & SSH keys"          task_admin_user
    run_task 5  "File permissions"               task_permissions
    run_task 6  "Firewall (default-deny)"        task_firewall
    run_task 7  "SSH hardening"                  task_ssh_hardening
    run_task 8  "Fail2ban (SSH jail)"            task_fail2ban
    run_task 9  "Automatic security updates"     task_auto_updates
    run_task 10 "Time synchronization"           task_time_sync
    run_task 11 "Insecure port scan"             task_port_scan
    run_task 12 "Final verification"             task_verify

    # Close every SSH port that is no longer managed, only after all tasks
    # have finished. The session running this script (and the one that
    # answered the gate) may still be connected on one of them, so closing
    # earlier leaves it protected only by the firewall's conntrack state.
    if [ "$SSH_HARDEN_APPLIED" -eq 1 ]; then
        local p
        for p in "${ALL_SSH_PORTS[@]}"; do
            [ "$p" = "$SSH_PORT_FINAL" ] || fw_close_old_ssh "$p"
        done
    fi

    show_summary
}

main "$@"
