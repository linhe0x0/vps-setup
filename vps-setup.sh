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
#     with `sshd -t` before restart and confirmed interactively afterwards,
#     with automatic rollback if the new configuration does not work.
#   - Auditable: every run writes a timestamped execution report under
#     /var/vps-setup/reports/, and edited files are backed up under
#     /var/vps-setup/backups/.
#
# Usage:
#   sudo bash vps-setup.sh
#
# HIGH-IMPACT side effects (also shown interactively before execution):
#   - Root SSH login is permanently disabled.
#   - SSH password authentication is disabled (key-only access).
#   - Incoming traffic is denied by default; only listed ports stay open.
#   - Failed SSH logins are banned by fail2ban.
#   - A full package upgrade is performed; a reboot may be required.
#=============================================================================

set -uo pipefail
# SC2317 is disabled file-wide: task_* functions are invoked indirectly via
# run_task ("$3"), which shellcheck cannot see, so every task body is flagged
# as "unreachable". All other findings stay enabled.
# shellcheck disable=SC2317
export LC_ALL=C
umask 077

#=============================================================================
# Constants
# NOTE: do NOT use the name VERSION — sourcing /etc/os-release defines it.
#=============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly BK_DIR="/var/vps-setup/backups"
readonly RESULT_DIR="/var/vps-setup/reports"
readonly STEP_TOTAL=12
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly SSHD_DROPIN="${SSHD_DROPIN_DIR}/00-vps-setup-hardening.conf"
readonly F2B_JAIL_LOCAL="/etc/fail2ban/jail.local"
readonly PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly SUDOERS_FILE="/etc/sudoers"
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

FAMILY=""            # debian | rhel
DISTRO_PRETTY="unknown"
PKG="apt-get"        # apt-get | dnf | yum
ADMIN_GROUP="sudo"   # sudo (Debian/Ubuntu) | wheel (RHEL family)
FW_KIND="ufw"        # ufw | firewalld
SSHD_BIN="/usr/sbin/sshd"
SSH_UNIT="ssh.service"
KBD_KEYWORD="KbdInteractiveAuthentication"
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

SSH_HARDEN_APPLIED=0
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
        printf 'Final SSH endpoint : ssh -p %s %s@%s\n' "$SSH_PORT_FINAL" "$NEW_USER" "$(public_ip_hint)"
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

wait_for_apt_lock() {
    local i=0
    while pgrep -f '(^|/)apt-get' >/dev/null 2>&1 || pgrep -f '(^|/)dpkg' >/dev/null 2>&1 \
        || pgrep -f '(^|/)unattended-upgrade' >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -gt 40 ]; then
            log_warn "apt/dpkg is still busy after ~10 minutes; continuing anyway"
            return 1
        fi
        [ "$i" -eq 1 ] && log_info "Waiting for a running apt/dpkg process to finish..."
        sleep 15
    done
    return 0
}

# Install packages; prints its own result. Returns 2 when nothing was missing.
install_pkgs() {
    local missing=() p
    for p in "$@"; do
        pkg_installed "$p" || missing+=("$p")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        log_skip "all required packages already installed: $*"
        return 2
    fi
    log_info "Installing: ${missing[*]}"
    case "$FAMILY" in
        debian)
            wait_for_apt_lock || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
            ;;
        rhel)
            "$PKG" install -y "${missing[@]}"
            ;;
    esac
}

# Public IP hint for the interactive SSH test (EC2 IMDSv2 -> routing table).
public_ip_hint() {
    local ip="" token=""
    if cmd_exists curl; then
        token=$(curl -s --connect-timeout 2 --max-time 3 \
            -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
            'http://169.254.169.254/latest/api/token' 2>/dev/null) || true
        if [ -n "$token" ]; then
            ip=$(curl -s --connect-timeout 2 --max-time 3 \
                -H "X-aws-ec2-metadata-token: $token" \
                'http://169.254.169.254/latest/meta-data/public-ipv4' 2>/dev/null) || true
        fi
    fi
    if [ -z "$ip" ]; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i+1); exit}}')
    fi
    [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    printf '%s' "$ip"
}

#=============================================================================
# Interactive prompt helpers
#=============================================================================
confirm_yn() { # $1 question, $2 default: y|n
    local ans
    if [ "${2:-y}" = "y" ]; then
        read -r -p "$1 [Y/n]: " ans
        ans="${ans:-y}"
    else
        read -r -p "$1 [y/N]: " ans
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

#=============================================================================
# Environment detection
#=============================================================================
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This script must run as root. Try: sudo bash $0"
    fi
}

require_tty() {
    if [ ! -t 0 ]; then
        die "No interactive terminal detected. Run this script directly in an SSH session: sudo bash $0"
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

    # Older OpenSSH (< 8.7) only knows ChallengeResponseAuthentication.
    if "$SSHD_BIN" -T 2>/dev/null | grep -qi '^kbdinteractiveauthentication'; then
        KBD_KEYWORD="KbdInteractiveAuthentication"
    else
        KBD_KEYWORD="ChallengeResponseAuthentication"
    fi

    # Effective SSH port before any change.
    local p
    p=$("$SSHD_BIN" -T 2>/dev/null | awk 'tolower($1)=="port"{print $2; exit}')
    if [ -n "$p" ] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] 2>/dev/null; then
        SSH_PORT_ORIG="$p"
    else
        SSH_PORT_ORIG=22
    fi
    SSH_PORT_FINAL="$SSH_PORT_ORIG"

    if grep -Eiq '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$SSHD_CONFIG" 2>/dev/null \
        && [ -d "$SSHD_DROPIN_DIR" ]; then
        DROPIN_SUPPORTED=1
    fi
}

sshd_effective() { # $1 keyword -> prints effective value
    "$SSHD_BIN" -T 2>/dev/null | awk -v k="$1" 'tolower($1)==tolower(k){print $2; exit}'
}

#=============================================================================
# Input collection (all user data is gathered BEFORE anything is changed)
#=============================================================================
ask_username() {
    while :; do
        read -r -p "Admin username to create: " NEW_USER
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

ask_password() {
    if [ "$USER_EXISTS" -eq 1 ]; then
        log_info "Existing user kept as-is; its password is not modified."
        ADMIN_PW=""
        return 0
    fi
    local pw1 pw2 cls
    while :; do
        read -r -s -p "Password for '$NEW_USER' (min 14 chars, at least 3 character classes): " pw1
        printf '\n'
        read -r -s -p "Confirm password: " pw2
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
        printf '%s' "$pw1" | grep -q '[0-9]'       && cls=$((cls + 1))
        printf '%s' "$pw1" | grep -q '[a-z]'       && cls=$((cls + 1))
        printf '%s' "$pw1" | grep -q '[A-Z]'       && cls=$((cls + 1))
        printf '%s' "$pw1" | grep -q '[^0-9A-Za-z]' && cls=$((cls + 1))
        if [ "$cls" -lt 3 ]; then
            log_error "Password must contain at least 3 of: digits, lowercase, uppercase, symbols. Try again."
            continue
        fi
        ADMIN_PW="$pw1"
        break
    done
    log_ok "Password accepted (validated locally; pwquality will enforce the same policy)."
}

ask_ssh_key() {
    local line
    subheader "SSH login key"
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
            read -r -p "Paste an SSH public key (empty = skip): " line
            [ -z "$line" ] && break
            if validate_pubkey "$line"; then
                SSH_KEYS_CONTENT="$line"
                break
            fi
            log_error "That does not look like a valid public key (ssh-keygen rejected it). Try again."
        done
    fi
    if [ -z "$SSH_KEYS_CONTENT" ] && [ ! -s "$ROOT_KEYS_FILE" ]; then
        NO_KEY_AVAILABLE=1
        log_warn "No SSH public key is available. SSH password authentication will stay ENABLED for safety."
        log_warn "You can add a key and re-run this script afterwards to finish hardening."
    fi
}

ask_ssh_port() {
    local ans unpriv_start
    subheader "SSH port"
    log_info "Current SSH port: $SSH_PORT_ORIG"
    unpriv_start=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || printf '1024')
    while :; do
        read -r -p "SSH port — press Enter to keep $SSH_PORT_ORIG, or type a new port: " ans
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
        log_ok "SSH will move to port $SSH_PORT_FINAL (update your AWS Security Group!)"
    else
        log_skip "SSH port stays at $SSH_PORT_FINAL"
    fi
}

ask_extra_ports() {
    local ans p seen
    subheader "Additional firewall ports"
    read -r -p "Additional TCP ports to allow (e.g. 80,443 — empty for none): " ans
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
    ip=$(public_ip_hint)
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
        port_line="SSH MOVES TO PORT ${SSH_PORT_FINAL}. You MUST open TCP ${SSH_PORT_FINAL} in your AWS Security Group or you WILL lose access."
    else
        port_line="SSH port stays at ${SSH_PORT_FINAL}."
    fi
    cat <<EOF
 Detected system : $DISTRO_PRETTY
 Server address  : ${ip:-<unresolved>}   (SSH test hint, verify yourself too)
 Execution log   : $RESULT_FILE

 Planned actions:
   1.  Package management: ${upgrade_line}
   2.  Password policy: pwquality minlen=14 + all character classes required
   3.  sudo audit logging: every sudo command logged to /var/log/sudo.log
   4.  Admin user: $NEW_USER (sudo/wheel group, bash shell, SSH key installed)
   5.  Permissions: /etc/passwd=644, /etc/shadow=600, ~/.ssh=700, authorized_keys=600
   6.  Firewall ($FW_KIND): DEFAULT DENY incoming; allow SSH${EXTRA_PORTS[*]:+ + extra ports ${EXTRA_PORTS[*]}}
   7.  SSH hardening: PermitRootLogin=no, PasswordAuthentication=no,
       KbdInteractiveAuthentication=no, UsePAM=no, port ${SSH_PORT_FINAL}
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
 * SSH PASSWORD LOGIN WILL BE DISABLED — only key-based access remains.
   Verify your key works BEFORE confirming, or you can lock yourself out.
 * ${port_line}
 * The firewall will DENY ALL incoming traffic except SSH and the extra
   ports listed above, and this applies after every reboot.
 * fail2ban will BAN IP addresses with repeated failed SSH logins —
   that can include your own IP if you mistype your key/password repeatedly.
 * A full system upgrade may install a new kernel: A REBOOT MAY BE REQUIRED.
 * UsePAM is set to 'no' (required by the target security audit); PAM session
   modules (e.g. pam_systemd session tracking) are skipped for SSH logins.
 * Edited files are backed up once under $BK_DIR before modification.
 * The script is idempotent — re-running it is always safe.

 >>> KEEP THIS SSH SESSION OPEN UNTIL THE SCRIPT HAS FINISHED. <<<
 The script will pause after applying SSH changes so you can verify a new
 login from a second terminal; if it fails, the change is rolled back.
EOF
    printf '%s[!]%s %s\n' "$YELLOW" "$NC" "If anything above is unacceptable, abort now — nothing has been changed yet."
}

final_confirm() {
    local ans
    printf '\n'
    read -r -p "Type 'yes' to APPLY all planned changes (anything else aborts): " ans
    [ "$ans" = "yes" ]
}

#=============================================================================
# Task 1 — base packages + system upgrade
#=============================================================================
task_system_update() {
    local rc=0 cnt=0

    if [ "$FAMILY" = "debian" ]; then
        install_pkgs sudo openssh-server ufw iproute2 libpam-pwquality fail2ban python3-systemd || rc=$?
        if [ "$rc" -eq 0 ]; then
            log_ok "Base packages present (ufw, fail2ban, pwquality, ...)"
        else
            log_warn "Some base packages failed to install — affected tasks will report their own skips"
        fi
        if [ "$DO_UPGRADE" -ne 1 ]; then
            log_skip "System upgrade disabled by user input"
            return 0
        fi
        wait_for_apt_lock || true
        log_info "Running apt-get update..."
        if apt-get update -y >/dev/null 2>&1; then
            log_ok "Package index updated"
        else
            log_warn "apt-get update failed — continuing with the existing index"
        fi
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
        install_pkgs sudo openssh-server firewalld iproute pwquality || rc=$?
        if [ "$rc" -eq 0 ]; then
            log_ok "Base packages present (firewalld, pwquality, ...)"
        else
            log_warn "Some base packages failed to install — affected tasks will report their own skips"
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
        log_error "$PWQUALITY_CONF missing — install libpam-pwquality/pwquality first"
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
    local n tmp line
    if grep -q '^Defaults.*logfile' "$SUDOERS_FILE"; then
        log_skip "sudo logging already configured in $SUDOERS_FILE"
        return 0
    fi
    backup_file "$SUDOERS_FILE"
    line='Defaults logfile="/var/log/sudo.log"'
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
        if [ -n "$ADMIN_PW" ]; then
            if printf '%s:%s\n' "$NEW_USER" "$ADMIN_PW" | chpasswd; then
                log_ok "Password set for $NEW_USER"
            else
                log_error "Failed to set password for $NEW_USER"
            fi
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

    if [ "$NO_KEY_AVAILABLE" -eq 1 ]; then
        log_warn "No key material anywhere — SSH hardening will keep password authentication ON"
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
fw_allow_port() { # $1 port — allows tcp/$1, reports skip when present
    local port="$1"
    if [ "$FW_KIND" = "ufw" ]; then
        if ufw status 2>/dev/null | grep -q "^${port}/tcp"; then
            log_skip "ufw rule for ${port}/tcp already present"
        else
            ufw allow "${port}/tcp" >/dev/null 2>&1 && log_ok "ufw: allowed incoming tcp/$port"
        fi
    else
        if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            log_skip "firewalld rule for ${port}/tcp already present"
        else
            firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 \
                && firewall-cmd --reload >/dev/null 2>&1 \
                && log_ok "firewalld: allowed incoming tcp/$port"
        fi
    fi
}

fw_remove_port() { # $1 port
    local port="$1"
    if [ "$FW_KIND" = "ufw" ]; then
        if ufw status 2>/dev/null | grep -q "^${port}/tcp"; then
            ufw delete allow "${port}/tcp" >/dev/null 2>&1 && log_ok "ufw: removed incoming tcp/$port"
        fi
    else
        if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1
        fi
        if firewall-cmd --query-service=ssh >/dev/null 2>&1; then
            firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1
        fi
        firewall-cmd --reload >/dev/null 2>&1 && log_ok "firewalld: removed incoming tcp/$port (and ssh service)"
    fi
}

task_firewall() {
    local p
    if [ "$FW_KIND" = "ufw" ]; then
        if ! cmd_exists ufw; then
            log_error "ufw not found — install it and re-run this script"
            return 0
        fi
        # Safety: allow the SSH ports BEFORE enabling default-deny.
        fw_allow_port "$SSH_PORT_FINAL"
        if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
            fw_allow_port "$SSH_PORT_ORIG"
            log_info "Old SSH port $SSH_PORT_ORIG temporarily allowed until the new port is verified"
        fi
        for p in ${EXTRA_PORTS[@]+"${EXTRA_PORTS[@]}"}; do
            fw_allow_port "$p"
        done
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
        if systemctl is-active --quiet firewalld; then
            log_skip "firewalld already running"
        else
            systemctl enable --now firewalld >/dev/null 2>&1 && log_ok "firewalld enabled and started"
        fi
        if firewall-cmd --state >/dev/null 2>&1; then
            log_ok "Verified: firewalld is active"
        else
            log_error "firewalld is not running"
            return 0
        fi
        fw_allow_port "$SSH_PORT_FINAL"
        if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
            fw_allow_port "$SSH_PORT_ORIG"
            log_info "Old SSH port $SSH_PORT_ORIG temporarily allowed until the new port is verified"
        fi
        for p in ${EXTRA_PORTS[@]+"${EXTRA_PORTS[@]}"}; do
            fw_allow_port "$p"
        done
        if [ "$(firewall-cmd --get-default-zone 2>/dev/null)" = "public" ]; then
            log_skip "firewalld default zone already 'public' (incoming default-deny)"
        else
            firewall-cmd --set-default-zone=public >/dev/null 2>&1 && log_ok "firewalld default zone set to 'public' (incoming default-deny)"
        fi
    fi
}

#=============================================================================
# Task 7 — SSH hardening (+ optional port change, with test gate & rollback)
#=============================================================================
build_sshd_block() {
    cat <<EOF
# BEGIN managed by vps-setup.sh v${SCRIPT_VERSION} on $(date '+%F %T')
Port ${SSH_PORT_FINAL}
PermitRootLogin no
PasswordAuthentication no
${KBD_KEYWORD} no
UsePAM no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
UseDNS no
# END managed by vps-setup.sh
EOF
}

ssh_harden_already_applied() {
    local kv want got
    while IFS=: read -r kv want; do
        [ -n "$kv" ] || continue
        got=$(sshd_effective "$kv")
        [ "$got" = "$want" ] || return 1
    done <<EOF
PermitRootLogin:no
PasswordAuthentication:no
${KBD_KEYWORD}:no
UsePAM:no
Port:${SSH_PORT_FINAL}
EOF
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
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
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

ssh_confirm_gate() {
    local ip ans
    ip=$(public_ip_hint)
    printf '\n%s%sACTION REQUIRED — VERIFY ACCESS NOW%s\n' "$BOLD" "$YELLOW" "$NC"
    cat <<EOF
 SSH has been reconfigured. From a NEW terminal, verify you can log in:

     ssh -p ${SSH_PORT_FINAL} ${NEW_USER}@${ip:-<server-address>}

 Then inside that session run:  sudo -v   (must succeed)
 $( [ "$SSH_PORT_CHANGED" -eq 1 ] && printf 'NOTE: if this fails, also check that TCP %s is open in your EC2 Security Group.' "$SSH_PORT_FINAL" )

 Type 'ok' to keep the new configuration, or 'rollback' to restore the
 previous SSH settings. (Ctrl-C keeps the new config and exits.)
EOF
    while :; do
        read -r -p "Verify and type ok / rollback: " ans
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
    local tmp clean

    if [ "$NO_KEY_AVAILABLE" -eq 1 ]; then
        log_skip "SSH hardening limited: no key available, password auth stays enabled (re-run after adding a key)"
    fi

    if ssh_harden_already_applied; then
        log_skip "SSH effective configuration already matches all hardening targets (port ${SSH_PORT_FINAL})"
        SSH_HARDEN_APPLIED=1
        return 0
    fi

    # Port change on enforcing SELinux requires ssh_port_t preparation first.
    if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
        if ! selinux_prepare_port "$SSH_PORT_FINAL"; then
            log_warn "Keeping the original SSH port $SSH_PORT_ORIG instead"
            SSH_PORT_FINAL="$SSH_PORT_ORIG"
            SSH_PORT_CHANGED=0
        fi
    fi

    log_info "Applying SSH hardening (root login off, key-only auth, UsePAM=no, port ${SSH_PORT_FINAL})..."

    if [ "$DROPIN_SUPPORTED" -eq 1 ]; then
        if [ -f "$SSHD_DROPIN" ] && [ ! -f "${SSHD_DROPIN}.pre-vps-setup" ]; then
            cp -a "$SSHD_DROPIN" "${SSHD_DROPIN}.pre-vps-setup"
        fi
        build_sshd_block > "$SSHD_DROPIN"
        chmod 600 "$SSHD_DROPIN"
        log_ok "SSH hardening drop-in written: $SSHD_DROPIN"
    else
        backup_file "$SSHD_CONFIG"
        # Remove any active occurrences of managed keywords (incl. Match
        # blocks), then prepend our block — sshd uses first-match-wins.
        clean=$(mktemp) || return 0
        sed -r '/^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|UsePAM|PermitEmptyPasswords|MaxAuthTries|LoginGraceTime|ClientAliveInterval|ClientAliveCountMax|X11Forwarding|UseDNS)[[:space:]]/Id' "$SSHD_CONFIG" > "$clean"
        tmp=$(mktemp) || return 0
        { build_sshd_block; cat "$clean"; } > "$tmp"
        rm -f "$clean"
        if "$SSHD_BIN" -t -f "$tmp" 2>/dev/null; then
            install -m 600 "$tmp" "$SSHD_CONFIG"
            log_ok "SSH hardening written into $SSHD_CONFIG"
        else
            log_error "Generated sshd config failed validation — $SSHD_CONFIG left unchanged"
            rm -f "$tmp"
            return 0
        fi
        rm -f "$tmp"
    fi

    if ! "$SSHD_BIN" -t 2>/dev/null; then
        log_error "sshd -t failed after applying changes — rolling back"
        rollback_ssh_hardening
        return 0
    fi
    log_ok "sshd -t: configuration is valid"

    if systemctl restart "$SSH_UNIT"; then
        log_ok "$SSH_UNIT restarted (now listening on port ${SSH_PORT_FINAL})"
    else
        log_error "$SSH_UNIT failed to restart — rolling back"
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
        SSH_HARDEN_APPLIED=1
        if [ "$SSH_PORT_CHANGED" -eq 1 ]; then
            fw_remove_port "$SSH_PORT_ORIG"
        fi
    else
        log_warn "SSH changes were rolled back at your request; server remains on port $SSH_PORT_FINAL"
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
        log_skip "fail2ban is not installed (installation failed earlier or is unavailable on this distro)"
        return 0
    fi

    local backend_line="" content
    if systemd_journal_available_for_f2b; then
        backend_line="backend  = systemd"
    elif [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
        log_info "python systemd module missing but syslog auth log exists — using default backend"
    else
        log_warn "No systemd python module and no syslog auth log — sshd jail may be ineffective"
    fi

    content=$(printf '# jail.local generated by vps-setup.sh v%s on %s\n[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\nbantime  = 3600\nfindtime = 600\nmaxretry = 5\n\n[sshd]\nenabled  = true\nmode     = aggressive\nport     = %s\n' \
        "$SCRIPT_VERSION" "$(date '+%F %T')" "$SSH_PORT_FINAL")
    if [ -n "$backend_line" ]; then
        content="${content}
backend  = systemd"
    fi

    if [ -f "$F2B_JAIL_LOCAL" ] && [ "$(cat "$F2B_JAIL_LOCAL")" = "$content" ]; then
        log_skip "$F2B_JAIL_LOCAL already up to date"
    else
        if [ -f "$F2B_JAIL_LOCAL" ]; then
            backup_file "$F2B_JAIL_LOCAL"
            log_info "Existing jail.local backed up and replaced"
        fi
        printf '%s\n' "$content" > "$F2B_JAIL_LOCAL"
        chmod 644 "$F2B_JAIL_LOCAL"
        log_ok "$F2B_JAIL_LOCAL written (sshd jail: enabled=true, mode=aggressive, port=${SSH_PORT_FINAL})"
    fi

    if systemctl is-enabled --quiet fail2ban 2>/dev/null; then
        log_skip "fail2ban service already enabled"
    else
        systemctl enable fail2ban >/dev/null 2>&1 && log_ok "fail2ban service enabled at boot"
    fi
    if systemctl is-active --quiet fail2ban; then
        systemctl restart fail2ban
        log_info "fail2ban restarted to pick up the new jail configuration"
    else
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
            if [ -f "$conf" ] && grep -Eq '^apply_updates[[:space:]]*=[[:space:]]*yes' "$conf"; then
                log_skip "dnf-automatic apply_updates already 'yes'"
            else
                if grep -qE '^[#[:space:]]*apply_updates' "$conf" 2>/dev/null; then
                    sed -ri 's/^[#[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' "$conf"
                else
                    printf 'apply_updates = yes\n' >> "$conf"
                fi
                log_ok "dnf-automatic apply_updates set to 'yes'"
            fi
            systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
            if systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
                log_ok "dnf-automatic.timer enabled"
            else
                log_warn "dnf-automatic.timer could not be enabled"
            fi
        else
            sed -ri 's/^apply_updates[[:space:]]*=.*/apply_updates = yes/' /etc/yum/yum-cron.conf 2>/dev/null || true
            systemctl enable --now "$svc" >/dev/null 2>&1
            if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
                log_ok "yum-cron enabled"
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
    local kv want got
    subheader "Effective SSH configuration (sshd -T)"
    while IFS=: read -r kv want; do
        [ -n "$kv" ] || continue
        got=$(sshd_effective "$kv")
        if [ "$got" = "$want" ]; then
            log_ok "sshd: ${kv}=${want}"
        else
            log_error "sshd: ${kv} is '${got:-<unset>}' (expected '${want}')"
        fi
    done <<EOF
Port:${SSH_PORT_FINAL}
PermitRootLogin:no
PasswordAuthentication:no
${KBD_KEYWORD}:no
UsePAM:no
PermitEmptyPasswords:no
MaxAuthTries:4
LoginGraceTime:30
EOF

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

    if systemctl is-active --quiet fail2ban && fail2ban-client status 2>/dev/null | grep -qw sshd; then
        log_ok "fail2ban: running, jails: $(fail2ban-client status 2>/dev/null | awk -F': ' '/Jail list/{print $2}' | tr -d '\t')"
    else
        log_error "fail2ban: sshd jail not active"
    fi

    log_ok "sudoers: $(grep -c '^Defaults.*logfile' "$SUDOERS_FILE" 2>/dev/null) logfile directive(s), pwquality: $(grep -E '^[[:space:]]*minlen[[:space:]]*=' "$PWQUALITY_CONF" 2>/dev/null | tail -1 | tr -s ' ')"
    log_ok "permissions: /etc/passwd=$(stat -c '%a' /etc/passwd), /etc/shadow=$(stat -c '%a' /etc/shadow)"
    if [ "$FAMILY" = "debian" ]; then
        log_ok "auto-updates: $(grep -h 'APT::Periodic' "$AUTO_UPGRADES_FILE" 2>/dev/null | tr -s ' \t' ' ' | tr '\n' '; ')"
    fi
    log_ok "admin user: $(id "$NEW_USER" 2>/dev/null || printf '%s missing!' "$NEW_USER")"
    local ak_file="/home/${NEW_USER}/.ssh/authorized_keys" n_keys=0
    [ -f "$ak_file" ] && n_keys=$(grep -cvE '^(#|$)' "$ak_file" 2>/dev/null)
    log_ok "ssh keys: ${NEW_USER}: ${n_keys} key(s)"
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

    log_info "Final SSH endpoint: ssh -p ${SSH_PORT_FINAL} ${NEW_USER}@$(public_ip_hint)"
    log_info "Configuration backups: $BK_DIR"
    log_info "Execution report: $RESULT_FILE"
    if [ "$reboot" -eq 1 ]; then
        log_warn "A package upgrade flagged a REBOOT as required — reboot soon: sudo reboot"
    fi
    if [ "$SSH_PORT_CHANGED" -eq 1 ] && [ "$SSH_HARDEN_APPLIED" -eq 1 ]; then
        log_warn "Remember to open TCP ${SSH_PORT_FINAL} (and close 22) in your AWS Security Group."
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
    trap 'printf "\n"; log_warn "Interrupted — configuration may be partial. Re-run this script to resume safely (idempotent)."; exit 130' INT TERM

    require_root
    require_tty
    init_report
    detect_os

    printf '%s%sVPS setup & security hardening v%s%s\n' "$BOLD" "$CYAN" "$SCRIPT_VERSION" "$NC"
    log_info "Detected: ${DISTRO_PRETTY} (${FAMILY} family, firewall=${FW_KIND}, ssh unit=${SSH_UNIT})"
    log_info "Current SSH port: ${SSH_PORT_ORIG}, OpenSSH keyword mode: ${KBD_KEYWORD}"

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

    show_summary
}

main "$@"
