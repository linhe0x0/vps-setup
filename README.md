# vps-setup

English | [简体中文](README.zh-CN.md)

Interactive one-shot bootstrap and security hardening for a fresh Linux
server (AWS EC2 or any cloud VPS). One file, no dependencies beyond a
standard systemd distribution, fully idempotent, and built to pass common
community VPS security audits.

> **Note:** This script has only been tested on Debian 13. The other
> supported distributions are handled by the code but are untested.

```bash
curl -fsSL https://github.com/linhe0x0/vps-setup/raw/refs/heads/main/vps-setup.sh | sudo bash
```

The script is interactive and needs a real terminal (an SSH session works).
When stdin is piped, the prompts are served from the controlling terminal
(`/dev/tty`) — they can never consume the script source itself. If you
prefer to review before running:

```bash
curl -fsSL https://github.com/linhe0x0/vps-setup/raw/refs/heads/main/vps-setup.sh -o vps-setup.sh
sudo bash vps-setup.sh
```

## Features

- **System update** — installs required base packages and applies a full
  system upgrade (skipped automatically when 0 packages are pending).
- **Admin user** — dedicated `sudo` (Debian/Ubuntu) or `wheel` (RHEL family)
  user with a strong password and a valid login shell.
- **Password policy** — `pwquality`: `minlen=14` plus all four character
  classes required.
- **SSH hardening** — `PermitRootLogin=no`, key-only access
  (`PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`,
  `UsePAM=yes`), optional port change with a lockout-safe
  verify-and-rollback flow plus a 15-minute dead-man switch that
  auto-reverts unconfirmed changes. Socket-activated sshd (Ubuntu 22.10+,
  Debian 13) is detected and migrated to classic `ssh.service` mode when
  the port changes.
- **Firewall** — default-deny incoming via **UFW** (Debian/Ubuntu) or
  **firewalld** (RHEL family); only SSH and user-selected extra ports stay
  open, persisted across reboots. On firewalld, rules are pre-staged
  offline before the daemon's first start, so enabling it can never cut
  the running SSH session.
- **fail2ban** — aggressive `sshd` jail (`bantime=1h`, `findtime=10m`,
  `maxretry=5`), always aligned with the actual SSH port.
- **Automatic security updates** — `unattended-upgrades` on Debian/Ubuntu,
  `dnf-automatic`/`yum-cron` on the RHEL family.
- **sudo audit logging** — every sudo command recorded to
  `/var/log/sudo.log`.
- **File permissions** — `/etc/passwd=644`, `/etc/shadow=600`,
  `~/.ssh=700`, `authorized_keys=600`.
- **Time synchronization** — ensures NTP (`systemd-timesyncd`/`chronyd`) is
  active.
- **Insecure port scan** — reports listeners on FTP/Telnet/SMTP/TFTP/RPC/
  SMB/RDP ports.
- **Final verification** — after every run, prints the *effective*
  configuration (`sshd -T`, firewall, fail2ban jails, permissions) so the
  result can be checked at a glance.
- **Persistent execution report** — every step is mirrored into a
  timestamped audit log under `/var/vps-setup/reports/`.
- **Transparent output** — uniform, greppable result tags:
  `[✓]` applied · `[→] SKIP` (with reason) · `[i]` info · `[!]` warning ·
  `[✗]` error.

## Supported distributions

Debian, Ubuntu, CentOS/RHEL, Rocky, AlmaLinux, Amazon Linux.
Any systemd-based system of these families; older OpenSSH (< 8.7) is
handled by using the legacy `ChallengeResponseAuthentication` keyword.
On socket-activated systems (Ubuntu 22.10+, Debian 13) the script detects
`ssh.socket` at runtime and migrates SSH to classic `ssh.service` mode
when a port change is requested. On the RHEL family, fail2ban lives in
EPEL — the script never adds repositories silently; it prints the exact
commands to run when EPEL is missing.

## Interactive flow

1. Detects the OS and current SSH setup.
2. Collects all input up front: admin username, password, SSH public key
   (reuse root's or paste one), optional new SSH port, optional extra
   firewall ports, and two toggles (full upgrade, automatic updates).
   Without any key, the script asks explicitly: re-check root's
   `authorized_keys` after you upload one from another session, or skip
   and keep password authentication enabled — it is never disabled
   silently.
3. Shows the complete change plan **including all high-risk operations**
   and requires a typed `yes` before touching anything.
4. Executes the 12 tasks, logging every result.
5. Pauses after reconfiguring SSH so a new login can be verified from a
   second terminal (`ok` keeps the change, `rollback` restores the
   previous configuration automatically). If the session dies before you
   answer — or no answer arrives within 15 minutes — the change is rolled
   back automatically.
6. Prints a summary and writes the closing block of the execution report.

## Safety & idempotency

- **Idempotent** — safe to re-run at any time; already-satisfied steps are
  reported as explicit `SKIP` lines with their reasons.
- **Backups** — every edited file is backed up once (first pre-script
  state) under `/var/vps-setup/backups/`.
- **Rollback** — SSH changes are validated with `sshd -t` before restart
  and confirmed interactively afterwards; on failure, on `rollback`, or on
  a 15-minute confirmation timeout (dead-man switch) the previous
  configuration is restored automatically, and abandoned firewall ports
  are reclaimed in every path.
- **Concurrency guard** — a non-blocking `flock` prevents two parallel
  runs from interleaving changes; the lock is released on any exit.
- **Interrupted-run recovery** — an `apt`/`dpkg` state left broken by a
  previously interrupted run is detected and recovered
  (`dpkg --configure -a`) before any new package operation, and every
  interactive prompt exits safely on accidental Ctrl-D instead of looping.
- **No secrets on disk** — passwords live only in memory; the execution
  report records key *fingerprints*, never key material or passwords.

## On-disk layout

| Path | Purpose |
|---|---|
| `/var/vps-setup/backups/` | First-generation backups of edited config files |
| `/var/vps-setup/reports/report-<timestamp>.log` | Persistent execution report (audit trail) |
| `/var/vps-setup/lock` | Non-blocking run lock (concurrency guard, released on any exit) |
| `/var/vps-setup/rollback-ssh-<timestamp>.sh` | Self-contained dead-man-switch rollback script (deleted once SSH changes are confirmed) |
| `/etc/ssh/sshd_config.d/00-vps-setup-hardening.conf` | SSH hardening drop-in (used whenever the main config includes `sshd_config.d` as its first directive, i.e. OpenSSH >= 8.2; package updates never touch this file) |
| `/etc/ssh/sshd_config` | Modified directly only when the `Include` is missing or not the first directive (legacy OpenSSH, e.g. CentOS 7); package managers keep modified configs (`.rpmnew` / `.dpkg-dist`) |
| `/etc/sudoers.d/60-vps-setup-logging` | sudo audit-logging drop-in (validated with `visudo` before and after install) |
| `/etc/apt/apt.conf.d/20auto-upgrades` | Enables daily index update + unattended upgrade (Debian/Ubuntu) |
| `/etc/fail2ban/jail.local` | fail2ban SSH jail configuration |

## Security checklist coverage

The script is built to satisfy every check of common community VPS security
audits:

| Check | Covered by |
|---|---|
| Non-root sudo user with valid shell | Admin user task |
| UFW installed / active / default-deny incoming | Firewall task |
| `PermitRootLogin=no`, `PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`, `UsePAM=yes` (via `sshd -T`) | SSH hardening task |
| `authorized_keys` present | Admin user task |
| fail2ban installed, enabled, running, `jail.local` with `enabled=true` + `mode=aggressive`, jail port aligned | fail2ban task |
| `/etc/passwd=644`, `/etc/shadow=600` | Permissions task |
| No FTP/Telnet/SMTP/TFTP/RPC/SMB/RDP listeners | Port scan task |
| `unattended-upgrades` installed, service running, `20auto-upgrades` enabled | Auto updates task |
| sudo `Defaults logfile`, pwquality `minlen>=12`, all upgrades applied, firewall active | Tasks 1–3 |

After the run, review the execution report under `/var/vps-setup/reports/`
and re-run the script at any time — every already-satisfied check is
reported as an explicit `SKIP`.

## Notes & trade-offs

- `UsePAM=yes` keeps PAM session tracking (`pam_systemd`) and PAM limits
  for SSH logins. Key-only access is enforced by
  `PasswordAuthentication=no` and `KbdInteractiveAuthentication=no`, not by
  `UsePAM`.
- Without an SSH key the script will not disable password authentication
  on its own: it either re-checks root's `authorized_keys` after you
  upload a key, or — only on your explicit choice — keeps password
  authentication enabled.
- The community audit flags SSH ports `>= net.ipv4.ip_unprivileged_port_start`
  (usually 1024). A non-standard port **below 1024** passes cleanly; the
  script warns and lets you decide.
- `Port` is cumulative in `sshd_config`: sshd listens on every declared
  port. A port change therefore also strips `Port` lines from the main
  config and other drop-ins. Each edited file is backed up first and
  restored if the change is rolled back. Ports that are no longer managed
  are closed in the firewall at the very end of the run.
- Opening a new SSH port also requires allowing it in the cloud provider's
  external firewall (AWS security group, Aliyun security group, ...) — the
  script reminds you before and after.
- The SSH command shown in the plan, the confirmation gate, and the report
  uses the public address reported by Cloudflare. On NAT/EIP hosts the
  detected address is private, so the script prints
  `<your-server-public-ip>` instead of a command that cannot work.
