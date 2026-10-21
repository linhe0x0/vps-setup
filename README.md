# vps-setup

English | [简体中文](README.zh-CN.md)

Interactive one-shot bootstrap and security hardening for a fresh Linux
server (AWS EC2 or any cloud VPS). One file, no dependencies beyond a
standard systemd distribution, fully idempotent, and built to pass common
community VPS security audits.

```bash
curl -fsSL https://github.com/linhe0x0/vps-setup/raw/refs/heads/main/vps-setup.sh | sudo bash
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
  `UsePAM=no`), optional port change with a lockout-safe
  verify-and-rollback flow.
- **Firewall** — default-deny incoming via **UFW** (Debian/Ubuntu) or
  **firewalld** (RHEL family); only SSH and user-selected extra ports stay
  open, persisted across reboots.
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

## Interactive flow

1. Detects the OS and current SSH setup.
2. Collects all input up front: admin username, password, SSH public key
   (reuse root's or paste one), optional new SSH port, optional extra
   firewall ports, and two toggles (full upgrade, automatic updates).
3. Shows the complete change plan **including all high-risk operations**
   and requires a typed `yes` before touching anything.
4. Executes the 12 tasks, logging every result.
5. Pauses after reconfiguring SSH so a new login can be verified from a
   second terminal (`ok` keeps the change, `rollback` restores the
   previous configuration automatically).
6. Prints a summary and writes the closing block of the execution report.

## Safety & idempotency

- **Idempotent** — safe to re-run at any time; already-satisfied steps are
  reported as explicit `SKIP` lines with their reasons.
- **Backups** — every edited file is backed up once (first pre-script
  state) under `/var/vps-setup/backups/`.
- **Rollback** — SSH changes are validated with `sshd -t` before restart
  and confirmed interactively afterwards; on failure or on `rollback` the
  previous configuration is restored automatically.
- **No secrets on disk** — passwords live only in memory; the execution
  report records key *fingerprints*, never key material or passwords.

## On-disk layout

| Path | Purpose |
|---|---|
| `/var/vps-setup/backups/` | First-generation backups of edited config files |
| `/var/vps-setup/reports/report-<timestamp>.log` | Persistent execution report (audit trail) |
| `/etc/ssh/sshd_config.d/00-vps-setup-hardening.conf` | SSH hardening drop-in (used whenever the main config supports `Include`, i.e. OpenSSH >= 8.2; package updates never touch this file) |
| `/etc/ssh/sshd_config` | Modified directly only on legacy OpenSSH (< 8.2, e.g. CentOS 7 / RHEL 8) that cannot parse `Include`; package managers keep modified configs (`.rpmnew` / `.dpkg-dist`) |
| `/etc/fail2ban/jail.local` | fail2ban SSH jail configuration |

## Security checklist coverage

The script is built to satisfy every check of common community VPS security
audits:

| Check | Covered by |
|---|---|
| Non-root sudo user with valid shell | Admin user task |
| UFW installed / active / default-deny incoming | Firewall task |
| `PermitRootLogin=no`, `PasswordAuthentication=no`, `KbdInteractiveAuthentication=no`, `UsePAM=no` (via `sshd -T`) | SSH hardening task |
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

- `UsePAM=no` is required by the target audit; PAM session modules (e.g.
  `pam_systemd` session tracking) are skipped for SSH logins.
- The community audit flags SSH ports `>= net.ipv4.ip_unprivileged_port_start`
  (usually 1024). A non-standard port **below 1024** passes cleanly; the
  script warns and lets you decide.
- Changing the SSH port on AWS also requires opening the new port in the
  **EC2 Security Group** — the script reminds you before and after.
