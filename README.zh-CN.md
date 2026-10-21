# vps-setup

[English](README.md) | 简体中文

面向全新 Linux 服务器（AWS EC2 或任意云 VPS）的交互式一键初始化与安全加固
脚本。单文件、除标准 systemd 发行版外零依赖、完全幂等，并以满足常见社区
VPS 安全审计检查项为构建目标。

```bash
curl -fsSL https://github.com/linhe0x0/vps-setup/raw/refs/heads/main/vps-setup.sh | sudo bash
```

## 功能特性

- **系统更新** — 安装所需基础软件包并执行完整的系统升级（无待更新包时自动跳过）。
- **管理员用户** — 创建专属 `sudo`（Debian/Ubuntu）或 `wheel`（RHEL 系）用户，
  设置强密码与有效登录 shell。
- **密码策略** — `pwquality`：`minlen=14`，且要求包含全部四类字符。
- **SSH 加固** — `PermitRootLogin=no`，仅允许密钥登录
  （`PasswordAuthentication=no`、`KbdInteractiveAuthentication=no`、`UsePAM=no`），
  可选修改端口，并配备防锁死的“验证 + 回滚”流程。
- **防火墙** — 通过 **UFW**（Debian/Ubuntu）或 **firewalld**（RHEL 系）实现
  默认拒绝入站；仅放行 SSH 与用户指定的额外端口，重启后依然生效。
- **fail2ban** — 激进模式的 `sshd` jail（`bantime=1h`、`findtime=10m`、
  `maxretry=5`），始终与实际 SSH 端口保持一致。
- **自动安全更新** — Debian/Ubuntu 使用 `unattended-upgrades`，RHEL 系使用
  `dnf-automatic`/`yum-cron`。
- **sudo 审计日志** — 每条 sudo 命令记录到 `/var/log/sudo.log`。
- **文件权限** — `/etc/passwd=644`、`/etc/shadow=600`、`~/.ssh=700`、
  `authorized_keys=600`。
- **时间同步** — 确保 NTP（`systemd-timesyncd`/`chronyd`）处于启用状态。
- **危险端口扫描** — 检测 FTP/Telnet/SMTP/TFTP/RPC/SMB/RDP 等端口监听。
- **最终校验** — 每次运行结束后输出*实际生效*的配置（`sshd -T`、防火墙、
  fail2ban jail、文件权限等），一目了然。
- **持久化执行报告** — 每个步骤同步写入带时间戳的审计日志，位于
  `/var/vps-setup/reports/`。
- **透明化输出** — 统一、可 grep 的结果标记：
  `[✓]` 已执行 · `[→] SKIP`（附原因）· `[i]` 信息 · `[!]` 警告 ·
  `[✗]` 错误。

## 支持的发行版

Debian、Ubuntu、CentOS/RHEL、Rocky、AlmaLinux、Amazon Linux。
支持上述发行版家族的任意 systemd 系统；旧版 OpenSSH（< 8.7）会自动改用
`ChallengeResponseAuthentication` 关键字。

## 交互流程

1. 检测操作系统与当前 SSH 配置。
2. 提前一次性收集所有输入：管理员用户名、密码、SSH 公钥（复用 root 的或
   手动粘贴）、可选的新 SSH 端口、可选的额外放行端口，以及两个开关
   （是否完整升级、是否开启自动更新）。
3. 展示完整的变更计划，**重点标注所有高风险操作**，必须输入 `yes` 才会
   开始执行。
4. 执行 12 项任务，逐步输出执行结果。
5. SSH 配置变更后脚本会暂停，等待你在另一个终端验证新登录（输入 `ok`
   保留变更；输入 `rollback` 自动恢复原配置）。
6. 输出总结，并写入执行报告的收尾部分。

## 安全性与幂等性

- **幂等** — 任何时候都可以安全地重复执行；已满足的步骤会以明确的
  `SKIP` 行说明原因。
- **备份** — 每个被修改的文件都会备份一次（保留最初的原始状态）到
  `/var/vps-setup/backups/`。
- **回滚** — SSH 变更在重启前先用 `sshd -t` 校验，重启后再交互确认；
  失败或选择 `rollback` 时自动恢复原配置。
- **不在磁盘留存敏感信息** — 密码只存在于内存中；执行报告只记录密钥
  *指纹*，绝不写入密钥内容或密码。

## 磁盘布局

| 路径 | 用途 |
|---|---|
| `/var/vps-setup/backups/` | 被修改配置文件的首次原始备份 |
| `/var/vps-setup/reports/report-<timestamp>.log` | 持久化执行报告（审计日志） |
| `/etc/ssh/sshd_config.d/00-vps-setup-hardening.conf` | SSH 加固 drop-in 配置（主配置支持 `Include` 即 OpenSSH >= 8.2 时使用；包更新不会覆盖该文件） |
| `/etc/ssh/sshd_config` | 仅在无法解析 `Include` 的旧版 OpenSSH（< 8.2，如 CentOS 7 / RHEL 8）上直接修改；包管理器会保留已修改的配置（`.rpmnew` / `.dpkg-dist`） |
| `/etc/fail2ban/jail.local` | fail2ban SSH jail 配置 |

## 安全检查项覆盖

脚本以满足常见社区 VPS 安全审计的全部检查项为构建目标：

| 检查项 | 对应任务 |
|---|---|
| 存在具备有效 shell 的非 root sudo 用户 | 管理员用户任务 |
| UFW 已安装 / 已启用 / 入站默认拒绝 | 防火墙任务 |
| `PermitRootLogin=no`、`PasswordAuthentication=no`、`KbdInteractiveAuthentication=no`、`UsePAM=no`（以 `sshd -T` 为准） | SSH 加固任务 |
| 存在 `authorized_keys` | 管理员用户任务 |
| fail2ban 已安装、已启用、运行中，`jail.local` 含 `enabled=true` + `mode=aggressive`，jail 端口与 SSH 端口一致 | fail2ban 任务 |
| `/etc/passwd=644`、`/etc/shadow=600` | 文件权限任务 |
| 无 FTP/Telnet/SMTP/TFTP/RPC/SMB/RDP 监听 | 端口扫描任务 |
| `unattended-upgrades` 已安装、服务运行中、`20auto-upgrades` 已启用 | 自动更新任务 |
| sudo `Defaults logfile`、pwquality `minlen>=12`、系统无待更新包、防火墙已启用 | 任务 1–3 |

运行结束后，请查看 `/var/vps-setup/reports/` 下的执行报告；也可以随时
重新运行本脚本 —— 所有已满足的检查项都会以明确的 `SKIP` 报告。

## 说明与权衡

- 目标安全审计要求 `UsePAM=no`；因此 SSH 登录会跳过 PAM 会话模块
  （例如 `pam_systemd` 会话跟踪）。
- 社区审计会将 `>= net.ipv4.ip_unprivileged_port_start`（通常为 1024）的
  SSH 端口标记为风险。**低于 1024** 的非标准端口可以干净通过检查；脚本
  会给出警告并由你自行决定。
- 在 AWS 上修改 SSH 端口后，还需要在 **EC2 安全组**中放行新端口 ——
  脚本会在执行前后各提醒一次。
