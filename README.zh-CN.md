# vps-setup

[English](README.md) | 简体中文

面向全新 Linux 服务器（AWS EC2 或任意云 VPS）的交互式一键初始化与安全加固
脚本。单文件、除标准 systemd 发行版外零依赖、完全幂等，并以满足常见社区
VPS 安全审计检查项为构建目标。

```bash
curl -fsSL https://github.com/linhe0x0/vps-setup/raw/refs/heads/main/vps-setup.sh | sudo bash
```

脚本为交互式，需要在真实终端（SSH 会话）中运行。通过管道执行时，交互提示
会自动改绑到控制终端（`/dev/tty`），绝不会读取脚本源码本身。如果希望先
审阅再执行：

```bash
curl -fsSL https://github.com/linhe0x0/vps-setup/raw/refs/heads/main/vps-setup.sh -o vps-setup.sh
sudo bash vps-setup.sh
```

## 功能特性

- **系统更新** — 安装所需基础软件包并执行完整的系统升级（无待更新包时自动跳过）。
- **管理员用户** — 创建专属 `sudo`（Debian/Ubuntu）或 `wheel`（RHEL 系）用户，
  设置强密码与有效登录 shell。
- **密码策略** — `pwquality`：`minlen=14`，且要求包含全部四类字符。
- **SSH 加固** — `PermitRootLogin=no`，仅允许密钥登录
  （`PasswordAuthentication=no`、`KbdInteractiveAuthentication=no`、`UsePAM=yes`），
  可选修改端口，配备防锁死的“验证 + 回滚”流程，以及 15 分钟内无人确认即自动
  回滚的看门狗。检测到 socket 激活模式的 sshd（Ubuntu 22.10+、Debian 13）时，
  修改端口前会先迁移到经典 `ssh.service` 模式。
- **防火墙** — 通过 **UFW**（Debian/Ubuntu）或 **firewalld**（RHEL 系）实现
  默认拒绝入站；仅放行 SSH 与用户指定的额外端口，重启后依然生效。firewalld
  在守护进程首次启动前先离线预置规则，启动动作本身绝不会切断现有 SSH 会话。
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
`ChallengeResponseAuthentication` 关键字。在 socket 激活的系统上
（Ubuntu 22.10+、Debian 13），脚本运行时探测 `ssh.socket`，需要改端口时
先迁移到经典 `ssh.service` 模式。RHEL 系的 fail2ban 位于 EPEL —— 脚本
不会静默添加软件源；检测到缺失时会打印需要手工执行的精确命令。

## 交互流程

1. 检测操作系统与当前 SSH 配置。
2. 提前一次性收集所有输入：管理员用户名、密码、SSH 公钥（复用 root 的或
   手动粘贴）、可选的新 SSH 端口、可选的额外放行端口，以及两个开关
   （是否完整升级、是否开启自动更新）。如果没有任何可用密钥，脚本会明确
   询问：从其他会话上传密钥后重新检测 root 的 `authorized_keys`，或选择
   跳过并保持密码认证开启 —— 绝不会静默关闭密码登录。
3. 展示完整的变更计划，**重点标注所有高风险操作**，必须输入 `yes` 才会
   开始执行。
4. 执行 12 项任务，逐步输出执行结果。
5. SSH 配置变更后脚本会暂停，等待你在另一个终端验证新登录（输入 `ok`
   保留变更；输入 `rollback` 自动恢复原配置）。若会话在确认前中断
   （掉线、Ctrl-C），或 15 分钟内没有任何确认，这些变更会自动回滚。
6. 输出总结，并写入执行报告的收尾部分。

## 安全性与幂等性

- **幂等** — 任何时候都可以安全地重复执行；已满足的步骤会以明确的
  `SKIP` 行说明原因。
- **备份** — 每个被修改的文件都会备份一次（保留最初的原始状态）到
  `/var/vps-setup/backups/`。
- **回滚** — SSH 变更在重启前先用 `sshd -t` 校验，重启后再交互确认；
  失败、选择 `rollback`、或 15 分钟内未确认（看门狗）时自动恢复原配置，
  并在任何路径下回收被放弃的防火墙端口。
- **并发防护** — 非阻塞 `flock` 防止两次并行运行交错修改；锁随进程退出
  自动释放，不存在死锁。
- **中断恢复** — 自动检测并修复上次运行遗留的 `apt`/`dpkg` 中断状态
  （`dpkg --configure -a`）；交互提示误按 Ctrl-D 会安全退出而不是死循环。
- **不在磁盘留存敏感信息** — 密码只存在于内存中；执行报告只记录密钥
  *指纹*，绝不写入密钥内容或密码。

## 磁盘布局

| 路径 | 用途 |
|---|---|
| `/var/vps-setup/backups/` | 被修改配置文件的首次原始备份 |
| `/var/vps-setup/reports/report-<timestamp>.log` | 持久化执行报告（审计日志） |
| `/var/vps-setup/lock` | 非阻塞运行锁（并发防护，随进程退出自动释放） |
| `/var/vps-setup/rollback-ssh-<timestamp>.sh` | 看门狗（dead-man switch）自包含回滚脚本；确认后自动删除 |
| `/etc/ssh/sshd_config.d/00-vps-setup-hardening.conf` | SSH 加固 drop-in 配置（主配置将 `sshd_config.d` 作为第一条指令 Include 时使用，即 OpenSSH >= 8.2；包更新不会覆盖该文件） |
| `/etc/ssh/sshd_config` | 仅在主配置缺少 `Include` 或其不在首位时直接修改（旧版 OpenSSH，如 CentOS 7）；包管理器会保留已修改的配置（`.rpmnew` / `.dpkg-dist`） |
| `/etc/sudoers.d/60-vps-setup-logging` | sudo 审计日志 drop-in 配置（安装前后均用 `visudo` 校验） |
| `/etc/apt/apt.conf.d/20auto-upgrades` | 启用每日索引更新与无人值守升级（Debian/Ubuntu） |
| `/etc/fail2ban/jail.local` | fail2ban SSH jail 配置 |

## 安全检查项覆盖

脚本以满足常见社区 VPS 安全审计的全部检查项为构建目标：

| 检查项 | 对应任务 |
|---|---|
| 存在具备有效 shell 的非 root sudo 用户 | 管理员用户任务 |
| UFW 已安装 / 已启用 / 入站默认拒绝 | 防火墙任务 |
| `PermitRootLogin=no`、`PasswordAuthentication=no`、`KbdInteractiveAuthentication=no`、`UsePAM=yes`（以 `sshd -T` 为准） | SSH 加固任务 |
| 存在 `authorized_keys` | 管理员用户任务 |
| fail2ban 已安装、已启用、运行中，`jail.local` 含 `enabled=true` + `mode=aggressive`，jail 端口与 SSH 端口一致 | fail2ban 任务 |
| `/etc/passwd=644`、`/etc/shadow=600` | 文件权限任务 |
| 无 FTP/Telnet/SMTP/TFTP/RPC/SMB/RDP 监听 | 端口扫描任务 |
| `unattended-upgrades` 已安装、服务运行中、`20auto-upgrades` 已启用 | 自动更新任务 |
| sudo `Defaults logfile`、pwquality `minlen>=12`、系统无待更新包、防火墙已启用 | 任务 1–3 |

运行结束后，请查看 `/var/vps-setup/reports/` 下的执行报告；也可以随时
重新运行本脚本 —— 所有已满足的检查项都会以明确的 `SKIP` 报告。

## 说明与权衡

- `UsePAM=yes` 保留 `pam_systemd` 会话跟踪和 PAM limits。仅允许密钥登录
  由 `PasswordAuthentication=no` 和 `KbdInteractiveAuthentication=no`
  保证，与 `UsePAM` 无关。
- 没有可用 SSH 密钥时，脚本不会自行关闭密码认证：要么在你上传密钥后
  重新检测 root 的 `authorized_keys`，要么仅在明确选择后保持密码认证
  开启。
- 社区审计会将 `>= net.ipv4.ip_unprivileged_port_start`（通常为 1024）的
  SSH 端口标记为风险。**低于 1024** 的非标准端口可以干净通过检查；脚本
  会给出警告并由你自行决定。
- 在 `sshd_config` 中 `Port` 是累加指令：sshd 会监听所有声明的端口。因此
  修改端口时还会清除主配置和其他 drop-in 中的 `Port` 行。每个被修改的文件
  都会先备份，回滚时恢复。不再由脚本管理的端口会在执行末尾从防火墙关闭。
- 修改 SSH 端口后，还需要在云厂商的外部防火墙（AWS 安全组、阿里云安全组等）
  中放行新端口 —— 脚本会在执行前后各提醒一次。
- 计划页、确认 gate 和最终报告里的 SSH 命令使用 Cloudflare 探测到的公网地址。
  在 NAT/EIP 环境中探测结果是私网地址，脚本会显示 `<your-server-public-ip>`，
  而不是一条无法连接的命令。
