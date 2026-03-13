# LanWatchDog - LAN Device Monitoring System

> Version: v1.3.1 | Updated: 2026-03-13

---

## 1. Overview

LanWatchDog is a Windows-based LAN device monitoring tool with the following features:

- 🔍 **LAN Device Scanning** - Auto-discover devices on your network
- 📊 **Traffic Monitoring** - Real-time network traffic monitoring (per-device traffic with PCAP)
- 🛡️ **Attack Detection** - Detect security threats on your LAN
- 🔔 **Alert Notifications** - Get notified for new devices, offline devices, abnormal traffic
- 📈 **Data Visualization** - ECharts graphs for traffic trends

---

## 2. Quick Start

### 2.1 Requirements

- OS: Windows 10/11 or Windows Server
- Network: LAN environment
- Permissions: Administrator (for network scanning and traffic monitoring)

### 2.2 Installation

1. **Download**

   Get the latest version from GitHub:
   ```
   https://github.com/lambersWangPika/LanWatchDog/releases
   ```

2. **Run**

   Double-click `nm.exe` to run, default port is `8080`

3. **Access**

   Open browser: `http://localhost:8080` or `http://your-ip:8080`

---

## 3. Features

### 3.1 Device List

**Location**: Home page (default)

**Functions**:
- Display all discovered LAN devices
- Show: status, IP, name, notes, MAC address, type, online duration, last seen

**Actions**:

| Action | Description |
|--------|-------------|
| 🔍 Port Scan | Scan device for open ports (19 common ports) |
| ✏️ Edit | Edit device name, notes, group |
| ⭐ Add Whitelist | Add device to whitelist |
| ❌ Remove Whitelist | Remove from whitelist |

**Status**:
- 🟢 Online - Device responding
- 🔴 Offline - Device not responding
- 🆕 New - First discovered
- ⭐ Whitelist - Confirmed safe

**Device Types**:
- router, pc, phone, printer, tablet, server

---

### 3.2 Traffic Monitoring

**Location**: Click「📊 Traffic」in navigation

**Functions**:
- Real-time inbound/outbound rate
- Total inbound/outbound traffic
- **Per-device traffic** (requires PCAP enabled)

**Traffic Charts**:
- Line chart: inbound/outbound rate over time (last 60 seconds)
- Pie chart: device traffic distribution

**Traffic Table**:

| Column | Description |
|--------|-------------|
| IP | Device IP address |
| Inbound | Total inbound traffic |
| Outbound | Total outbound traffic |
| Rate | Current transfer rate |
| Last Update | Data update time |

**Units**: Auto-scaled: B → KB → MB → GB → TB

---

### 3.3 Alerts

**Location**: Click「🔔 Alerts」in navigation

**Functions**:
- Display all alert records
- Levels: high, medium, low, info

**Alert Types**:
- New Device - New device discovered
- Device Offline - Device went offline
- Traffic Anomaly - Traffic exceeded threshold
- Attack Detected - Network attack detected

---

### 3.4 Attack Detection

**Location**: Click「🛡️ Attacks」in navigation

**Functions**:
- Display detected network attack records

**Detection Types**:
- Brute Force
- Port Scan
- Flood
- ARP Spoofing

---

### 3.5 System Logs

**Location**: Click「📋 Logs」in navigation

**Functions**:
- Scan logs: scan timestamps, device counts
- Operation logs: whitelist operations, config changes
- Alert logs: alert triggers

---

### 3.6 Statistics

**Location**: Click「📈 Stats」in navigation

**Functions**:
- Total devices, online, offline
- Whitelist count
- Alert count, attack count
- Traffic stats: total in/out, rate in/out

---

### 3.7 Settings

**Location**: Click「⚙️ Settings」in navigation

#### 3.7.1 Scan Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Auto Scan Interval | Time between auto scans | 30 seconds |

#### 3.7.2 Traffic Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Traffic Interval | Data collection interval | 5 seconds |
| Global Threshold | Alert when exceeded | 100 MB/hour |

#### 3.7.3 PCAP Precise Traffic (Important⭐)

**Description**:
- Default uses PowerShell adapter stats, only shows total traffic
- With PCAP enabled, shows **per-device precise traffic**

**Enable Steps**:

1. Download npcap driver: https://npcap.com/dist/npcap-1.78.exe

2. Install npcap (Admin):
   - Run installer
   - Check「Npcap Loopback Adapter」
   - Check「Install npcap in WinPcap API-compatible mode」
   - Complete installation

3. In Settings page:
   - Check「Enable PCAP Capture」
   - Leave「Interface Name」empty for auto-select
   - Click「Save Settings」

4. Restart program

**Verification**:
- Check logs for `[PCAP] Started traffic capture` message
- Traffic page shows per-device traffic

#### 3.7.4 Alert Settings

| Setting | Description |
|---------|-------------|
| Enable Alerts | Turn on/off alerts |
| Alert Sound | Enable alert sound |
| New Device Alert | Alert on new device |
| Offline Alert | Alert on device offline |
| Traffic Alert | Alert on threshold exceeded |
| Attack Alert | Alert on detected attack |

#### 3.7.5 Notification Settings

| Setting | Description |
|---------|-------------|
| Windows Notification | Use Windows system notifications |
| Telegram Notification | Send via Telegram Bot |
| Webhook Notification | Send via Webhook URL |

---

## 4. Advanced Features

### 4.1 Data Export

**Location**: Toolbar「📥 Export Devices」

**Functions**:
- Export device list to CSV
- Includes: IP, MAC, name, notes, type, status, online duration

### 4.2 Port Scan

**Location**: 🔍 button on each device row

**Scanned Ports** (19 total):

```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS)
80 (HTTP), 110 (POP3), 135 (RPC), 139 (NetBIOS), 143 (IMAP)
443 (HTTPS), 445 (SMB), 993 (IMAPS), 995 (POP3S)
1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL)
8080 (HTTP Alt), 8443 (HTTPS Alt)
```

### 4.3 Device Management

**Location**: ✏️ button on each device row

**Functions**:
- Edit device name
- Add notes
- Set group

---

## 5. Configuration File

Config file is `config.json` in the same directory:

```json
{
  "scan_interval": 30,              // Scan interval (seconds)
  "scan_timeout": 2,               // Single IP timeout (seconds)
  "ping_count": 1,                 // Ping attempts
  "ip_ranges": ["192.168.2.0/24"], // IP range to scan
  
  "traffic_enabled": true,         // Enable traffic monitoring
  "collect_interval": 5,           // Collection interval (seconds)
  "use_pcap": true,               // Use PCAP for precise traffic
  "interface_name": "",            // Network interface (empty = auto)
  
  "auto_scan_on_start": true,      // Auto scan on startup
  "alert_enabled": true,            // Enable alerts
  
  "notify_windows": true,          // Windows notifications
  "notify_telegram": false,        // Telegram notifications
  "telegram_bot_token": "",        // Telegram Bot Token
  "telegram_chat_id": ""          // Telegram Chat ID
}
```

---

## 6. FAQ

**Q1: Program won't start?**
- Check if port 8080 is in use: `netstat -ano | findstr :8080`
- Kill the conflicting process or change the port

**Q2: Can't scan devices?**
- Check if IP range is correct
- Ensure devices are on the same LAN

**Q3: PCAP won't start?**
- Confirm npcap driver is installed
- Check logs for error messages
- Some adapters may not support PCAP

**Q4: Traffic shows 0?**
- Without PCAP enabled, shows only total traffic
- Check if there's actual network traffic

**Q5: How to run in background?**
- Use `start nm.exe` command
- Or set `minimize_to_tray: true` in config

---

## 7. Version History

| Version | Changes |
|---------|---------|
| v1.3.1 | PCAP support, npcap download link, unit display fix |
| v1.3.0 | ECharts visualization, enhanced port scanning |
| v1.2.0 | Device management, traffic filter, online duration, CSV export |
| v1.1.0 | Attack detection, alert notifications |
| v1.0.0 | Initial release |

---

## 8. Support

- GitHub: https://github.com/lambersWangPika/LanWatchDog
- Issues: https://github.com/lambersWangPika/LanWatchDog/issues

---

*Last updated: 2026-03-13*





# LanWatchDog 局域网设备监控系统

> 版本：v1.3.1 | 更新日期：2026-03-13

---

## 一、系统简介

LanWatchDog 是一款运行在 Windows 上的局域网设备监控工具，主要功能包括：

- 🔍 **局域网设备扫描** - 自动发现网络中的设备
- 📊 **流量监控** - 实时监控网络流量（支持精确到每个设备的流量统计）
- 🛡️ **攻击检测** - 检测局域网内的安全威胁
- 🔔 **告警通知** - 新设备加入、设备离线、异常流量时及时告警
- 📈 **数据可视化** - ECharts 图表展示流量趋势

---

## 二、快速开始

### 2.1 环境要求

- 操作系统：Windows 10/11 或 Windows Server
- 网络：局域网环境
- 权限：管理员（用于网络扫描和流量监控）

### 2.2 安装步骤

1. **下载程序**
   
   从 GitHub 下载最新版本：
   ```
   https://github.com/lambersWangPika/LanWatchDog/releases
   ```

2. **运行程序**
   
   双击 `nm.exe` 即可运行，默认端口 `8080`

3. **访问界面**
   
   打开浏览器访问：`http://localhost:8080` 或 `http://本机IP:8080`

---

## 三、功能详解

### 3.1 设备列表

**位置**：首页默认显示

**功能**：
- 显示所有发现的局域网设备
- 每个设备显示：状态、IP、名称、备注、MAC地址、类型、在线时长、最后在线时间

**操作**：

| 操作 | 说明 |
|------|------|
| 🔍 端口扫描 | 点击扫描按钮，检测设备开放的常用端口（19个端口） |
| ✏️ 编辑 | 修改设备名称、备注、分组 |
| ⭐ 加入白名单 | 将设备加入白名单，避免重复告警 |
| ❌ 移除白名单 | 从白名单中移除 |

**设备状态**：
- 🟢 在线（online）- 设备可响应
- 🔴 离线（offline）- 设备无响应
- 🆕 新设备（new）- 首次发现的设备
- ⭐ 白名单（whitelist）- 已确认安全的设备

**设备类型**：
- 路由器（router）
- 电脑（pc）
- 手机（phone）
- 打印机（printer）
- 平板电脑（tablet）
- 服务器（server）

---

### 3.2 流量监控

**位置**：点击导航栏「📊 流量」

**功能**：
- 实时显示网络入站/出站速率
- 显示总入站/总出站流量
- **精确设备流量**：每个IP的独立流量统计（需要启用PCAP）

**流量趋势图**：
- 入站/出站速率随时间变化的折线图（最近60秒）
- 设备流量占比饼图

**设备流量表**：

| 列名 | 说明 |
|------|------|
| IP | 设备IP地址 |
| 入站 | 累计入站流量 |
| 出站 | 累计出站流量 |
| 速率 | 当前传输速率 |
| 最后更新 | 数据更新时间 |

**流量单位**：
- 自动适配：B → KB → MB → GB → TB

---

### 3.3 告警列表

**位置**：点击导航栏「🔔 告警」

**功能**：
- 显示系统产生的所有告警记录
- 告警分等级：high（高）、medium（中）、low（低）、info（信息）

**告警类型**：
- 新设备加入 - 发现新的局域网设备
- 设备离线 - 设备从在线变为离线
- 流量异常 - 超过设定的流量阈值
- 攻击检测 - 检测到网络攻击

---

### 3.4 攻击检测

**位置**：点击导航栏「🛡️ 攻击」

**功能**：
- 显示检测到的网络攻击记录

**检测类型**：
- 暴力破解（Brute Force）
- 端口扫描（Port Scan）
- 流量洪水（Flood）
- ARP欺骗（ARP Spoof）

---

### 3.5 系统日志

**位置**：点击导航栏「📋 日志」

**功能**：
- 扫描日志：每次扫描的时间、设备数量
- 操作日志：设备白名单操作、配置修改等
- 告警日志：告警触发记录

---

### 3.6 系统统计

**位置**：点击导航栏「📈 统计」

**功能**：
- 设备总数、在线设备、离线设备
- 白名单数量
- 告警数量、攻击数量
- 流量统计：总入站、总出站，入站速率、出站速率

---

### 3.7 设置

**位置**：点击导航栏「⚙️ 设置」

#### 3.7.1 扫描设置

| 设置项 | 说明 | 默认值 |
|--------|------|--------|
| 自动扫描间隔 | 多久自动扫描一次 | 30秒 |

#### 3.7.2 流量监控设置

| 设置项 | 说明 | 默认值 |
|--------|------|--------|
| 流量监控间隔 | 流量数据采集间隔 | 5秒 |
| 全局流量阈值 | 超过此值触发告警 | 100 MB/小时 |

#### 3.7.3 PCAP 精确流量（重点⭐）

**说明**：
- 默认使用 PowerShell 网卡统计，只能获取全局总流量
- 启用 PCAP 后可获取**每个设备的精确流量**

**启用步骤**：

1. 下载 npcap 驱动：https://npcap.com/dist/npcap-1.78.exe

2. 安装 npcap（管理员权限）：
   - 运行下载的安装程序
   - 勾选「Npcap Loopback Adapter」
   - 勾选「Install npcap in WinPcap API-compatible mode」
   - 完成安装

3. 在设置页面：
   - 勾选「启用 PCAP 捕获」
   - 网卡名称留空则自动选择
   - 点击「保存设置」

4. 重启程序生效

**验证**：
- 查看日志，出现 `[PCAP] 已启动流量捕获` 即表示成功
- 流量页面显示每个设备的独立流量

#### 3.7.4 告警设置

| 设置项 | 说明 |
|--------|------|
| 启用告警 | 开启/关闭告警功能 |
| 告警声音 | 是否有告警提示音 |
| 新设备加入 | 新设备发现时告警 |
| 设备离线 | 设备离线时告警 |
| 流量异常 | 流量超过阈值时告警 |
| 攻击检测 | 检测到攻击时告警 |

#### 3.7.5 通知设置

| 设置项 | 说明 |
|--------|------|
| Windows 通知 | 使用 Windows 系统通知 |
| Telegram 通知 | 通过 Telegram Bot 推送 |
| Webhook 通知 | 通过 Webhook URL 推送 |

---

## 四、高级功能

### 4.1 数据导出

**位置**：首页工具栏「📥 导出设备」

**功能**：
- 导出设备列表为 CSV 文件
- 包含：IP、MAC、名称、备注、类型、状态、在线时长等

### 4.2 端口扫描

**位置**：设备列表每行的 🔍 按钮

**功能**：
- 扫描设备开放的常用端口

**扫描的端口**（共19个）：

```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS)
80 (HTTP), 110 (POP3), 135 (RPC), 139 (NetBIOS), 143 (IMAP)
443 (HTTPS), 445 (SMB), 993 (IMAPS), 995 (POP3S)
1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL)
8080 (HTTP Alt), 8443 (HTTPS Alt)
```

### 4.3 设备管理

**位置**：设备列表每行的 ✏️ 按钮

**功能**：
- 修改设备名称
- 添加设备备注
- 设置设备分组

---

## 五、配置文件说明

配置文件位于程序同级目录 `config.json`：

```json
{
  "scan_interval": 30,           // 扫描间隔（秒）
  "scan_timeout": 2,            // 单IP超时（秒）
  "ping_count": 1,              // Ping次数
  "ip_ranges": ["192.168.2.0/24"],  // 扫描IP范围
  
  "traffic_enabled": true,      // 启用流量监控
  "collect_interval": 5,        // 采集间隔（秒）
  "use_pcap": true,            // 使用PCAP精确流量
  "interface_name": "",         // 网卡名称（留空自动）
  
  "auto_scan_on_start": true,  // 启动时自动扫描
  "alert_enabled": true,        // 启用告警
  
  "notify_windows": true,      // Windows通知
  "notify_telegram": false,    // Telegram通知
  "telegram_bot_token": "",     // Telegram Bot Token
  "telegram_chat_id": ""       // Telegram Chat ID
}
```

---

## 六、常见问题

**Q1: 程序无法启动？**
- 检查端口8080是否被占用：`netstat -ano | findstr :8080`
- 尝试关闭占用程序或修改端口

**Q2: 设备扫描不到？**
- 检查IP段设置是否正确
- 确认设备与运行主机在同一局域网

**Q3: PCAP 无法启动？**
- 确认已安装 npcap 驱动
- 检查日志是否有错误信息
- 部分网卡可能不支持PCAP，回退到全局流量模式

**Q4: 流量显示为0？**
- 如果未启用PCAP，显示的是全局流量（需要 npcap 驱动）
- 检查网络是否有流量传输

**Q5: 如何后台运行？**
- 使用 `start nm.exe` 命令启动
- 或修改配置 `minimize_to_tray: true`

---

## 七、版本历史

| 版本 | 更新内容 |
|------|----------|
| v1.3.1 | PCAP精确流量支持、npcap下载链接、单位显示修复 |
| v1.3.0 | ECharts可视化、端口扫描增强 |
| v1.2.0 | 设备管理、流量过滤、在线时长、CSV导出 |
| v1.1.0 | 攻击检测、告警通知 |
| v1.0.0 | 初始版本 |

---

## 八、联系与支持

- GitHub：https://github.com/lambersWangPika/LanWatchDog
- 问题反馈：https://github.com/lambersWangPika/LanWatchDog/issues

---

*文档最后更新：2026-03-13*
