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
   - Check「Install npcap in WinPap API-compatible mode」
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

### Q1: Program won't start?
- Check if port 8080 is in use: `netstat -ano | findstr :8080`
- Kill the conflicting process or change the port

### Q2: Can't scan devices?
- Check if IP range is correct
- Ensure devices are on the same LAN

### Q3: PCAP won't start?
- Confirm npcap driver is installed
- Check logs for error messages
- Some adapters may not support PCAP

### Q4: Traffic shows 0?
- Without PCAP enabled, shows only total traffic
- Check if there's actual network traffic

### Q5: How to run in background?
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
