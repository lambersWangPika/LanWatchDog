package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	alerterPkg "network-monitor/internal/alerter"
	"network-monitor/internal/attack"
	"network-monitor/internal/config"
	"network-monitor/internal/logger"
	"network-monitor/internal/models"
	"network-monitor/internal/scanner"
	"network-monitor/internal/traffic"
)

var cfg *config.Config
var scan *scanner.Scanner
var alertMgr *alerterPkg.Alerter
var trafficMon *traffic.Monitor
var attackDet *attack.Detector
var appLogger *logger.Logger

func main() {
	var err error
	
	// 获取程序所在目录
	execPath, _ := os.Executable()
	progDir := filepath.Dir(execPath)
	logDir := filepath.Join(progDir, "Logs")
	
	// 加载配置
	cfg, err = config.Load("config.json")
	if err != nil {
		log.Printf("配置加载失败，使用默认配置: %v", err)
		cfg = config.Default()
		config.Save(cfg, "config.json")
	}

	// 初始化模块
	scan = scanner.New(cfg)
	scan.StartOnlineDurationUpdater() // 启动在线时长更新
	appLogger = logger.New(logDir)
	
	// 设置扫描完成回调，记录日志
	scan.OnScanComplete = func(dev interface{}) {
		if devs, ok := dev.([]*models.Device); ok {
			appLogger.LogScan(devs)
		}
	}
	
	alertMgr = alerterPkg.New(&alerterPkg.Config{
		Enabled:         cfg.AlertEnabled,
		SoundEnabled:    cfg.AlertSoundEnabled,
		NewDeviceAlert:  cfg.NewDeviceAlert,
		OfflineAlert:    cfg.OfflineAlert,
		TrafficAlert:    cfg.TrafficAlert,
		AttackAlert:     cfg.AttackAlert,
		NotifyWindows:   cfg.NotifyWindows,
		NotifyTelegram:  cfg.NotifyTelegram,
		NotifyWebhook:   cfg.NotifyWebhook,
		WebhookURL:      cfg.WebhookURL,
		TelegramBotToken: cfg.TelegramBotToken,
		TelegramChatID:  cfg.TelegramChatID,
	})
	alertMgr.Start()
	
	trafficMon = traffic.New(&traffic.Config{
		Enabled:         cfg.TrafficEnabled,
		CollectInterval: cfg.TrafficInterval,
		GlobalThreshold: cfg.GlobalThreshold,
		ThresholdUnit:   cfg.ThresholdUnit,
	})
	if cfg.TrafficEnabled {
		trafficMon.Start()
	}
	
	attackDet = attack.New(&attack.Config{
		Enabled:            cfg.DefenseEnabled,
		BruteForceDetect:   cfg.BruteForceDetect,
		PortScanDetect:     cfg.PortScanDetect,
		FloodDetect:        cfg.FloodDetect,
		ARPSpoofDetect:     cfg.ARPSpoofDetect,
		MaxConnections:    1000,
		BruteForceThreshold: 10,
	})
	if cfg.DefenseEnabled {
		attackDet.Start()
	}

	// 自动打开浏览器
	go func() {
		time.Sleep(2 * time.Second)
		openBrowser("http://localhost:8080")
	}()

	// API路由
	http.HandleFunc("/", mainPage)
	http.HandleFunc("/api/scan", apiScan)
	http.HandleFunc("/api/portscan", apiPortScan)
	http.HandleFunc("/api/devices", apiDevices)
	http.HandleFunc("/api/device", apiDevice)
	http.HandleFunc("/api/config", apiConfig)
	http.HandleFunc("/api/whitelist", apiWhitelist)
	http.HandleFunc("/api/blacklist", apiBlacklist)
	http.HandleFunc("/api/alerts", apiAlerts)
	http.HandleFunc("/api/traffic", apiTraffic)
	http.HandleFunc("/api/attacks", apiAttacks)
	http.HandleFunc("/api/logs", apiLogs)
	http.HandleFunc("/api/stats", apiStats)
	http.HandleFunc("/api/export", apiExport)
	http.HandleFunc("/api/exit", apiExit)
	
	// 静态文件
	http.Handle("/static/", http.FileServer(http.Dir(".")))

	log.Println("========================================")
	log.Println("  局域网设备监控系统 v1.3.0")
	log.Println("  请访问: http://localhost:8080")
	log.Println("========================================")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func openBrowser(url string) {
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"cmd", "/c", "start", url}
	case "darwin":
		args = []string{"open", url}
	default:
		args = []string{"xdg-open", url}
	}
	exec.Command(args[0], args[1:]...).Start()
}

var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>局域网设备监控系统 v1.3.0</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5}
        .header{background:linear-gradient(135deg,#1890ff 0%,#096dd9 100%);color:white;padding:20px 24px;display:flex;justify-content:space-between;align-items:center}
        .header h1{font-size:22px}
        .toolbar{background:white;padding:16px 24px;border-bottom:1px solid #e8e8e8;display:flex;gap:12px;flex-wrap:wrap}
        .btn{padding:8px 20px;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500;display:inline-flex;align-items:center;gap:6px}
        .btn-primary{background:#1890ff;color:white}
        .btn-primary:hover{background:#40a9ff}
        .btn-default{background:#f5f5f5;color:#333;border:1px solid #d9d9d9}
        .btn-default:hover{background:#e6f7ff;border-color:#1890ff}
        .btn-success{background:#52c41a;color:white}
        .btn-danger{background:#ff4d4f;color:white}
        .btn-warning{background:#faad14;color:white}
        .btn-sm{padding:4px 12px;font-size:12px}
        .content{padding:24px}
        .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
        .stat-card{background:white;padding:20px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
        .stat-card .label{color:#666;font-size:14px}
        .stat-card .value{font-size:28px;font-weight:600}
        
        /* 设置页面样式 */
        .settings-section{background:#fafafa;border-radius:8px;padding:16px;margin-bottom:16px;border:1px solid #e8e8e8}
        .settings-section h4{color:#1890ff;font-size:15px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #e8e8e8}
        .settings-section .form-group{margin-bottom:12px}
        .form-row{display:flex;gap:24px;flex-wrap:wrap;margin-bottom:8px}
        .form-row label{display:flex;align-items:center;gap:6px;white-space:nowrap}
        .form-actions{display:flex;gap:12px;margin-top:16px;padding-top:16px;border-top:1px solid #e8e8e8}
        .stat-card .sub{font-size:12px;color:#999}
        .card{background:white;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);margin-bottom:24px}
        .card-header{padding:16px 24px;border-bottom:1px solid #e8e8e8;font-weight:600;display:flex;justify-content:space-between;align-items:center}
        .card-body{padding:16px 24px}
        table{width:100%;border-collapse:collapse}
        th,td{padding:12px 16px;text-align:left;border-bottom:1px solid #f0f0f0}
        th{background:#fafafa;font-weight:600}
        .status{padding:2px 8px;border-radius:4px;font-size:12px}
        .status-online{background:#f6ffed;color:#52c41a}
        .status-offline{background:#fff1f0;color:#ff4d4f}
        .status-new{background:#e6f7ff;color:#1890ff}
        .status-blocked{background:#fff2e8;color:#fa8c16}
        .status-whitelist{background:#f9f0ff;color:#722ed1}
        .footer{padding:16px 24px;border-top:1px solid #e8e8e8;color:#666;background:white;text-align:center}
        .empty{text-align:center;color:#999;padding:40px}
        .log-area{background:white;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);padding:16px;max-height:200px;overflow:auto}
        .log-item{font-family:monospace;font-size:12px;color:#666;padding:2px 0}
        .tabs{display:flex;border-bottom:1px solid #e8e8e8;padding:0 24px;gap:8px}
        .tab{padding:12px 16px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
        .tab.active{border-bottom-color:#1890ff;color:#1890ff}
        .badge{padding:2px 8px;border-radius:10px;font-size:12px;margin-left:8px}
        .badge-danger{background:#ff4d4f;color:white}
        .badge-warning{background:#faad14;color:white}
        .modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1000}
        .modal.show{display:flex}
        .modal-content{background:white;border-radius:8px;width:90%;max-width:600px;max-height:80vh;overflow:auto}
        .modal-header{padding:16px 24px;border-bottom:1px solid #e8e8e8;font-weight:600}
        .modal-body{padding:24px}
        .modal-footer{padding:16px 24px;border-top:1px solid #e8e8e8;text-align:right}
        .form-group{margin-bottom:16px}
        .form-label{display:block;margin-bottom:8px;font-weight:500}
        .input{padding:8px 12px;border:1px solid #d9d9d9;border-radius:4px;width:100%}
        .input:focus{outline:none;border-color:#40a9ff;box-shadow:0 0 0 2px rgba(24,144,255,0.2)}
        .inline-form{display:inline-flex;gap:8px;align-items:center}
        .inline-form select,.inline-form input{padding:4px 8px;border:1px solid #d9d9d9;border-radius:4px}
        .alert-item{padding:12px;border-radius:4px;margin-bottom:8px;background:#fff1f0;border-left:3px solid #ff4d4f}
        .alert-item.high{border-left-color:#fa8c16}
        .alert-item.medium{border-left-color:#faad14}
        .alert-item.low{border-left-color:#1890ff}
        .log-item{padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px}
        h4{margin:16px 0 8px 0;color:#333}
    </style>
</head>
<body onload="load()">
    <div class="header">
        <h1>🏠 局域网设备监控系统</h1>
        <span>v1.3.0</span>
    </div>
    <div class="toolbar">
        <button class="btn btn-primary" onclick="scan()" id="scanBtn">🔍 开始扫描</button>
        <button class="btn btn-default" onclick="load()">🔄 刷新</button>
        <button class="btn btn-default" onclick="showTab('devices')">📱 设备</button>
        <button class="btn btn-default" onclick="showTab('alerts')">🔔 告警 <span id="alertCount" class="badge badge-danger">0</span></button>
        <button class="btn btn-default" onclick="showTab('traffic')">📊 流量</button>
        <button class="btn btn-default" onclick="showTab('attacks')">🛡️ 攻击</button>
        <button class="btn btn-default" onclick="showTab('logs')">📋 日志</button>
        <button class="btn btn-default" onclick="showTab('stats')">📈 统计</button>
        <button class="btn btn-success" onclick="exportData('devices')">📥 导出设备</button>
        <button class="btn btn-default" onclick="exitApp()">⏹️ 退出</button>
        <button class="btn btn-default" onclick="showTab('settings')">⚙️ 设置</button>
    </div>
    <div class="content">
        <div class="stats">
            <div class="stat-card"><div class="label">设备总数</div><div class="value" id="total">0</div></div>
            <div class="stat-card"><div class="label">在线</div><div class="value" id="online" style="color:#52c41a">0</div></div>
            <div class="stat-card"><div class="label">离线</div><div class="value" id="offline" style="color:#ff4d4f">0</div></div>
            <div class="stat-card"><div class="label">白名单</div><div class="value" id="whitelistCount" style="color:#722ed1">0</div></div>
            <div class="stat-card"><div class="label">流量速率</div><div class="value" id="trafficRate">0</div><div class="sub">KB/s</div></div>
            <div class="stat-card"><div class="label">总入站</div><div class="value" id="homeTotalIn" style="color:#1890ff">0</div><div class="sub">KB</div></div>
            <div class="stat-card"><div class="label">总出站</div><div class="value" id="homeTotalOut" style="color:#52c41a">0</div><div class="sub">KB</div></div>
            <div class="stat-card"><div class="label">告警</div><div class="value" id="alertCount2" style="color:#ff4d4f">0</div></div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <span>📱 设备列表 (<span id="count">0</span>个)</span>
                <div class="inline-form">
                    <input type="text" id="searchInput" placeholder="搜索..." onkeyup="filterDevices()" style="width:150px">
                </div>
            </div>
            <table>
                <thead><tr><th>状态</th><th>IP</th><th>名称</th><th>备注</th><th>MAC</th><th>类型</th><th>在线时长</th><th>最后在线</th><th>操作</th></tr></thead>
                <tbody id="list"><tr><td colspan="10" class="empty">暂无设备，点击"开始扫描"</td></tr></tbody>
            </table>
        </div>
        
        <!-- 告警页面 -->
        <div class="card" id="alertsCard" style="display:none">
            <div class="card-header">
                <span>🔔 告警列表 (<span id="alertListCount">0</span>条)</span>
            </div>
            <div class="card-body" id="alertList">
                <div class="empty">暂无告警</div>
            </div>
        </div>
        
        <!-- 流量页面 -->
        <div class="card" id="trafficCard" style="display:none">
            <div class="card-header">
                <span>📊 流量监控</span>
            </div>
            <div class="card-body">
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px">
                    <div class="stat-card"><div class="label">入站速率</div><div class="value" id="trafficIn">0</div><div class="sub">KB/s</div></div>
                    <div class="stat-card"><div class="label">出站速率</div><div class="value" id="trafficOut">0</div><div class="sub">KB/s</div></div>
                    <div class="stat-card"><div class="label">总入站</div><div class="value" id="trafficTotalIn">0</div><div class="sub">KB</div></div>
                    <div class="stat-card"><div class="label">总出站</div><div class="value" id="trafficTotalOut">0</div><div class="sub">KB</div></div>
                </div>

                <!-- 流量图表 -->
                <h4 style="margin-top:20px">📈 流量趋势图 (最近60秒)</h4>
                <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:16px">
                    <div id="trafficTrendChart" style="height:300px;border:1px solid #e8e8e8;border-radius:8px;padding:8px"></div>
                    <div id="trafficPieChart" style="height:300px;border:1px solid #e8e8e8;border-radius:8px;padding:8px"></div>
                </div>

                <h4 style="margin-top:20px">📊 设备流量</h4>
                <table id="trafficTable"><thead><tr><th>IP</th><th>入站</th><th>出站</th><th>速率</th><th>最后更新</th></tr></thead>
                <tbody id="trafficList"><tr><td colspan="5" class="empty">暂无数据</td></tr></tbody></table>
            </div>
        </div>
        
        <!-- 攻击页面 -->
        <div class="card" id="attacksCard" style="display:none">
            <div class="card-header">
                <span>🛡️ 攻击检测 (<span id="attackCount">0</span>条)</span>
            </div>
            <div class="card-body" id="attackList">
                <div class="empty">暂无攻击记录</div>
            </div>
        </div>
        
        <!-- 日志页面 -->
        <div class="card" id="logsCard" style="display:none">
            <div class="card-header">
                <span>📋 系统日志</span>
            </div>
            <div class="card-body" id="logsList">
                <div class="empty">暂无日志</div>
            </div>
        </div>
        
        <!-- 统计页面 -->
        <div class="card" id="statsCard" style="display:none">
            <div class="card-header">
                <span>📈 系统统计</span>
            </div>
            <div class="card-body" id="statsList">
                <div class="empty">暂无统计</div>
            </div>
        </div>
        
        <!-- 设置页面 -->
        <div class="card" id="settingsCard" style="display:none">
            <div class="card-header">
                <span>⚙️ 系统设置</span>
            </div>
            <div class="card-body">
                <!-- 扫描设置 -->
                <div class="settings-section">
                    <h4>🔍 扫描设置</h4>
                    <div class="form-group">
                        <label>自动扫描间隔: 
                            <select id="scanInterval" style="width:120px">
                                <option value="30">30秒</option>
                                <option value="60">1分钟</option>
                                <option value="300">5分钟</option>
                                <option value="600">10分钟</option>
                                <option value="1800">30分钟</option>
                                <option value="0">禁用</option>
                            </select>
                        </label>
                    </div>
                    <div class="form-group">
                        <label>流量监控间隔: 
                            <select id="trafficInterval" style="width:120px">
                                <option value="1">1秒</option>
                                <option value="5">5秒</option>
                                <option value="10">10秒</option>
                                <option value="30">30秒</option>
                            </select>
                        </label>
                    </div>
                </div>
                
                <!-- 告警设置 -->
                <div class="settings-section">
                    <h4>🔔 告警设置</h4>
                    <div class="form-row">
                        <label><input type="checkbox" id="alertEnabled" checked> 启用告警</label>
                        <label><input type="checkbox" id="alertSound" checked> 告警声音</label>
                    </div>
                    <div class="form-row">
                        <label><input type="checkbox" id="newDeviceAlert" checked> 新设备加入</label>
                        <label><input type="checkbox" id="offlineAlert" checked> 设备离线</label>
                    </div>
                    <div class="form-row">
                        <label><input type="checkbox" id="trafficAlert" checked> 流量异常</label>
                        <label><input type="checkbox" id="attackAlert" checked> 攻击检测</label>
                    </div>
                </div>
                
                <!-- 流量阈值 -->
                <div class="settings-section">
                    <h4>📊 流量监控阈值</h4>
                    <div class="form-group">
                        <label>全局流量阈值: <input type="number" id="globalThreshold" value="100" style="width:100px"> MB/小时</label>
                    </div>
                </div>
                
                <!-- 通知设置 -->
                <div class="settings-section">
                    <h4>📨 通知设置</h4>
                    <div class="form-row">
                        <label><input type="checkbox" id="notifyWindows" checked> Windows 通知</label>
                    </div>
                    <div class="form-group">
                        <label><input type="checkbox" id="notifyTelegram"> Telegram 通知</label>
                    </div>
                    <div class="form-group" style="margin-left:20px">
                        <label>Bot Token: <input type="text" id="telegramToken" style="width:250px" placeholder="请输入Bot Token"></label>
                    </div>
                    <div class="form-group" style="margin-left:20px">
                        <label>Chat ID: <input type="text" id="telegramChatID" style="width:250px" placeholder="请输入Chat ID"></label>
                    </div>
                    <div class="form-group">
                        <label><input type="checkbox" id="notifyWebhook"> Webhook 通知</label>
                    </div>
                    <div class="form-group" style="margin-left:20px">
                        <label>URL: <input type="text" id="webhookURL" style="width:300px" placeholder="请输入Webhook地址"></label>
                    </div>
                </div>
                
                <div class="form-actions">
                    <button class="btn btn-primary" onclick="saveSettings()">💾 保存设置</button>
                    <button class="btn btn-default" onclick="loadSettings()">🔄 重新加载</button>
                </div>
            </div>
        </div>
    </div>
    <div class="footer">🕐 最后扫描: <span id="last">-</span> | 刷新间隔: <span id="refreshInfo">-</span> | 扫描范围: <span id="range">-</span></div>

    <script>
        let devices=[];
        let alerts=[];
        let trafficData={};
        let attackData=[];
        let currentTab='devices';
        
        function log(msg){
            console.log(msg);
        }
        
        function showTab(tab){
            currentTab=tab;
            document.querySelectorAll('.card').forEach(c=>c.style.display='none');
            if(tab==='devices'){
                document.querySelectorAll('.card')[0].style.display='block';
            } else if(tab==='alerts'){
                document.getElementById('alertsCard').style.display='block';
                renderAlerts();
            } else if(tab==='traffic'){
                document.getElementById('trafficCard').style.display='block';
                renderTraffic();
            } else if(tab==='attacks'){
                document.getElementById('attacksCard').style.display='block';
                renderAttacks();
            } else if(tab==='logs'){
                document.getElementById('logsCard').style.display='block';
                renderLogs();
            } else if(tab==='stats'){
                document.getElementById('statsCard').style.display='block';
                renderStats();
            } else if(tab==='settings'){
                document.getElementById('settingsCard').style.display='block';
                loadSettings();
            }
            if(tab==='traffic'){
                renderTraffic();
            }
            load();
        }

        // 响应式图表
        window.addEventListener('resize', function(){
            if(trafficTrendChart) trafficTrendChart.resize();
            if(trafficPieChart) trafficPieChart.resize();
        });
        
        function fmt(t){return t?new Date(t).toLocaleString('zh-CN'):'-';}

        // 格式化在线时长
        function fmtDuration(seconds){
            if(!seconds || seconds <= 0) return '-';
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = seconds % 60;
            if(h > 0) return h+'小时'+m+'分';
            if(m > 0) return m+'分'+s+'秒';
            return s+'秒';
        }

        // 自动格式化字节大小
        function fmtBytes(bytes){
            if(!bytes || bytes <= 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let unitIndex = 0;
            let value = bytes;
            while(value >= 1024 && unitIndex < units.length - 1){
                value /= 1024;
                unitIndex++;
            }
            return value.toFixed(unitIndex > 0 ? 2 : 0) + ' ' + units[unitIndex];
        }

        // 自动格式化速率 (bytes/sec -> KB/s, MB/s 等)
        function fmtRate(bytesPerSec){
            if(!bytesPerSec || bytesPerSec <= 0) return '0 B/s';
            const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
            let unitIndex = 0;
            let value = bytesPerSec;
            while(value >= 1024 && unitIndex < units.length - 1){
                value /= 1024;
                unitIndex++;
            }
            return value.toFixed(unitIndex > 0 ? 2 : 0) + ' ' + units[unitIndex];
        }
        
        function getStatusClass(status, whitelist){
            if(whitelist) return 'status-whitelist';
            if(status==='online') return 'status-online';
            if(status==='offline') return 'status-offline';
            if(status==='new') return 'status-new';
            if(status==='blocked') return 'status-blocked';
            return 'status-offline';
        }
        
        function getStatusText(status, whitelist){
            if(whitelist) return '白名单';
            if(status==='online') return '在线';
            if(status==='offline') return '离线';
            if(status==='new') return '新设备';
            if(status==='blocked') return '已屏蔽';
            return '未知';
        }
        
        function getTypeIcon(type){
            const icons={router:'🔴',server:'🟠',pc:'💻',printer:'🖨️',phone:'📱',tablet:'📲',unknown:'❓'};
            return icons[type]||'❓';
        }
        
        function render(){
            const on = devices.filter(d=>d.status==='online').length;
            const wl = devices.filter(d=>d.whitelist).length;
            document.getElementById('total').textContent=devices.length;
            document.getElementById('online').textContent=on;
            document.getElementById('offline').textContent=devices.length-on;
            document.getElementById('whitelistCount').textContent=wl;
            document.getElementById('alertCount').textContent=alerts.length;
            document.getElementById('alertCount2').textContent=alerts.length;
            document.getElementById('count').textContent=devices.length;
            
            // 更新流量统计
            if(trafficData && trafficData.total_in){
                const totalIn = trafficData.total_in || 0;
                const totalOut = trafficData.total_out || 0;
                const inSpeed = trafficData.rate_in || 0;
                const outSpeed = trafficData.rate_out || 0;
                document.getElementById('trafficRate').textContent=fmtRate(inSpeed + outSpeed);
                document.getElementById('homeTotalIn').textContent=fmtBytes(totalIn);
                document.getElementById('homeTotalOut').textContent=fmtBytes(totalOut);
            }
            
            if(!devices.length){
                document.getElementById('list').innerHTML='<tr><td colspan="10" class="empty">暂无设备</td></tr>';
                return;
            }
            
            document.getElementById('list').innerHTML=devices.map(d=>'<tr>'+
                '<td><span class="status '+getStatusClass(d.status,d.whitelist)+'">'+getStatusText(d.status,d.whitelist)+'</span></td>'+
                '<td><strong>'+d.ip+'</strong></td>'+
                '<td>'+(d.name||d.vendor||'-')+'</td>'+
                '<td>'+(d.notes||'-')+'</td>'+
                '<td>'+(d.mac||'-')+'</td>'+
                '<td>'+(d.type||'unknown')+'</td>'+
                '<td>'+fmtDuration(d.online_duration)+'</td>'+
                '<td>'+fmt(d.last_seen)+'</td>'+
                '<td>'+
                    '<button class="btn btn-sm btn-default" onclick="portScan(\''+d.ip+'\')">🔍</button> '+
                    '<button class="btn btn-sm btn-default" onclick="editDevice(\''+d.ip+'\')">✏️</button> '+
                    (d.whitelist?'<button class="btn btn-sm btn-warning" onclick="removeWhitelist(\''+d.ip+'\')">❌</button>':
                    '<button class="btn btn-sm btn-success" onclick="addWhitelist(\''+d.ip+'\')">⭐</button>')+
                '</td></tr>').join('');
            
            document.getElementById('last').textContent=fmt(new Date());
                console.log('页面刷新 at', new Date());
        }
        
        function load(){
            console.log('[DEBUG] 开始加载数据...');
            Promise.all([
                fetch('/api/devices').then(r=>r.json()).then(d=>{console.log('[DEBUG] devices:', d); return d;}),
                fetch('/api/alerts').then(r=>r.json()).catch(()=>[]),
                fetch('/api/traffic').then(r=>r.json()).catch(()=>({})),
                fetch('/api/config').then(r=>r.json()).catch(()=>({})),
                fetch('/api/attacks').then(r=>r.json()).catch(()=>[])
            ]).then(([d,a,t,c,atk])=>{
                console.log('[DEBUG] 设备数据加载完成, count:', d?d.length:0);
                devices=d||[];
                alerts=a||[];
                trafficData=t||{};
                attackData=atk||[];
                document.getElementById('range').textContent=(c.ip_ranges||[]).join(',');
                console.log('[DEBUG] 调用render(), devices:', devices);
                render();
            }).catch(e=>{
                console.error('[DEBUG] 加载失败:', e);
            });
        }
        
        function scan(){
            const btn=document.getElementById('scanBtn');
            btn.textContent='⏳ 扫描中...';
            fetch('/api/scan',{method:'POST'}).then(r=>r.json()).then(d=>{
                devices=d.devices||[];
                render();
                btn.textContent='🔍 开始扫描';
            }).catch(e=>{btn.textContent='🔍 开始扫描';});
        }
        
        function exitApp(){
            if(confirm('确定要退出程序吗？')){
                fetch('/api/exit',{method:'POST'});
            }
        }
        
        // 导出数据
        function exportData(type_){
            const url = '/api/export?type=' + type_;
            const link = document.createElement('a');
            link.href = url;
            link.download = type_ + '_' + new Date().toISOString().slice(0,10) + '.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // 端口扫描
        function portScan(ip){
            const btn = event.target;
            btn.textContent = '⏳';
            btn.disabled = true;

            fetch('/api/portscan?ip=' + ip)
                .then(r => r.json())
                .then(data => {
                    btn.textContent = '🔍';
                    btn.disabled = false;
                    if(data.open_ports && data.open_ports.length > 0){
                        alert('开放端口: ' + data.open_ports.join(', '));
                    } else {
                        alert('未发现开放端口 (扫描了 ' + data.total_scanned + ' 个常用端口)');
                    }
                })
                .catch(e => {
                    btn.textContent = '🔍';
                    btn.disabled = false;
                    alert('扫描失败: ' + e);
                });
        }

        function addWhitelist(ip){
            fetch('/api/whitelist?action=add&ip='+ip,{method:'POST'}).then(()=>load());
        }
        
        function removeWhitelist(ip){
            fetch('/api/whitelist?action=remove&ip='+ip,{method:'POST'}).then(()=>load());
        }
        
        function editDevice(ip){
            const d=devices.find(x=>x.ip===ip);
            if(!d) return;
            
            // 创建编辑对话框
            const name = prompt('设备名称:', d.name || d.vendor || '');
            if(name === null) return;
            
            const notes = prompt('设备备注:', d.notes || '');
            if(notes === null) return;
            
            const group = prompt('设备分组:', d.group || '');
            if(group === null) return;
            
            fetch('/api/device?action=update&name='+encodeURIComponent(name)+
                  '&notes='+encodeURIComponent(notes)+
                  '&group='+encodeURIComponent(group)+
                  '&ip='+ip,{method:'POST'}).then(()=>load());
        }
        
        function filterDevices(){
            const q=document.getElementById('searchInput').value.toLowerCase();
            const filtered=devices.filter(d=>!q||d.ip.includes(q)||(d.name||'').toLowerCase().includes(q)||(d.mac||'').toLowerCase().includes(q));
            const temp=devices;
            devices=filtered;
            render();
            devices=temp;
        }
        
        // 自动刷新 - 使用配置的流量刷新间隔
        let refreshInterval = 30000; // 默认30秒
        fetch('/api/config').then(r=>r.json()).then(c=>{
            refreshInterval = (c.traffic_interval || 30) * 1000;
            document.getElementById('refreshInfo').textContent = (refreshInterval/1000) + '秒';
            setInterval(load, refreshInterval);
        }).catch(()=>{
            document.getElementById('refreshInfo').textContent = '30秒';
            setInterval(load, 30000);
        });
        
        // 渲染告警
        function renderAlerts(){
            const levelColors={high:'#ff4d4f',medium:'#fa8c16',low:'#1890ff',info:'#52c41a'};
            document.getElementById('alertListCount').textContent=alerts.length;
            if(!alerts.length){
                document.getElementById('alertList').innerHTML='<div class="empty">暂无告警</div>';
                return;
            }
            document.getElementById('alertList').innerHTML=alerts.map(a=>'<div class="alert-item" style="border-left-color:'+(levelColors[a.level]||'#999')+'">'+
                '<div style="display:flex;justify-content:space-between"><strong>'+(a.type||'未知')+'</strong><span style="color:#999">'+fmt(a.timestamp)+'</span></div>'+
                '<div>'+(a.message||'')+'</div>'+
                '<div style="color:#666;font-size:12px">IP: '+(a.ip||'-')+'</div></div>').join('');
        }
        
        // 渲染流量
        // 流量图表实例
        let trafficTrendChart = null;
        let trafficPieChart = null;

        // 初始化图表
        function initCharts(){
            if(trafficTrendChart) return;

            // 趋势图
            trafficTrendChart = echarts.init(document.getElementById('trafficTrendChart'));
            const trendOption = {
                title: { text: '流量趋势 (KB/s)', left: 'center' },
                tooltip: { trigger: 'axis' },
                legend: { data: ['入站', '出站'], top: 30 },
                grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
                xAxis: { type: 'category', boundaryGap: false, data: [] },
                yAxis: { type: 'value' },
                series: [
                    { name: '入站', type: 'line', smooth: true, data: [], areaStyle: { color: 'rgba(24,144,255,0.3)' }, itemStyle: { color: '#1890ff' } },
                    { name: '出站', type: 'line', smooth: true, data: [], areaStyle: { color: 'rgba(82,196,26,0.3)' }, itemStyle: { color: '#52c41a' } }
                ]
            };
            trafficTrendChart.setOption(trendOption);

            // 饼图
            trafficPieChart = echarts.init(document.getElementById('trafficPieChart'));
            const pieOption = {
                title: { text: '设备流量分布', left: 'center' },
                tooltip: { trigger: 'item' },
                legend: { orient: 'vertical', right: 10 },
                series: [
                    {
                        name: '流量',
                        type: 'pie',
                        radius: ['40%', '70%'],
                        avoidLabelOverlap: false,
                        itemStyle: { borderRadius: 10, borderColor: '#fff', borderWidth: 2 },
                        label: { show: false, position: 'center' },
                        emphasis: { label: { show: true, fontSize: 16, fontWeight: 'bold' } },
                        labelLine: { show: false },
                        data: []
                    }
                ]
            };
            trafficPieChart.setOption(pieOption);
        }

        // 更新趋势图
        function updateTrendChart(inSpeed, outSpeed){
            if(!trafficTrendChart) return;
            const now = new Date();
            const time = now.getHours() + ':' + now.getMinutes() + ':' + now.getSeconds();

            const option = trafficTrendChart.getOption();
            if(option.xAxis[0].data.length >= 60){
                option.xAxis[0].data.shift();
                option.series[0].data.shift();
                option.series[1].data.shift();
            }

            option.xAxis[0].data.push(time);
            option.series[0].data.push(inSpeed);
            option.series[1].data.push(outSpeed);

            trafficTrendChart.setOption(option);
        }

        // 更新饼图
        function updatePieChart(devices){
            if(!trafficPieChart) return;

            // 取前5个流量最大的设备 (使用总流量)
            const sorted = [...(devices || [])].sort((a,b) => (b.TotalIn||0) - (a.TotalIn||0)).slice(0, 5);
            const data = sorted.map(d => ({
                name: (d.IP || '*').split('.')[3] || d.IP,
                value: Math.round((d.TotalIn || 0) / 1024 / 1024) // 转为 MB
            }));

            const option = trafficPieChart.getOption();
            option.series[0].data = data;
            trafficPieChart.setOption(option);
        }

        function renderTraffic(){
            if(!trafficData || !trafficData.total_in){
                document.getElementById('trafficList').innerHTML='<tr><td colspan="5" class="empty">暂无数据</td></tr>';
                return;
            }

            // 初始化图表
            initCharts();

            // 显示全局流量统计 (自动单位)
            const totalIn = trafficData.total_in || 0;
            const totalOut = trafficData.total_out || 0;
            const inSpeed = trafficData.rate_in || 0;
            const outSpeed = trafficData.rate_out || 0;

            document.getElementById('trafficIn').textContent=fmtRate(inSpeed);
            document.getElementById('trafficOut').textContent=fmtRate(outSpeed);
            document.getElementById('trafficRate').textContent=fmtRate(inSpeed + outSpeed);
            document.getElementById('trafficTotalIn').textContent=fmtBytes(totalIn);
            document.getElementById('trafficTotalOut').textContent=fmtBytes(totalOut);

            // 更新图表 (转换为 KB/s)
            updateTrendChart(inSpeed / 1024, outSpeed / 1024);
            updatePieChart(trafficData.devices);

            let html = '';

            // 显示设备流量
            if(trafficData.devices && trafficData.devices.length > 0){
                html += '<h4>📊 设备流量详情</h4>';
                html += '<table><thead><tr><th>IP</th><th>入站</th><th>出站</th><th>速率</th><th>最后更新</th></tr></thead><tbody>';
                trafficData.devices.forEach(d => {
                    html += '<tr><td>'+(d.IP||'*')+'</td>'+
                        '<td>'+fmtBytes(d.BytesIn)+'</td>'+
                        '<td>'+fmtBytes(d.BytesOut)+'</td>'+
                        '<td>'+fmtRate(d.RateIn * 1024)+'</td>'+
                        '<td>'+fmt(d.LastUpdate)+'</td></tr>';
                });
                html += '</tbody></table>';
            }

            // 显示活跃连接
            if(trafficData.connections && trafficData.connections.length > 0){
                html += '<h4>🌐 活跃连接</h4>';
                html += '<table><thead><tr><th>本地IP</th><th>远程IP</th><th>端口</th></tr></thead><tbody>';
                trafficData.connections.forEach(c => {
                    html += '<tr><td>'+c.local_ip+'</td><td>'+c.remote_ip+'</td><td>'+c.remote_port+'</td></tr>';
                });
                html += '</tbody></table>';
            }

            if(!html) html = '<div class="empty">暂无数据</div>';
            document.getElementById('trafficList').innerHTML=html;
        }
        
        // 渲染攻击
        function renderAttacks(){
            document.getElementById('attackCount').textContent=attackData.length;
            if(!attackData.length){
                document.getElementById('attackList').innerHTML='<div class="empty">暂无攻击记录</div>';
                return;
            }
            document.getElementById('attackList').innerHTML=attackData.map(a=>'<div class="alert-item high">'+
                '<div style="display:flex;justify-content:space-between"><strong>'+(a.type||'攻击')+'</strong><span style="color:#999">'+fmt(a.timestamp)+'</span></div>'+
                '<div>来源: '+(a.source||'-')+' -> 目标: '+(a.target||'-')+'</div>'+
                '<div style="color:#666;font-size:12px">'+((a.details)||'')+'</div></div>').join('');
        }
        
        // 渲染日志
        function renderLogs(){
            fetch('/api/logs').then(r=>r.json()).then(logs=>{
                let html='';
                if(logs.scan && logs.scan.length){
                    html+='<h4>扫描日志</h4>';
                    logs.scan.slice(-5).reverse().forEach(l=>{
                        html+='<div class="log-item"><span style="color:#999">'+fmt(l.timestamp)+'</span> 扫描: '+l.online_devices+'/'+l.total_devices+' 设备</div>';
                    });
                }
                if(logs.operation && logs.operation.length){
                    html+='<h4>操作日志</h4>';
                    logs.operation.slice(-5).reverse().forEach(l=>{
                        html+='<div class="log-item"><span style="color:#999">'+fmt(l.timestamp)+'</span> '+l.operation+': '+l.target+' - '+(l.details||'')+'</div>';
                    });
                }
                if(logs.alert && logs.alert.length){
                    html+='<h4>告警日志</h4>';
                    logs.alert.slice(-5).reverse().forEach(l=>{
                        html+='<div class="log-item"><span style="color:#999">'+fmt(l.timestamp)+'</span> '+l.type+': '+(l.message||'')+'</div>';
                    });
                }
                document.getElementById('logsList').innerHTML=html||'<div class="empty">暂无日志</div>';
            }).catch(()=>{
                document.getElementById('logsList').innerHTML='<div class="empty">加载失败</div>';
            });
        }
        
        // 渲染统计
        function renderStats(){
            fetch('/api/stats').then(r=>r.json()).then(s=>{
                document.getElementById('statsList').innerHTML='<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px">'+
                    '<div class="stat-card"><div class="label">设备总数</div><div class="value">'+s.total_devices+'</div></div>'+
                    '<div class="stat-card"><div class="label">在线设备</div><div class="value" style="color:#52c41a">'+s.online_devices+'</div></div>'+
                    '<div class="stat-card"><div class="label">离线设备</div><div class="value" style="color:#ff4d4f">'+s.offline_devices+'</div></div>'+
                    '<div class="stat-card"><div class="label">白名单</div><div class="value" style="color:#722ed1">'+s.whitelist_count+'</div></div>'+
                    '<div class="stat-card"><div class="label">告警数</div><div class="value" style="color:#fa8c16">'+s.alert_count+'</div></div>'+
                    '<div class="stat-card"><div class="label">攻击数</div><div class="value" style="color:#ff4d4f">'+s.attack_count+'</div></div>'+
                    '<div class="stat-card"><div class="label">总入站</div><div class="value">'+Math.round(s.traffic_total_in/1024/1024)+' MB</div></div>'+
                    '<div class="stat-card"><div class="label">总出站</div><div class="value">'+Math.round(s.traffic_total_out/1024/1024)+' MB</div></div>'+
                    '<div class="stat-card"><div class="label">入站速率</div><div class="value">'+s.traffic_rate_in.toFixed(2)+' KB/s</div></div></div>';
            }).catch(()=>{
                document.getElementById('statsList').innerHTML='<div class="empty">加载失败</div>';
            });
        }
        
        // 加载设置
        function loadSettings(){
            fetch('/api/config').then(r=>r.json()).then(c=>{
                document.getElementById('scanInterval').value = c.scan_interval || 60;
                document.getElementById('trafficInterval').value = c.traffic_interval || 5;
                document.getElementById('alertEnabled').checked = c.alert_enabled !== false;
                document.getElementById('alertSound').checked = c.alert_sound_enabled !== false;
                document.getElementById('newDeviceAlert').checked = c.new_device_alert !== false;
                document.getElementById('offlineAlert').checked = c.offline_alert !== false;
                document.getElementById('trafficAlert').checked = c.traffic_alert !== false;
                document.getElementById('attackAlert').checked = c.attack_alert !== false;
                document.getElementById('globalThreshold').value = c.global_threshold || 100;
                document.getElementById('notifyWindows').checked = c.notify_windows !== false;
                document.getElementById('notifyTelegram').checked = c.notify_telegram === true;
                document.getElementById('telegramToken').value = c.telegram_bot_token || '';
                document.getElementById('telegramChatID').value = c.telegram_chat_id || '';
                document.getElementById('notifyWebhook').checked = c.notify_webhook === true;
                document.getElementById('webhookURL').value = c.webhook_url || '';
            });
        }
        
        // 保存设置
        function saveSettings(){
            // 获取当前配置，保留未修改的字段
            fetch('/api/config').then(r=>r.json()).then(currentConfig=>{
                const data = {
                    // 保留原有值或使用默认值
                    ip_ranges: currentConfig.ip_ranges || ["192.168.2.0/24"],
                    scan_timeout: currentConfig.scan_timeout || 2,
                    ping_count: currentConfig.ping_count || 1,
                    
                    scan_interval: parseInt(document.getElementById('scanInterval').value) || 60,
                    traffic_interval: parseInt(document.getElementById('trafficInterval').value) || 5,
                    alert_enabled: document.getElementById('alertEnabled').checked,
                    alert_sound_enabled: document.getElementById('alertSound').checked,
                    new_device_alert: document.getElementById('newDeviceAlert').checked,
                    offline_alert: document.getElementById('offlineAlert').checked,
                    traffic_alert: document.getElementById('trafficAlert').checked,
                    attack_alert: document.getElementById('attackAlert').checked,
                    global_threshold: parseInt(document.getElementById('globalThreshold').value) || 100,
                    notify_windows: document.getElementById('notifyWindows').checked,
                    notify_telegram: document.getElementById('notifyTelegram').checked,
                    telegram_bot_token: document.getElementById('telegramToken').value,
                    telegram_chat_id: document.getElementById('telegramChatID').value,
                    notify_webhook: document.getElementById('notifyWebhook').checked,
                    webhook_url: document.getElementById('webhookURL').value,
                };
                fetch('/api/config',{
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify(data)
                }).then(r=>r.json()).then(d=>{
                    if(d.success){
                        alert('设置保存成功！');
                    } else {
                        alert('保存失败: '+(d.error||'未知错误'));
                    }
                }).catch(e=>alert('保存失败: '+e));
            });
        }
        
        log('系统启动 v1.2.0');
        load();
    </script>
</body>
</html>`))

func mainPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pageTmpl.Execute(w, nil)
}

func apiScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	devices, err := scan.Scan()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	// 记录日志
	appLogger.LogScan(devices)
	json.NewEncoder(w).Encode(map[string]interface{}{"count": len(devices), "devices": devices})
}

// apiPortScan 端口扫描
func apiPortScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	ip := r.URL.Query().Get("ip")
	portsStr := r.URL.Query().Get("ports")
	
	if ip == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "请指定 IP 地址"})
		return
	}
	
	// 默认扫描常用端口
	ports := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443}
	
	// 如果指定了端口
	if portsStr != "" {
		ports = []int{}
		for _, p := range strings.Split(portsStr, ",") {
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}
	
	// 扫描端口
	openPorts := []int{}
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip": ip,
		"open_ports": openPorts,
		"total_scanned": len(ports),
	})
}

func apiDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan.GetDevices())
}

func apiDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := r.URL.Query().Get("ip")
	action := r.URL.Query().Get("action")
	
	if action == "update" {
		name := r.URL.Query().Get("name")
		group := r.URL.Query().Get("group")
		whitelist := r.URL.Query().Get("whitelist") == "true"
		notes := r.URL.Query().Get("notes")
		
		err := scan.UpdateDevice(ip, name, group, whitelist, notes)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		appLogger.LogOperation("update_device", ip, "Updated: "+name+" notes: "+notes)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	
	device := scan.GetDevice(ip)
	if device == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "设备不存在"})
		return
	}
	json.NewEncoder(w).Encode(device)
}

func apiConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method == "POST" {
		// 读取请求body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		
		// 使用MergeConfig合并配置，保留未指定的字段
		mergedCfg, err := config.MergeConfig(cfg, bodyBytes)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		*cfg = *mergedCfg
		config.Save(cfg, "config.json")
		
		// 动态更新各模块配置
		scan.SetConfig(cfg)
		trafficMon.SetConfig(&traffic.Config{
			Enabled:         cfg.TrafficEnabled,
			CollectInterval: cfg.TrafficInterval,
			GlobalThreshold: cfg.GlobalThreshold,
			ThresholdUnit:   cfg.ThresholdUnit,
		})
		alertMgr.SetConfig(&alerterPkg.Config{
			Enabled:         cfg.AlertEnabled,
			SoundEnabled:    cfg.AlertSoundEnabled,
			NewDeviceAlert:  cfg.NewDeviceAlert,
			OfflineAlert:    cfg.OfflineAlert,
			TrafficAlert:    cfg.TrafficAlert,
			AttackAlert:     cfg.AttackAlert,
			NotifyWindows:   cfg.NotifyWindows,
			NotifyTelegram:  cfg.NotifyTelegram,
			NotifyWebhook:   cfg.NotifyWebhook,
			WebhookURL:      cfg.WebhookURL,
			TelegramBotToken: cfg.TelegramBotToken,
			TelegramChatID:  cfg.TelegramChatID,
		})
		
		appLogger.LogOperation("config_update", "", "Configuration updated")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	
	json.NewEncoder(w).Encode(cfg)
}

func apiWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := r.URL.Query().Get("ip")
	action := r.URL.Query().Get("action")
	
	// 获取白名单设备列表
	if ip == "" {
		json.NewEncoder(w).Encode(scan.GetWhitelist())
		return
	}
	
	// 查询单个设备的白名单状态
	if action == "" {
		device := scan.GetDevice(ip)
		if device != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ip": ip, "whitelist": device.Whitelist})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "device not found"})
		}
		return
	}
	
	switch action {
	case "add":
		scan.SetWhitelist(ip, true)
		appLogger.LogOperation("whitelist_add", ip, "Added to whitelist")
		alertMgr.Alert("info", "whitelist", ip, "", "设备添加到白名单: "+ip)
	case "remove":
		scan.SetWhitelist(ip, false)
		appLogger.LogOperation("whitelist_remove", ip, "Removed from whitelist")
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func apiBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan.GetBlacklist())
}

func apiAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alertMgr.GetRecentAlerts(50))
}

func apiTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rateIn, rateOut, totalIn, totalOut := trafficMon.GetGlobalTraffic()
	// 只返回局域网设备流量
	lanDevices := trafficMon.GetLANTraffic()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rate_in": rateIn,
		"rate_out": rateOut,
		"total_in": totalIn,
		"total_out": totalOut,
		"devices": lanDevices,
		"connections": trafficMon.GetConnections(),
	})
}

func apiAttacks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attackDet.GetRecentAlerts(50))
}

func apiLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logType := r.URL.Query().Get("type")
	limit := 50
	
	switch logType {
	case "scan":
		json.NewEncoder(w).Encode(appLogger.GetScanLogs(limit))
	case "alert":
		json.NewEncoder(w).Encode(appLogger.GetAlertLogs(limit))
	case "attack":
		json.NewEncoder(w).Encode(appLogger.GetAttackLogs(limit))
	case "operation":
		json.NewEncoder(w).Encode(appLogger.GetOperationLogs(limit))
	default:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scan": appLogger.GetScanLogs(limit),
			"alert": appLogger.GetAlertLogs(limit),
			"attack": appLogger.GetAttackLogs(limit),
			"operation": appLogger.GetOperationLogs(limit),
		})
	}
}

func apiStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	devices := scan.GetDevices()
	online := 0
	for _, d := range devices {
		if d.Status == "online" {
			online++
		}
	}
	
	rateIn, rateOut, totalIn, totalOut := trafficMon.GetGlobalTraffic()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_devices": len(devices),
		"online_devices": online,
		"offline_devices": len(devices) - online,
		"whitelist_count": len(scan.GetWhitelist()),
		"alert_count": len(alertMgr.GetAlerts()),
		"attack_count": len(attackDet.GetAlerts()),
		"traffic_rate_in": rateIn,
		"traffic_rate_out": rateOut,
		"traffic_total_in": totalIn,
		"traffic_total_out": totalOut,
	})
}

// apiExport 导出数据为 CSV 格式
func apiExport(w http.ResponseWriter, r *http.Request) {
	exportType := r.URL.Query().Get("type")
	
	if exportType == "devices" {
		devices := scan.GetDevices()
		csv := "IP,MAC,名称,备注,类型,状态,在线时长,首次发现,最后在线\n"
		for _, d := range devices {
			duration := fmt.Sprintf("%d秒", d.OnlineDuration)
			if d.OnlineDuration > 3600 {
				duration = fmt.Sprintf("%.1f小时", float64(d.OnlineDuration)/3600)
			}
			csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
				d.IP, d.MAC, d.Name, d.Notes, d.Type, d.Status, duration,
				d.FirstSeen.Format("2006-01-02 15:04:05"),
				d.LastSeen.Format("2006-01-02 15:04:05"))
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=devices.csv")
		w.Write([]byte(csv))
		return
	}
	
	if exportType == "traffic" {
		devices := trafficMon.GetLANTraffic()
		csv := "IP,入站(字节),出站(字节),速率入站(KB/s),速率出站(KB/s),总入站(字节),总出站(字节),最后更新\n"
		for _, d := range devices {
			csv += fmt.Sprintf("%s,%d,%d,%.2f,%.2f,%d,%d,%s\n",
				d.IP, d.BytesIn, d.BytesOut, d.RateIn, d.RateOut, d.TotalIn, d.TotalOut,
				d.LastUpdate.Format("2006-01-02 15:04:05"))
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=traffic.csv")
		w.Write([]byte(csv))
		return
	}
	
	if exportType == "alerts" {
		alerts := alertMgr.GetAlerts()
		csv := "时间,类型,级别,IP,MAC,消息\n"
		for _, a := range alerts {
			csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
				a.Timestamp.Format("2006-01-02 15:04:05"),
				a.Type, a.Level, a.IP, a.MAC, a.Message)
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=alerts.csv")
		w.Write([]byte(csv))
		return
	}
	
	// 默认返回设备列表
	devices := scan.GetDevices()
	csv := "IP,MAC,名称,备注,类型,状态\n"
	for _, d := range devices {
		csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s\n", d.IP, d.MAC, d.Name, d.Notes, d.Type, d.Status)
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=export.csv")
	w.Write([]byte(csv))
}

func apiExit(w http.ResponseWriter, r *http.Request) {
	log.Println("收到退出请求，正在关闭程序...")
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func init() {
	os.MkdirAll("logs", 0755)
}
