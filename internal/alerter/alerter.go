package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"network-monitor/internal/models"
)

// Alerter 告警器
type Alerter struct {
	cfg       *Config
	alerts    []*models.Alert
	notifyChan chan *models.Alert
}

// Config 告警配置
type Config struct {
	Enabled         bool   `json:"enabled"`
	SoundEnabled    bool   `json:"sound_enabled"`
	NewDeviceAlert  bool   `json:"new_device_alert"`
	OfflineAlert    bool   `json:"offline_alert"`
	TrafficAlert    bool   `json:"traffic_alert"`
	AttackAlert     bool   `json:"attack_alert"`
	NotifyWindows   bool   `json:"notify_windows"`
	NotifyTelegram  bool   `json:"notify_telegram"`
	NotifyWebhook   bool   `json:"notify_webhook"`
	WebhookURL      string `json:"webhook_url"`
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID  string `json:"telegram_chat_id"`
}

// New 创建告警器
func New(cfg *Config) *Alerter {
	return &Alerter{
		cfg:       cfg,
		alerts:    make([]*models.Alert, 0),
		notifyChan: make(chan *models.Alert, 100),
	}
}

// Start 启动告警器
func (a *Alerter) Start() {
	go a.processAlerts()
}

// Stop 停止告警器
func (a *Alerter) Stop() {
	close(a.notifyChan)
}

// SetConfig 更新配置
func (a *Alerter) SetConfig(cfg *Config) {
	a.cfg = cfg
}

// Alert 发送告警
func (a *Alerter) Alert(level string, alertType string, ip string, mac string, message string) {
	if !a.cfg.Enabled {
		return
	}

	alert := &models.Alert{
		ID:        generateID(),
		Timestamp: time.Now(),
		Type:      alertType,
		Level:     level,
		IP:        ip,
		MAC:       mac,
		Message:   message,
		Handled:   false,
	}

	// 检查是否需要告警
	switch alertType {
	case "new_device":
		if !a.cfg.NewDeviceAlert {
			return
		}
	case "offline":
		if !a.cfg.OfflineAlert {
			return
		}
	case "traffic":
		if !a.cfg.TrafficAlert {
			return
		}
	case "attack":
		if !a.cfg.AttackAlert {
			return
		}
	}

	a.alerts = append(a.alerts, alert)
	a.notifyChan <- alert
}

// 处理告警
func (a *Alerter) processAlerts() {
	for alert := range a.notifyChan {
		log.Printf("🔔 告警 [%s] %s: %s", alert.Level, alert.IP, alert.Message)
		
		// Windows 气泡通知
		if runtime.GOOS == "windows" && a.cfg.NotifyWindows {
			a.sendWindowsNotification(alert)
		}
		
		// 声音提醒
		if a.cfg.SoundEnabled {
			a.playSound(alert.Level)
		}
		
		// Telegram 通知
		if a.cfg.NotifyTelegram && a.cfg.TelegramBotToken != "" && a.cfg.TelegramChatID != "" {
			a.sendTelegramNotification(alert)
		}
		
		// Webhook 通知
		if a.cfg.NotifyWebhook && a.cfg.WebhookURL != "" {
			a.sendWebhookNotification(alert)
		}
	}
}

// 发送 Windows 通知
func (a *Alerter) sendWindowsNotification(alert *models.Alert) {
	title := "局域网监控告警"
	if alert.Level == "critical" {
		title = "🔴 严重告警 - " + title
	} else if alert.Level == "high" {
		title = "🟠 高危告警 - " + title
	} else if alert.Level == "medium" {
		title = "🟡 中危告警 - " + title
	} else {
		title = "🔵 告警 - " + title
	}

	// 使用 PowerShell 显示气泡通知
	script := `
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.SystemIcons]::Info
$balloon.BalloonTipTitle = '` + title + `'
$balloon.BalloonTipText = '` + alert.Message + `'
$balloon.Visible = $true
$balloon.ShowBalloonTip(5000)
Start-Sleep -Seconds 1
$balloon.Dispose()
`
	exec.Command("powershell", "-Command", script).Start()
}

// 播放声音
func (a *Alerter) playSound(level string) {
	var sound string
	switch level {
	case "critical":
		sound = "SystemExclamation"
	case "high":
		sound = "SystemHand"
	default:
		sound = "SystemAsterisk"
	}
	
	if runtime.GOOS == "windows" {
		exec.Command("powershell", "-Command", 
			"[System.Media.SystemSounds]::"+sound+".Play()").Start()
	}
}

// GetAlerts 获取告警列表
func (a *Alerter) GetAlerts() []*models.Alert {
	return a.alerts
}

// GetRecentAlerts 获取最近告警
func (a *Alerter) GetRecentAlerts(count int) []*models.Alert {
	if count > len(a.alerts) {
		count = len(a.alerts)
	}
	result := make([]*models.Alert, count)
	copy(result, a.alerts[len(a.alerts)-count:])
	return result
}

// ClearAlerts 清除告警
func (a *Alerter) ClearAlerts() {
	a.alerts = make([]*models.Alert, 0)
}

// 生成ID
func generateID() string {
	return time.Now().Format("20060102150405")
}

// 发送 Telegram 通知
func (a *Alerter) sendTelegramNotification(alert *models.Alert) {
	title := "局域网监控告警"
	message := fmt.Sprintf("%s\n\nIP: %s\n消息: %s\n时间: %s", 
		title, alert.IP, alert.Message, alert.Timestamp.Format("2006-01-02 15:04:05"))
	
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", a.cfg.TelegramBotToken)
	data := map[string]string{
		"chat_id": a.cfg.TelegramChatID,
		"text":    message,
	}
	
	jsonData, _ := json.Marshal(data)
	http.Post(url, "application/json", bytes.NewBuffer(jsonData))
}

// 发送 Webhook 通知
func (a *Alerter) sendWebhookNotification(alert *models.Alert) {
	data := map[string]interface{}{
		"title":   "局域网监控告警",
		"level":   alert.Level,
		"type":    alert.Type,
		"ip":      alert.IP,
		"mac":     alert.MAC,
		"message": alert.Message,
		"time":    alert.Timestamp.Format("2006-01-02 15:04:05"),
	}
	
	jsonData, _ := json.Marshal(data)
	http.Post(a.cfg.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
}
