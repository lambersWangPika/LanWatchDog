package config

import (
	"encoding/json"
	"os"
)

// Config 应用配置
type Config struct {
	// 扫描设置
	ScanInterval   int    `json:"scan_interval"`   // 扫描间隔(分钟)
	ScanTimeout    int    `json:"scan_timeout"`    // 单个IP超时(秒)
	PingCount      int    `json:"ping_count"`      // Ping次数
	IPRanges       []string `json:"ip_ranges"`     // 扫描IP范围

	// 流量监控
	TrafficEnabled bool   `json:"traffic_enabled"` // 是否启用流量监控
	CollectInterval int  `json:"collect_interval"` // 采集间隔(秒)
	TrafficInterval int  `json:"traffic_interval"` // 流量刷新间隔(秒)
	GlobalThreshold int  `json:"global_threshold"` // 全局阈值(MB/小时)
	ThresholdUnit   string `json:"threshold_unit"` // 阈值单位

	// 防御设置
	DefenseEnabled     bool `json:"defense_enabled"`      // 是否启用防御
	BruteForceDetect   bool `json:"brute_force_detect"`    // 暴力破解检测
	PortScanDetect     bool `json:"port_scan_detect"`      // 端口扫描检测
	FloodDetect        bool `json:"flood_detect"`           // 洪水攻击检测
	ARPSpoofDetect     bool `json:"arp_spoof_detect"`      // ARP欺骗检测

	// 告警设置
	AlertEnabled      bool `json:"alert_enabled"`       // 告警启用
	AlertSoundEnabled bool `json:"alert_sound_enabled"` // 告警声音
	NewDeviceAlert    bool `json:"new_device_alert"`   // 新设备告警
	OfflineAlert      bool `json:"offline_alert"`      // 离线告警
	TrafficAlert      bool `json:"traffic_alert"`      // 流量告警
	AttackAlert       bool `json:"attack_alert"`       // 攻击告警
	
	// 通知设置
	NotifyWindows bool   `json:"notify_windows"`   // Windows通知
	NotifyTelegram bool  `json:"notify_telegram"`  // Telegram通知
	NotifyWebhook  bool  `json:"notify_webhook"`   // Webhook通知
	WebhookURL    string `json:"webhook_url"`      // Webhook地址
	TelegramBotToken string `json:"telegram_bot_token"` // Telegram机器人Token
	TelegramChatID  string `json:"telegram_chat_id"`   // Telegram聊天ID

	// 常规设置
	AutoStart       bool `json:"auto_start"`        // 开机启动
	MinimizeToTray  bool `json:"minimize_to_tray"`  // 最小化到托盘
	AutoScanOnStart bool `json:"auto_scan_on_start"` // 启动时扫描
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		// 扫描默认设置
		ScanInterval:  5,
		ScanTimeout:   1,  // 减少超时
		PingCount:     1,
		IPRanges:      []string{"192.168.2.0/24"},

		// 流量默认设置
		TrafficEnabled:  true,
		CollectInterval:  1,
		TrafficInterval:  5,
		GlobalThreshold:  100,
		ThresholdUnit:   "MB/hour",

		// 防御默认设置
		DefenseEnabled:    true,
		BruteForceDetect:  true,
		PortScanDetect:    true,
		FloodDetect:       true,
		ARPSpoofDetect:    true,

		// 告警默认设置
		AlertEnabled:      true,
		AlertSoundEnabled: true,
		NewDeviceAlert:    true,
		OfflineAlert:      true,
		TrafficAlert:     true,
		AttackAlert:      true,
		
		// 通知默认设置
		NotifyWindows: true,  // 默认开启Windows通知
		NotifyTelegram: false,
		NotifyWebhook:  false,
		WebhookURL:     "",
		TelegramBotToken: "",
		TelegramChatID:  "",

		// 常规默认设置
		AutoStart:       false,
		MinimizeToTray:  true,
		AutoScanOnStart: true,
	}
}

// Load 加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Save 保存配置
func Save(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	return nil
}

// MergeConfig 合并配置 - 只更新JSON中存在的字段
func MergeConfig(original *Config, jsonData []byte) (*Config, error) {
	var updateMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &updateMap); err != nil {
		return nil, err
	}

	merged := *original

	// 扫描设置
	if v, ok := updateMap["scan_interval"]; ok {
		if f, ok := v.(float64); ok { merged.ScanInterval = int(f) }
	}
	if v, ok := updateMap["scan_timeout"]; ok {
		if f, ok := v.(float64); ok { merged.ScanTimeout = int(f) }
	}
	if v, ok := updateMap["ping_count"]; ok {
		if f, ok := v.(float64); ok { merged.PingCount = int(f) }
	}
	if v, ok := updateMap["ip_ranges"]; ok {
		if arr, ok := v.([]interface{}); ok {
			merged.IPRanges = make([]string, len(arr))
			for i, item := range arr {
				if s, ok := item.(string); ok { merged.IPRanges[i] = s }
			}
		}
	}

	// 流量监控
	if v, ok := updateMap["traffic_enabled"]; ok {
		if b, ok := v.(bool); ok { merged.TrafficEnabled = b }
	}
	if v, ok := updateMap["collect_interval"]; ok {
		if f, ok := v.(float64); ok { merged.CollectInterval = int(f) }
	}
	if v, ok := updateMap["traffic_interval"]; ok {
		if f, ok := v.(float64); ok { merged.TrafficInterval = int(f) }
	}
	if v, ok := updateMap["global_threshold"]; ok {
		if f, ok := v.(float64); ok { merged.GlobalThreshold = int(f) }
	}
	if v, ok := updateMap["threshold_unit"]; ok {
		if s, ok := v.(string); ok { merged.ThresholdUnit = s }
	}

	// 防御设置
	if v, ok := updateMap["defense_enabled"]; ok {
		if b, ok := v.(bool); ok { merged.DefenseEnabled = b }
	}
	if v, ok := updateMap["brute_force_detect"]; ok {
		if b, ok := v.(bool); ok { merged.BruteForceDetect = b }
	}
	if v, ok := updateMap["port_scan_detect"]; ok {
		if b, ok := v.(bool); ok { merged.PortScanDetect = b }
	}
	if v, ok := updateMap["flood_detect"]; ok {
		if b, ok := v.(bool); ok { merged.FloodDetect = b }
	}
	if v, ok := updateMap["arp_spoof_detect"]; ok {
		if b, ok := v.(bool); ok { merged.ARPSpoofDetect = b }
	}

	// 告警设置
	if v, ok := updateMap["alert_enabled"]; ok {
		if b, ok := v.(bool); ok { merged.AlertEnabled = b }
	}
	if v, ok := updateMap["alert_sound_enabled"]; ok {
		if b, ok := v.(bool); ok { merged.AlertSoundEnabled = b }
	}
	if v, ok := updateMap["new_device_alert"]; ok {
		if b, ok := v.(bool); ok { merged.NewDeviceAlert = b }
	}
	if v, ok := updateMap["offline_alert"]; ok {
		if b, ok := v.(bool); ok { merged.OfflineAlert = b }
	}
	if v, ok := updateMap["traffic_alert"]; ok {
		if b, ok := v.(bool); ok { merged.TrafficAlert = b }
	}
	if v, ok := updateMap["attack_alert"]; ok {
		if b, ok := v.(bool); ok { merged.AttackAlert = b }
	}

	// 通知设置
	if v, ok := updateMap["notify_windows"]; ok {
		if b, ok := v.(bool); ok { merged.NotifyWindows = b }
	}
	if v, ok := updateMap["notify_telegram"]; ok {
		if b, ok := v.(bool); ok { merged.NotifyTelegram = b }
	}
	if v, ok := updateMap["notify_webhook"]; ok {
		if b, ok := v.(bool); ok { merged.NotifyWebhook = b }
	}
	if v, ok := updateMap["webhook_url"]; ok {
		if s, ok := v.(string); ok { merged.WebhookURL = s }
	}
	if v, ok := updateMap["telegram_bot_token"]; ok {
		if s, ok := v.(string); ok { merged.TelegramBotToken = s }
	}
	if v, ok := updateMap["telegram_chat_id"]; ok {
		if s, ok := v.(string); ok { merged.TelegramChatID = s }
	}

	// 常规设置
	if v, ok := updateMap["auto_start"]; ok {
		if b, ok := v.(bool); ok { merged.AutoStart = b }
	}
	if v, ok := updateMap["minimize_to_tray"]; ok {
		if b, ok := v.(bool); ok { merged.MinimizeToTray = b }
	}
	if v, ok := updateMap["auto_scan_on_start"]; ok {
		if b, ok := v.(bool); ok { merged.AutoScanOnStart = b }
	}

	return &merged, nil
}
