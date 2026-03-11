package models

import (
	"time"
)

// DeviceType 设备类型
type DeviceType string

const (
	DeviceTypeRouter   DeviceType = "router"
	DeviceTypeServer   DeviceType = "server"
	DeviceTypePC       DeviceType = "pc"
	DeviceTypePrinter  DeviceType = "printer"
	DeviceTypePhone    DeviceType = "phone"
	DeviceTypeTablet   DeviceType = "tablet"
	DeviceTypeUnknown  DeviceType = "unknown"
)

// DeviceStatus 设备状态
type DeviceStatus string

const (
	StatusOnline  DeviceStatus = "online"
	StatusOffline DeviceStatus = "offline"
	StatusNew     DeviceStatus = "new"
	StatusBlocked DeviceStatus = "blocked"
)

// SecurityStatus 安全状态
type SecurityStatus string

const (
	SecurityNormal          SecurityStatus = "normal"
	SecurityTrafficWarning SecurityStatus = "traffic_warning"
	SecurityAttackWarning  SecurityStatus = "attack_warning"
	SecurityUnderAttack    SecurityStatus = "under_attack"
)

// Device 设备信息
type Device struct {
	IP              string         `json:"ip"`
	MAC             string         `json:"mac"`
	Vendor          string         `json:"vendor"`
	Name            string         `json:"name"`
	Type            DeviceType     `json:"type"`
	Status          DeviceStatus   `json:"status"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	OnlineDuration  int64          `json:"online_duration"` // 秒
	WasOnline       bool           `json:"was_online"`      // 是否曾经上线过
	Group           string         `json:"group"`
	Whitelist       bool           `json:"whitelist"`
	AlertEnabled    bool           `json:"alert_enabled"`
	TrafficEnabled  bool           `json:"traffic_enabled"`
	TrafficThreshold int           `json:"traffic_threshold"`  // MB/小时
	DefenseEnabled  bool           `json:"defense_enabled"`
	AttackCount     int            `json:"attack_count"`
	SecurityStatus  SecurityStatus `json:"security_status"`

	// 运行时数据
	TrafficIn  int64 `json:"traffic_in"`  // 实时入站速率 KB/s
	TrafficOut int64 `json:"traffic_out"` // 实时出站速率 KB/s
}

// TrafficAlert 流量预警
type TrafficAlert struct {
	ID           string    `json:"id"`
	IP           string    `json:"ip"`
	Threshold    int       `json:"threshold"`
	ThresholdUnit string   `json:"threshold_unit"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	PeakRate     float64   `json:"peak_rate"`
	TotalTraffic float64   `json:"total_traffic"`
	Duration     int       `json:"duration"` // 秒
	Status       string    `json:"status"`   // active/recovered
}

// AttackAlert 攻击预警
type AttackAlert struct {
	ID            string    `json:"id"`
	AttackType    string    `json:"attack_type"`
	TargetIP      string    `json:"target_ip"`
	SourceIP      string    `json:"source_ip"`
	SourcePort    int       `json:"source_port"`
	TargetPort    int       `json:"target_port"`
	Protocol      string    `json:"protocol"`
	ThreatLevel   string    `json:"threat_level"` // critical/high/medium/low
	Frequency     int       `json:"frequency"`
	FrequencyUnit string    `json:"frequency_unit"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	AttackCount   int       `json:"attack_count"`
	Status        string    `json:"status"` // active/blocked/recorded
	ActionTaken   string    `json:"action_taken"`
	Details       string    `json:"details"`
}

// Alert 通用告警
type Alert struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Level     string    `json:"level"` // critical/high/medium/low
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Message   string    `json:"message"`
	Handled   bool      `json:"handled"`
}

// ScanLog 扫描日志
type ScanLog struct {
	Timestamp   time.Time  `json:"timestamp"`
	TotalDevices int       `json:"total_devices"`
	OnlineDevices int      `json:"online_devices"`
	Devices     []Device  `json:"devices"`
}

// OperationLog 操作日志
type OperationLog struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Details   string    `json:"details"`
}

// AttackLog 攻击日志
type AttackLog struct {
	Timestamp  time.Time `json:"timestamp"`
	AttackType string    `json:"attack_type"`
	SourceIP   string    `json:"source_ip"`
	TargetIP  string    `json:"target_ip"`
	ThreatLevel string   `json:"threat_level"`
	Details    string    `json:"details"`
}
