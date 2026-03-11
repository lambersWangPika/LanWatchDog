package attack

import (
	"log"
	"strconv"
	"sync"
	"time"

	"network-monitor/internal/models"
)

// Detector 攻击检测器
type Detector struct {
	cfg          *Config
	connections  map[string]*Connection
	mu           sync.RWMutex
	stopChan     chan struct{}
	alerts       []*models.AttackAlert
}

// Config 攻击检测配置
type Config struct {
	Enabled           bool `json:"enabled"`
	BruteForceDetect  bool `json:"brute_force_detect"`
	PortScanDetect    bool `json:"port_scan_detect"`
	FloodDetect       bool `json:"flood_detect"`
	ARPSpoofDetect    bool `json:"arp_spoof_detect"`
	MaxConnections    int  `json:"max_connections"`
	BruteForceThreshold int `json:"brute_force_threshold"`
	FloodThreshold    int  `json:"flood_threshold"`
}

// Connection 连接信息
type Connection struct {
	IP           string
	Port         int
	Protocol     string
	StartTime    time.Time
	Count        int
	FirstSeen    time.Time
}

// New 创建攻击检测器
func New(cfg *Config) *Detector {
	return &Detector{
		cfg:         cfg,
		connections: make(map[string]*Connection),
		alerts:      make([]*models.AttackAlert, 0),
		stopChan:    make(chan struct{}),
	}
}

// Start 启动检测
func (d *Detector) Start() {
	go d.monitorConnections()
}

// Stop 停止检测
func (d *Detector) Stop() {
	close(d.stopChan)
}

// 监控连接
func (d *Detector) monitorConnections() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.check()
		case <-d.stopChan:
			return
		}
	}
}

// Check 检测攻击
func (d *Detector) check() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 检查连接数
	if d.cfg.MaxConnections > 0 {
		if len(d.connections) > d.cfg.MaxConnections {
			d.alert("flood", "high", "", 0, "too many connections", d.cfg.MaxConnections)
		}
	}

	// 检查暴力破解
	d.checkBruteForce()

	// 检查端口扫描
	d.checkPortScan()
}

// checkBruteForce 检查暴力破解
func (d *Detector) checkBruteForce() {
	if !d.cfg.BruteForceDetect {
		return
	}

	// 按IP统计连接数
	ipCounts := make(map[string]int)
	for _, conn := range d.connections {
		ipCounts[conn.IP]++
	}

	// 报告频繁连接的IP
	for ip, count := range ipCounts {
		if count > d.cfg.BruteForceThreshold {
			d.alert("brute_force", "critical", ip, 0, "possible brute force attack", count)
		}
	}
}

// checkPortScan 检查端口扫描
func (d *Detector) checkPortScan() {
	if !d.cfg.PortScanDetect {
		return
	}

	// 检查短时间内大量连接
	threshold := 10
	timeWindow := 1 * time.Minute

	// 按IP统计短时间内的连接
	ipCounts := make(map[string]int)
	now := time.Now()

	for _, conn := range d.connections {
		if now.Sub(conn.FirstSeen) < timeWindow {
			ipCounts[conn.IP]++
		}
	}

	for ip, count := range ipCounts {
		if count > threshold {
			d.alert("port_scan", "high", ip, 0, "possible port scanning", count)
		}
	}
}

// AddConnection 添加连接
func (d *Detector) AddConnection(ip string, port int, protocol string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := ip + ":" + protocol + ":" + strconv.Itoa(port)
	now := time.Now()

	if conn, ok := d.connections[key]; ok {
		conn.Count++
		conn.FirstSeen = now
	} else {
		d.connections[key] = &Connection{
			IP:        ip,
			Port:      port,
			Protocol:  protocol,
			StartTime: now,
			FirstSeen: now,
			Count:     1,
		}
	}
}

// RemoveConnection 移除连接
func (d *Detector) RemoveConnection(ip string, port int, protocol string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := ip + ":" + protocol + ":" + strconv.Itoa(port)
	delete(d.connections, key)
}

// alert 发送告警
func (d *Detector) alert(attackType string, level string, ip string, port int, message string, count int) {
	alert := &models.AttackAlert{
		ID:            generateID(),
		AttackType:    attackType,
		TargetIP:      ip,
		SourceIP:      ip,
		SourcePort:    port,
		TargetPort:    port,
		Protocol:      "tcp",
		ThreatLevel:   level,
		Frequency:     count,
		FrequencyUnit: "connections",
		StartTime:     time.Now(),
		EndTime:       time.Now(),
		AttackCount:   count,
		Status:        "active",
		ActionTaken:   "monitoring",
		Details:       message,
	}

	d.alerts = append(d.alerts, alert)
	log.Printf("🛡️ 攻击告警 [%s] %s: %s (频率: %d)", level, ip, message, count)
}
// generateID 生成ID
func generateID() string {
	return time.Now().Format("20060102150405")
}

// GetAlerts 获取告警
func (d *Detector) GetAlerts() []*models.AttackAlert {
	return d.alerts
}

// GetRecentAlerts 获取最近告警
func (d *Detector) GetRecentAlerts(count int) []*models.AttackAlert {
	if count > len(d.alerts) {
		count = len(d.alerts)
	}
	result := make([]*models.AttackAlert, count)
	copy(result, d.alerts[len(d.alerts)-count:])
	return result
}

// ClearAlerts 清除告警
func (d *Detector) ClearAlerts() {
	d.alerts = make([]*models.AttackAlert, 0)
}

