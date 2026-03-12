package traffic

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"network-monitor/internal/models"
)

// Monitor 流量监控器
type Monitor struct {
	cfg            *Config
	devices        map[string]*DeviceTraffic
	connections    []ConnectionInfo
	mu             sync.RWMutex
	stopChan       chan struct{}
}

// Config 流量监控配置
type Config struct {
	Enabled         bool  `json:"enabled"`
	CollectInterval int   `json:"collect_interval"`  // 秒 - 流量采集间隔
	TrafficInterval int   `json:"traffic_interval"` // 秒 - 流量刷新间隔
	GlobalThreshold int   `json:"global_threshold"` // MB/小时
	ThresholdUnit  string `json:"threshold_unit"`
}

// DeviceTraffic 设备流量数据
type DeviceTraffic struct {
	IP            string
	BytesIn       int64
	BytesOut      int64
	RateIn        float64 // KB/s
	RateOut       float64 // KB/s
	LastUpdate    time.Time
	TotalIn       int64
	TotalOut      int64
	AlertActive   bool
	Threshold     int // MB/小时
}

// New 创建流量监控器
func New(cfg *Config) *Monitor {
	m := &Monitor{
		cfg:     cfg,
		devices: make(map[string]*DeviceTraffic),
		stopChan: make(chan struct{}),
	}
	return m
}

// splitAddr 分割地址和端口
func splitAddr(addr string) (string, int) {
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		port := 0
		fmt.Sscanf(parts[len(parts)-1], "%d", &port)
		ip := strings.Join(parts[:len(parts)-1], ":")
		return ip, port
	}
	return addr, 0
}

// Start 启动监控
func (m *Monitor) Start() {
	go m.collectLoop()
}

// Stop 停止监控
func (m *Monitor) Stop() {
	close(m.stopChan)
}

// SetConfig 更新配置
func (m *Monitor) SetConfig(cfg *Config) {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	
	// 重启流量监控
	go func() {
		m.Stop()
		m.stopChan = make(chan struct{})
		if cfg.Enabled {
			go m.collectLoop()
		}
	}()
}

// 采集循环
func (m *Monitor) collectLoop() {
	// 设置默认采集间隔
	interval := m.cfg.CollectInterval
	if interval <= 0 {
		interval = 5 // 默认 5 秒
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collect()
		case <-m.stopChan:
			return
		}
	}
}

// 采集流量数据
func (m *Monitor) collect() {
	trafficData := m.getNetworkTraffic()
	
	m.mu.Lock()
	defer m.mu.Unlock()

	for ip, data := range trafficData {
		// 跳过汇总键
		if ip == "*" {
			continue
		}
		
		dt, ok := m.devices[ip]
		if !ok {
			dt = &DeviceTraffic{IP: ip, Threshold: m.cfg.GlobalThreshold}
			m.devices[ip] = dt
		}

		// 计算速率 (每个连接约1KB/秒估算)
		interval := m.cfg.CollectInterval
		if interval <= 0 {
			interval = 5
		}
		
		dt.RateIn = float64(data.BytesIn) / float64(interval) / 1024
		dt.RateOut = float64(data.BytesOut) / float64(interval) / 1024
		dt.BytesIn = data.BytesIn
		dt.BytesOut = data.BytesOut
		dt.TotalIn += int64(dt.RateIn * float64(interval) * 1024)
		dt.TotalOut += int64(dt.RateOut * float64(interval) * 1024)
		dt.LastUpdate = time.Now()

		// 阈值检查 (MB/小时)
		hourlyRate := (dt.RateIn + dt.RateOut) * 3600 / 1024
		if int(hourlyRate) > dt.Threshold && dt.Threshold > 0 {
			dt.AlertActive = true
		} else {
			dt.AlertActive = false
		}
	}
}

// 获取网络流量 (Windows)
func (m *Monitor) getNetworkTraffic() map[string]NetworkStats {
	result := make(map[string]NetworkStats)

	if runtime.GOOS != "windows" {
		return result
	}

	// 使用 netstat 获取连接统计
	cmd := exec.Command("cmd", "/c", "netstat -ano")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("流量获取失败: %v", err)
		return result
	}

	// 解析连接并按远程IP统计
	lines := strings.Split(string(output), "\n")
	connectionCount := make(map[string]int)
	
	for _, line := range lines {
		if !strings.Contains(line, "ESTABLISHED") {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "TCP" {
			continue
		}
		
		localAddr := fields[1]
		remoteAddr := fields[2]
		
		localIP, _ := splitAddr(localAddr)
		remoteIP, _ := splitAddr(remoteAddr)
		
		// 排除本地自连接
		if localIP == remoteIP || remoteIP == "0.0.0.0" || remoteIP == ":::" {
			continue
		}
		
		connectionCount[remoteIP]++
	}

	// 为每个有连接的IP创建流量记录
	for ip, count := range connectionCount {
		result[ip] = NetworkStats{
			BytesIn:  int64(count * 1024),  // 估算值
			BytesOut: int64(count * 512),   // 估算值
		}
	}

	// 计算总数
	var totalIn, totalOut int64
	for _, data := range result {
		totalIn += data.BytesIn
		totalOut += data.BytesOut
	}
	result["*"] = NetworkStats{
		BytesIn:  totalIn,
		BytesOut: totalOut,
	}

	log.Printf("流量统计: %d 个IP, 入站: %d, 出站: %d", len(result)-1, result["*"].BytesIn, result["*"].BytesOut)

	return result
}



// ConnectionInfo 连接信息
type ConnectionInfo struct {
	LocalIP    string `json:"local_ip"`
	RemoteIP   string `json:"remote_ip"`
	LocalPort  int    `json:"local_port"`
	RemotePort int    `json:"remote_port"`
}

// NetworkStats 网络统计
type NetworkStats struct {
	BytesIn  int64
	BytesOut int64
}

// GetTraffic 获取设备流量
func (m *Monitor) GetTraffic(ip string) *DeviceTraffic {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devices[ip]
}

// GetAllTraffic 获取所有设备流量
func (m *Monitor) GetAllTraffic() []*DeviceTraffic {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*DeviceTraffic, 0, len(m.devices))
	for _, dt := range m.devices {
		result = append(result, dt)
	}
	return result
}

// GetGlobalTraffic 获取全局流量
func (m *Monitor) GetGlobalTraffic() (rateIn, rateOut float64, totalIn, totalOut int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, dt := range m.devices {
		rateIn += dt.RateIn
		rateOut += dt.RateOut
		totalIn += dt.TotalIn
		totalOut += dt.TotalOut
	}
	return
}

// GetConnections 获取活跃连接
func (m *Monitor) GetConnections() []ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connections
}

// SetThreshold 设置阈值
func (m *Monitor) SetThreshold(ip string, threshold int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if dt, ok := m.devices[ip]; ok {
		dt.Threshold = threshold
	} else {
		m.devices[ip] = &DeviceTraffic{IP: ip, Threshold: threshold}
	}
}

// CheckAlerts 检查需要告警的设备
func (m *Monitor) CheckAlerts() []*models.TrafficAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var alerts []*models.TrafficAlert
	for _, dt := range m.devices {
		if dt.AlertActive {
			alerts = append(alerts, &models.TrafficAlert{
				ID:          dt.IP + time.Now().Format("20060102150405"),
				IP:          dt.IP,
				Threshold:   dt.Threshold,
				PeakRate:   dt.RateIn + dt.RateOut,
				TotalTraffic: float64(dt.TotalIn + dt.TotalOut) / 1024 / 1024,
				StartTime:   dt.LastUpdate,
				Status:      "active",
			})
		}
	}
	return alerts
}
