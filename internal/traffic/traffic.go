package traffic

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
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
	Enabled        bool  `json:"enabled"`
	CollectInterval int  `json:"collect_interval"` // 秒
	GlobalThreshold int  `json:"global_threshold"`  // MB/小时
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

// Start 启动监控
func (m *Monitor) Start() {
	go m.collectLoop()
}

// Stop 停止监控
func (m *Monitor) Stop() {
	close(m.stopChan)
}

// 采集循环
func (m *Monitor) collectLoop() {
	ticker := time.NewTicker(time.Duration(m.cfg.CollectInterval) * time.Second)
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
		dt, ok := m.devices[ip]
		if !ok {
			dt = &DeviceTraffic{IP: ip, Threshold: m.cfg.GlobalThreshold}
			m.devices[ip] = dt
		}

		// 计算速率
		dt.RateIn = float64(data.BytesIn-dt.BytesIn) / float64(m.cfg.CollectInterval) / 1024
		dt.RateOut = float64(data.BytesOut-dt.BytesOut) / float64(m.cfg.CollectInterval) / 1024
		dt.BytesIn = data.BytesIn
		dt.BytesOut = data.BytesOut
		dt.TotalIn += int64(dt.RateIn * float64(m.cfg.CollectInterval) * 1024)
		dt.TotalOut += int64(dt.RateOut * float64(m.cfg.CollectInterval) * 1024)
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

	// 使用 PowerShell 获取网络接口统计
	cmd := exec.Command("powershell", "-Command", 
		"Get-NetAdapterStatistics | ConvertTo-Json -Compress")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("流量获取失败: %v", err)
		return result
	}

	// 解析JSON数组
	var stats []struct {
		ReceivedBytes int64 `json:"ReceivedBytes"`
		SentBytes     int64 `json:"SentBytes"`
		Name          string `json:"Name"`
	}
	
	if json.Unmarshal(output, &stats) == nil {
		var totalIn, totalOut int64
		for _, s := range stats {
			totalIn += s.ReceivedBytes
			totalOut += s.SentBytes
		}
		result["*"] = NetworkStats{
			BytesIn:  totalIn,
			BytesOut: totalOut,
		}
	}

	// 获取活跃连接
	m.getConnections()

	return result
}

// getConnections 获取活跃连接
func (m *Monitor) getConnections() {
	m.connections = []ConnectionInfo{}
	
	// 使用更简单的命令
	cmd := exec.Command("powershell", "-Command", 
		"Get-NetTCPConnection -State Established | Select-Object -Property LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("获取连接失败: %v", err)
		return
	}
	
	// 解析JSON
	var data interface{}
	if json.Unmarshal(output, &data) != nil {
		log.Printf("JSON解析失败")
		return
	}
	
	// 处理数组
	var conns []map[string]interface{}
	switch v := data.(type) {
	case []interface{}:
		for _, item := range v {
			if c, ok := item.(map[string]interface{}); ok {
				conns = append(conns, c)
			}
		}
	case map[string]interface{}:
		conns = append(conns, v)
	}
	
	for _, c := range conns {
		localAddr, _ := c["LocalAddress"].(string)
		remoteAddr, _ := c["RemoteAddress"].(string)
		
		// 显示所有非本地连接
		if localAddr != "127.0.0.1" && remoteAddr != "127.0.0.1" {
			localPort := 0
			remotePort := 0
			if lp, ok := c["LocalPort"].(float64); ok {
				localPort = int(lp)
			}
			if rp, ok := c["RemotePort"].(float64); ok {
				remotePort = int(rp)
			}
			m.connections = append(m.connections, ConnectionInfo{
				LocalIP:    localAddr,
				RemoteIP:   remoteAddr,
				LocalPort:  localPort,
				RemotePort: remotePort,
			})
		}
	}
	
	// 去重：按 LocalIP+RemoteIP+LocalPort+RemotePort 去重
	seen := make(map[string]bool)
	uniqueConnections := []ConnectionInfo{}
	for _, conn := range m.connections {
		key := fmt.Sprintf("%s:%d->%s:%d", conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort)
		if !seen[key] {
			seen[key] = true
			uniqueConnections = append(uniqueConnections, conn)
		}
	}
	
	// 过滤掉本地自连接（同一个IP的连接，如 192.168.2.216 -> 192.168.2.216）
	filteredConnections := []ConnectionInfo{}
	for _, conn := range uniqueConnections {
		if conn.LocalIP == conn.RemoteIP {
			continue  // 跳过本地自连接
		}
		filteredConnections = append(filteredConnections, conn)
	}
	m.connections = filteredConnections
	
	log.Printf("发现 %d 个活跃连接 (去重后，排除本地自连接)", len(m.connections))
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
