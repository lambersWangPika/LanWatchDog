package traffic

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Monitor 流量监控器
type Monitor struct {
	cfg          *Config
	devices      map[string]*DeviceTraffic
	connections  []ConnectionInfo
	mu           sync.RWMutex
	stopChan     chan struct{}
	// 记录监控开始时的网卡流量（用于计算增量）
	startBytesIn   int64
	startBytesOut int64
	// 上一次的值（用于计算速率）
	lastBytesIn   int64
	lastBytesOut  int64
	lastUpdate    time.Time
	// 监控开始后的累计流量
	totalStats    NetworkStats
	history       []HistoryPoint
}

type HistoryPoint struct {
	Timestamp time.Time
	RateIn    float64
	RateOut   float64
	TotalIn   int64
	TotalOut  int64
}

type Config struct {
	Enabled         bool  `json:"enabled"`
	CollectInterval int   `json:"collect_interval"`
	TrafficInterval int   `json:"traffic_interval"`
	GlobalThreshold int   `json:"global_threshold"`
	ThresholdUnit  string `json:"threshold_unit"`
}

type DeviceTraffic struct {
	IP          string
	BytesIn     int64
	BytesOut    int64
	RateIn      float64
	RateOut     float64
	LastUpdate  time.Time
	TotalIn     int64
	TotalOut    int64
	Threshold   int
	AlertActive bool
}

type ConnectionInfo struct {
	LocalIP   string `json:"local_ip"`
	RemoteIP  string `json:"remote_ip"`
	LocalPort int    `json:"local_port"`
	RemotePort int   `json:"remote_port"`
}

type NetworkStats struct {
	BytesIn  int64
	BytesOut int64
	RateIn   float64
	RateOut  float64
}

func New(cfg *Config) *Monitor {
	m := &Monitor{
		cfg:      cfg,
		devices:  make(map[string]*DeviceTraffic),
		stopChan: make(chan struct{}),
	}
	if cfg.Enabled {
		go func() { m.collectLoop() }()
	}
	log.Println("[Traffic] 流量监控器已启动")
	return m
}

func (m *Monitor) Start() {
	if m.cfg.Enabled {
		go m.collectLoop()
	}
}

func (m *Monitor) Stop() {
	close(m.stopChan)
}

func (m *Monitor) SetConfig(cfg *Config) {
	m.cfg = cfg
}

func (m *Monitor) collectLoop() {
	interval := m.cfg.CollectInterval
	if interval <= 0 {
		interval = 5
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

func (m *Monitor) collect() {
	// 获取全局网卡流量
	globalData := m.getGlobalTraffic()
	
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	interval := m.cfg.CollectInterval
	if interval <= 0 {
		interval = 5
	}

	// 首次运行时，初始化起始流量
	if m.startBytesIn == 0 {
		m.startBytesIn = globalData.BytesIn
		m.startBytesOut = globalData.BytesOut
		m.lastBytesIn = globalData.BytesIn
		m.lastBytesOut = globalData.BytesOut
		m.lastUpdate = now
		log.Printf("[Traffic] 流量监控初始化，起始流量: in=%d, out=%d", m.startBytesIn, m.startBytesOut)
		return
	}

	timeDiff := now.Sub(m.lastUpdate).Seconds()
	if timeDiff <= 0 {
		timeDiff = float64(interval)
	}

	// 计算全局速率 (bytes/sec → KB/s)
	if m.lastBytesIn > 0 && globalData.BytesIn >= m.lastBytesIn {
		deltaIn := globalData.BytesIn - m.lastBytesIn
		m.totalStats.RateIn = float64(deltaIn) / timeDiff / 1024
	}
	if m.lastBytesOut > 0 && globalData.BytesOut >= m.lastBytesOut {
		deltaOut := globalData.BytesOut - m.lastBytesOut
		m.totalStats.RateOut = float64(deltaOut) / timeDiff / 1024
	}

	// 累计流量 = 监控开始后的增量 (当前值 - 起始值)
	m.totalStats.BytesIn = globalData.BytesIn - m.startBytesIn
	m.totalStats.BytesOut = globalData.BytesOut - m.startBytesOut

	m.lastBytesIn = globalData.BytesIn
	m.lastBytesOut = globalData.BytesOut
	m.lastUpdate = now

	// 获取连接统计
	connections := m.getConnectionStats()

	// 更新每个设备的流量 - 只记录设备状态，流量显示全局值
	for ip := range connections {
		if !isLANIP(ip) {
			continue
		}
		dt, ok := m.devices[ip]
		if !ok {
			dt = &DeviceTraffic{IP: ip, Threshold: m.cfg.GlobalThreshold}
			m.devices[ip] = dt
		}

		// 设备流量 = 全局流量 / 设备数量（平均分配）
		deviceCount := 0
		for ip := range connections {
			if isLANIP(ip) {
				deviceCount++
			}
		}
		if deviceCount == 0 {
			deviceCount = 1
		}

		// 平均分配全局流量
		dt.RateIn = m.totalStats.RateIn / float64(deviceCount)
		dt.RateOut = m.totalStats.RateOut / float64(deviceCount)
		dt.TotalIn = m.totalStats.BytesIn / int64(deviceCount)
		dt.TotalOut = m.totalStats.BytesOut / int64(deviceCount)
		dt.BytesIn = int64(dt.RateIn * 1024)
		dt.BytesOut = int64(dt.RateOut * 1024)
		dt.LastUpdate = now

		// 阈值检查
		hourlyRate := (dt.RateIn + dt.RateOut) * 3600 / 1024
		dt.AlertActive = int(hourlyRate) > dt.Threshold && dt.Threshold > 0
	}

	// 记录历史
	if len(m.history) == 0 || now.Sub(m.history[len(m.history)-1].Timestamp) >= time.Minute {
		m.history = append(m.history, HistoryPoint{
			Timestamp: now,
			RateIn:    m.totalStats.RateIn,
			RateOut:   m.totalStats.RateOut,
			TotalIn:   m.totalStats.BytesIn,
			TotalOut:  m.totalStats.BytesOut,
		})
		if len(m.history) > 60 {
			m.history = m.history[len(m.history)-60:]
		}
	}

	log.Printf("流量统计: 全局入站=%.2f KB/s, 出站=%.2f KB/s, 累计=%d bytes", 
		m.totalStats.RateIn, m.totalStats.RateOut, m.totalStats.BytesIn)
}

// getGlobalTraffic 获取全局网卡流量
func (m *Monitor) getGlobalTraffic() NetworkStats {
	if runtime.GOOS != "windows" {
		return NetworkStats{}
	}

	// 使用 PowerShell 获取主网卡 (Ethernet0) 的流量
	cmd := exec.Command("powershell", "-Command",
		"$adapter = Get-NetAdapter | Where-Object {$_.Name -eq 'Ethernet0' -or $_.Name -eq '以太网' -or $_.Status -eq 'Up'} | Select-Object -First 1; "+
		"$stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue; "+
		"if($stats){$stats.ReceivedBytes; $stats.SentBytes}")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("获取流量失败: %v", err)
		return NetworkStats{}
	}

	// 解析输出 (每行一个数字)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var totalReceived, totalSent int64
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		val := strings.ReplaceAll(line, ",", "")
		if v, err := strconv.ParseInt(val, 10, 64); err == nil {
			if i == 0 {
				totalReceived = v
			} else if i == 1 {
				totalSent = v
				break
			}
		}
	}

	return NetworkStats{BytesIn: totalReceived, BytesOut: totalSent}
}

// getConnectionStats 获取连接统计
func (m *Monitor) getConnectionStats() map[string]int {
	connections := make(map[string]int)
	if runtime.GOOS != "windows" {
		return connections
	}

	cmd := exec.Command("cmd", "/c", "netstat -ano | findstr ESTABLISHED")
	output, err := cmd.Output()
	if err != nil {
		return connections
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "TCP" {
			continue
		}

		localIP, _ := splitAddr(fields[1])
		if localIP != "" && localIP != "127.0.0.1" && !strings.HasPrefix(localIP, "0.0.0.0") {
			connections[localIP]++
		}
	}

	return connections
}

func (m *Monitor) GetTraffic(ip string) *DeviceTraffic {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devices[ip]
}

func (m *Monitor) GetAllTraffic() []*DeviceTraffic {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*DeviceTraffic, 0, len(m.devices))
	for _, dt := range m.devices {
		result = append(result, dt)
	}
	return result
}

func (m *Monitor) GetLANTraffic() []*DeviceTraffic {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*DeviceTraffic, 0)
	for _, dt := range m.devices {
		if !isLANIP(dt.IP) {
			continue
		}
		result = append(result, dt)
	}
	return result
}

func (m *Monitor) GetGlobalTraffic() (rateIn, rateOut float64, totalIn, totalOut int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rateIn = m.totalStats.RateIn
	rateOut = m.totalStats.RateOut
	totalIn = m.totalStats.BytesIn
	totalOut = m.totalStats.BytesOut
	return
}

func (m *Monitor) GetHistory() []HistoryPoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]HistoryPoint, len(m.history))
	copy(result, m.history)
	return result
}

func (m *Monitor) GetConnections() []ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connections
}

func isLANIP(ip string) bool {
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}
	if strings.HasPrefix(ip, "10.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			num, _ := strconv.Atoi(parts[1])
			if num >= 16 && num <= 31 {
				return true
			}
		}
	}
	return ip == "127.0.0.1" || ip == "localhost"
}

func splitAddr(addr string) (string, int) {
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		port, _ := strconv.Atoi(parts[len(parts)-1])
		return strings.Join(parts[:len(parts)-1], ":"), port
	}
	return addr, 0
}

func (m *Monitor) String() string {
	return fmt.Sprintf("TrafficMonitor{devices:%d}", len(m.devices))
}
