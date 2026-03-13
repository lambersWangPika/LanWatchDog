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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	
	// PCAP 捕获
	pcapHandle    *pcap.Handle
	pcapEnabled   bool
	pcapTraffic   map[string]*IPTraffic
	pcapStopChan  chan struct{}
}

type IPTraffic struct {
	BytesIn  int64
	BytesOut int64
	Packets  int64
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
	UsePCAP         bool  `json:"use_pcap"`
	InterfaceName   string `json:"interface_name"`
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
		cfg:         cfg,
		devices:     make(map[string]*DeviceTraffic),
		stopChan:    make(chan struct{}),
		pcapTraffic: make(map[string]*IPTraffic),
		pcapStopChan: make(chan struct{}),
	}
	
	// 尝试初始化 PCAP
	if cfg.UsePCAP {
		m.initPCAP(cfg.InterfaceName)
	}
	
	if cfg.Enabled {
		go func() { m.collectLoop() }()
	}
	log.Println("[Traffic] 流量监控器已启动")
	return m
}

// initPCAP 初始化 PCAP 捕获
func (m *Monitor) initPCAP(interfaceName string) bool {
	if runtime.GOOS != "windows" {
		log.Println("[PCAP] 仅支持 Windows 平台")
		return false
	}

	// 如果没有指定网卡名，尝试自动获取
	if interfaceName == "" {
		iface, err := getDefaultInterface()
		if err != nil {
			log.Printf("[PCAP] 获取默认网卡失败: %v", err)
			return false
		}
		interfaceName = iface
	}

	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[PCAP] 打开网卡 %s 失败: %v (需要安装 npcap 驱动)", interfaceName, err)
		log.Printf("[PCAP] 请访问 https://npcap.com/dist/npcap-1.78.exe 下载安装")
		return false
	}

	// 设置过滤器：只捕获 IP 包
	filter := "ip and (tcp or udp)"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("[PCAP] 设置过滤器失败: %v", err)
		handle.Close()
		return false
	}

	m.pcapHandle = handle
	m.pcapEnabled = true
	
	// 启动 PCAP 捕获 goroutine
	go m.pcapCaptureLoop()
	
	log.Printf("[PCAP] 已启动流量捕获: %s", interfaceName)
	return true
}

// getDefaultInterface 获取默认网卡名称
func getDefaultInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	
	// 优先找 Ethernet0 或以太网
	for _, d := range devices {
		if d.Name == "Ethernet0" || d.Name == "以太网" {
			return d.Name, nil
		}
	}
	
	// 返回第一个非回环网卡
	for _, d := range devices {
		for _, a := range d.Addresses {
			if !strings.HasPrefix(a.IP.String(), "127.") {
				return d.Name, nil
			}
		}
	}
	
	if len(devices) > 0 {
		return devices[0].Name, nil
	}
	
	return "", fmt.Errorf("未找到可用的网络接口")
}

// pcapCaptureLoop PCAP 捕获循环
func (m *Monitor) pcapCaptureLoop() {
	if m.pcapHandle == nil {
		return
	}

	packetSource := gopacket.NewPacketSource(m.pcapHandle, m.pcapHandle.LinkType())
	
	for {
		select {
		case <-m.pcapStopChan:
			return
		case packet := <-packetSource.Packets():
			if packet != nil {
				m.processPacket(packet)
			}
		}
	}
}

// processPacket 处理数据包
func (m *Monitor) processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	if ip == nil {
		return
	}

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	// 只处理局域网 IP
	if !isLANIP(srcIP) && !isLANIP(dstIP) {
		return
	}

	payloadLen := int(ip.Length) - int(ip.IHL)*4
	if payloadLen <= 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 更新源 IP 的出站流量
	if t, ok := m.pcapTraffic[srcIP]; ok {
		t.BytesOut += int64(payloadLen)
		t.Packets++
	} else {
		m.pcapTraffic[srcIP] = &IPTraffic{
			BytesOut: int64(payloadLen),
			Packets:  1,
		}
	}

	// 更新目标 IP 的入站流量
	if t, ok := m.pcapTraffic[dstIP]; ok {
		t.BytesIn += int64(payloadLen)
		t.Packets++
	} else {
		m.pcapTraffic[dstIP] = &IPTraffic{
			BytesIn: int64(payloadLen),
			Packets:  1,
		}
	}
}

func (m *Monitor) Start() {
	if m.cfg.Enabled {
		go m.collectLoop()
	}
	// 尝试启动 PCAP
	if m.cfg.UsePCAP && !m.pcapEnabled {
		m.initPCAP(m.cfg.InterfaceName)
	}
}

func (m *Monitor) Stop() {
	close(m.stopChan)
	if m.pcapEnabled {
		close(m.pcapStopChan)
		if m.pcapHandle != nil {
			m.pcapHandle.Close()
		}
	}
}

func (m *Monitor) SetConfig(cfg *Config) {
	// 如果配置变化需要重启 PCAP
	if cfg.UsePCAP != m.cfg.UsePCAP || cfg.InterfaceName != m.cfg.InterfaceName {
		m.Stop()
		m.pcapEnabled = false
		m.pcapTraffic = make(map[string]*IPTraffic)
		m.pcapStopChan = make(chan struct{})
		
		if cfg.UsePCAP {
			m.initPCAP(cfg.InterfaceName)
		}
	}
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

	// 如果启用了 PCAP，使用 PCAP 数据更新设备流量
	if m.pcapEnabled {
		for ip, pcapData := range m.pcapTraffic {
			if !isLANIP(ip) {
				continue
			}
			dt, ok := m.devices[ip]
			if !ok {
				dt = &DeviceTraffic{IP: ip, Threshold: m.cfg.GlobalThreshold}
				m.devices[ip] = dt
			}
			dt.BytesIn = pcapData.BytesIn
			dt.BytesOut = pcapData.BytesOut
			// 速率需要根据时间间隔计算
			dt.RateIn = float64(pcapData.BytesIn) / timeDiff / 1024
			dt.RateOut = float64(pcapData.BytesOut) / timeDiff / 1024
			dt.TotalIn = pcapData.BytesIn
			dt.TotalOut = pcapData.BytesOut
			dt.LastUpdate = now
		}
	} else {
		// 回退到旧逻辑：平均分配全局流量
		for ip := range connections {
			if !isLANIP(ip) {
				continue
			}
			dt, ok := m.devices[ip]
			if !ok {
				dt = &DeviceTraffic{IP: ip, Threshold: m.cfg.GlobalThreshold}
				m.devices[ip] = dt
			}

			deviceCount := 0
			for ip := range connections {
				if isLANIP(ip) {
					deviceCount++
				}
			}
			if deviceCount == 0 {
				deviceCount = 1
			}

			dt.RateIn = m.totalStats.RateIn / float64(deviceCount)
			dt.RateOut = m.totalStats.RateOut / float64(deviceCount)
			dt.TotalIn = m.totalStats.BytesIn / int64(deviceCount)
			dt.TotalOut = m.totalStats.BytesOut / int64(deviceCount)
			dt.BytesIn = int64(dt.RateIn * 1024)
			dt.BytesOut = int64(dt.RateOut * 1024)
			dt.LastUpdate = now
		}
	}

	// 阈值检查
	for _, dt := range m.devices {
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

	log.Printf("流量统计: 全局入站=%.2f KB/s, 出站=%.2f KB/s, 累计=%d bytes (PCAP=%v)", 
		m.totalStats.RateIn, m.totalStats.RateOut, m.totalStats.BytesIn, m.pcapEnabled)
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

// GetPCAPEnabled 获取 PCAP 是否启用
func (m *Monitor) GetPCAPEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pcapEnabled
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
	return fmt.Sprintf("TrafficMonitor{devices:%d, pcap:%v}", len(m.devices), m.pcapEnabled)
}
