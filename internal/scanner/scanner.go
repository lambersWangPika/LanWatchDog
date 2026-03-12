package scanner

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"network-monitor/internal/config"
	"network-monitor/internal/models"
)

// Scanner 网络扫描器
type Scanner struct {
	cfg          *config.Config
	devices      map[string]*models.Device
	mu           sync.RWMutex
	autoScanChan chan struct{}
	stopAutoScan chan struct{}
	// 日志回调
	OnScanComplete func(interface{})
}

func New(cfg *config.Config) *Scanner {
	s := &Scanner{
		cfg:          cfg,
		devices:      make(map[string]*models.Device),
		autoScanChan: make(chan struct{}, 1),
		stopAutoScan: make(chan struct{}),
	}
	
	// 启动自动扫描
	if cfg.AutoScanOnStart {
		go s.autoScanLoop()
	}
	
	return s
}

// Stop 停止扫描器
func (s *Scanner) Stop() {
	close(s.stopAutoScan)
}

// SetConfig 更新配置
func (s *Scanner) SetConfig(cfg *config.Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	
	// 重启自动扫描
	go func() {
		s.Stop()
		s.stopAutoScan = make(chan struct{})
		if cfg.AutoScanOnStart {
			go s.autoScanLoop()
		}
	}()
}

// 自动扫描循环
func (s *Scanner) autoScanLoop() {
	ticker := time.NewTicker(time.Duration(s.cfg.ScanInterval) * time.Minute)
	defer ticker.Stop()
	
	// 启动时扫描一次
	s.triggerScan()
	
	for {
		select {
		case <-ticker.C:
			s.triggerScan()
		case <-s.autoScanChan:
			s.doScan()
		case <-s.stopAutoScan:
			return
		}
	}
}

// TriggerScan 触发扫描
func (s *Scanner) triggerScan() {
	select {
	case s.autoScanChan <- struct{}{}:
	default:
	}
}

// 执行实际扫描
func (s *Scanner) doScan() {
	log.Println("开始自动扫描...")
	devices, err := s.Scan()
	if err != nil {
		log.Printf("自动扫描失败: %v", err)
		return
	}
	log.Printf("自动扫描完成，发现 %d 个设备", len(devices))
	
	// 触发日志回调
	if s.OnScanComplete != nil {
		s.OnScanComplete(devices)
	}
}

func (s *Scanner) Scan() ([]*models.Device, error) {
	log.Println("开始扫描...")

	// 快速方法：直接从ARP缓存获取在线设备
	arpDevices := s.getARPDevices()
	log.Printf("ARP缓存发现 %d 个设备", len(arpDevices))
	
	now := time.Now()
	
	// 更新内存中的设备列表
	s.mu.Lock()
	
	// 先标记所有设备为离线
	for _, d := range s.devices {
		if d.WasOnline && d.Status == models.StatusOnline {
			d.Status = models.StatusOffline
		}
	}
	
	// 处理发现的设备
	devices := make([]*models.Device, 0)
	for ip, mac := range arpDevices {
		if existing, ok := s.devices[ip]; ok {
			// 已存在设备更新状态
			existing.Status = models.StatusOnline
			existing.LastSeen = now
			existing.WasOnline = true
			if mac != "" {
				existing.MAC = mac
				existing.Vendor = getVendor(mac)
			}
			devices = append(devices, existing)
		} else {
			// 新设备 - 每次都用当前时间
			vendor := getVendor(mac)
			device := &models.Device{
				IP:         ip,
				MAC:        mac,
				Vendor:     vendor,
				Status:     models.StatusOnline,
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
				WasOnline:  true,
				Type:       s.identifyDeviceType(ip),
				Name:       s.getDeviceName(ip),
			}
			s.devices[ip] = device
			devices = append(devices, device)
			
			// 新设备告警
			if s.cfg.AlertEnabled && s.cfg.NewDeviceAlert {
				log.Printf("🔔 新设备发现: %s (%s)", ip, mac)
			}
		}
	}
	
	s.mu.Unlock()

	log.Printf("扫描完成，发现 %d 个在线设备", len(devices))
	return devices, nil
}

// getARPDevices 从ARP缓存获取在线设备
func (s *Scanner) getARPDevices() map[string]string {
	result := make(map[string]string)
	
	if runtime.GOOS != "windows" {
		return result
	}
	
	// 执行 arp -a 获取所有缓存
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("ARP获取失败: %v", err)
		return result
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// 跳过标题行
		if strings.Contains(line, "Interface") || strings.Contains(line, "Internet") || strings.Contains(line, "Address") {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := strings.TrimSpace(fields[0])
			mac := strings.TrimSpace(fields[1])
			
			// 验证IP格式
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				continue
			}
			
			// 过滤组播地址 224.0.0.0/4
			ip4 := parsedIP.To4()
			if ip4 != nil && ip4[0] >= 224 {
				continue
			}
			
			// 过滤广播地址 (xxx.xxx.xxx.255)
			if ip4 != nil && ip4[3] == 255 {
				continue
			}
			
			// 验证MAC格式 (xx-xx-xx-xx-xx-xx)
			if len(mac) == 17 && strings.Contains(mac, "-") {
				result[ip] = strings.ToUpper(mac)
			}
		}
	}
	
	return result
}

// 获取设备名称
func (s *Scanner) getDeviceName(ipStr string) string {
	// 先尝试 ping 唤醒设备
	net.ParseIP(ipStr).To4()
	
	// 尝试通过 DNS/NetBIOS 解析名称
	names, err := net.LookupAddr(ipStr)
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		if name != "" {
			return name
		}
	}
	
	// 如果没有 DNS 名称，尝试从 ARP 表获取
	arpCmd := exec.Command("arp", "-a", ipStr)
	output, err := arpCmd.Output()
	if err == nil {
		outputStr := string(output)
		// 尝试从 ARP 输出中提取设备名称
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, ipStr) {
				// 尝试匹配类似 "at 00:0C:29:98:C0:E7" 这样的行
				if atIdx := strings.Index(line, "at "); atIdx > 0 {
					macPart := strings.TrimSpace(line[atIdx+3:])
					parts := strings.Fields(macPart)
					if len(parts) > 0 {
						mac := strings.ReplaceAll(parts[0], "-", ":")
						// 根据 MAC 前缀获取厂商作为备选
						if vendor := getVendor(mac); vendor != "Unknown" {
							return vendor
						}
					}
				}
			}
		}
	}
	
	// 如果都没有，返回厂商信息
	return ""
}

// 识别设备类型
func (s *Scanner) identifyDeviceType(ipStr string) models.DeviceType {
	parts := net.ParseIP(ipStr).To4()
	if parts == nil {
		return models.DeviceTypeUnknown
	}
	lastOctet := parts[3]

	// 常见IP模式识别
	if lastOctet == 1 {
		return models.DeviceTypeRouter
	}
	if lastOctet == 254 {
		return models.DeviceTypeRouter
	}

	// 默认识别为PC
	return models.DeviceTypePC
}

// MAC 厂商映射
var macVendors = map[string]string{
	"00:50:56": "VMware虚拟机",
	"00:0C:29": "VMware虚拟机",
	"00:1C:42": "Parallels虚拟机",
	"00:03:FF": "微软虚拟机",
	"00:15:5D": "微软虚拟机",
	"28:C6:3F": "Intel设备",
	"3C:D9:2B": "HP设备",
	"00:17:42": "Cisco设备",
	"00:1E:68": "Cisco设备",
	"00:25:B3": "HP服务器",
	"00:26:B9": "Dell设备",
	"00:1D:09": "Dell设备",
	"00:1E:C9": "Dell设备",
	"B8:27:EB": "树莓派",
	"DC:A6:32": "树莓派",
	"F0:18:98": "苹果设备",
	"3C:06:30": "苹果设备",
	"00:1A:2B": "AXIS摄像头",
	"00:40:8D": "佳能打印机",
	"00:1E:8F": "佳能打印机",
	"00:00:48": "爱普生打印机",
	"F0:7D:68": "TP-Link设备",
	"F4:EC:38": "TP-Link设备",
	"F8:1A:67": "TP-Link设备",
	"F8:D1:11": "TP-Link设备",
	"B4:04:21": "TP-Link路由器",
	"C8:1F:66": "TP-Link设备",
}

// 获取厂商
func getVendor(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}
	
	// 转换MAC格式 (xx-xx-xx-xx-xx-xx -> xx:xx:xx:xx:xx:xx)
	macClean := strings.ReplaceAll(strings.ToUpper(mac), "-", ":")
	
	prefix := macClean[:8]
	
	if vendor, ok := macVendors[prefix]; ok {
		return vendor
	}
	
	// 更宽松的匹配
	prefix3 := macClean[:5]
	for k, v := range macVendors {
		if strings.HasPrefix(k, prefix3) {
			return v
		}
	}
	
	return "Unknown"
}

func (s *Scanner) GetDevices() []*models.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	devices := make([]*models.Device, 0, len(s.devices))
	for _, d := range s.devices {
		// 只返回曾经上线过的设备
		if d.WasOnline {
			devices = append(devices, d)
		}
	}
	return devices
}

// GetDevice 获取单个设备
func (s *Scanner) GetDevice(ip string) *models.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.devices[ip]
}

// UpdateDevice 更新设备信息
func (s *Scanner) UpdateDevice(ip string, name string, group string, whitelist bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if device, ok := s.devices[ip]; ok {
		device.Name = name
		device.Group = group
		device.Whitelist = whitelist
		return nil
	}
	return fmt.Errorf("设备不存在: %s", ip)
}

// SetWhitelist 设置白名单
func (s *Scanner) SetWhitelist(ip string, whitelist bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if device, ok := s.devices[ip]; ok {
		device.Whitelist = whitelist
		return nil
	}
	return fmt.Errorf("设备不存在: %s", ip)
}

// GetWhitelist 获取白名单设备
func (s *Scanner) GetWhitelist() []*models.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var result []*models.Device
	for _, d := range s.devices {
		if d.Whitelist {
			result = append(result, d)
		}
	}
	return result
}

// GetBlacklist 获取黑名单设备
func (s *Scanner) GetBlacklist() []*models.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var result []*models.Device
	for _, d := range s.devices {
		if d.Status == models.StatusBlocked {
			result = append(result, d)
		}
	}
	return result
}
