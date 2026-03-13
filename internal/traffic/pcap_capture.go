package traffic

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PCAPCapture 使用 gopacket 捕获网络数据包
type PCAPCapture struct {
	handle     *pcap.Handle
	stopChan   chan struct{}
	traffic    map[string]*PCAPTraffic
}

type PCAPTraffic struct {
	BytesIn  int64
	BytesOut int64
	Packets  int64
}

// NewPCAPCapture 创建 pcap 捕获器
func NewPCAPCapture(interfaceName string) *PCAPCapture {
	c := &PCAPCapture{
		traffic:  make(map[string]*PCAPTraffic),
		stopChan: make(chan struct{}),
	}

	// 打开网卡
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[PCAP] 打开网卡失败: %v", err)
		return nil
	}
	c.handle = handle

	log.Printf("[PCAP] 已打开网卡: %s", interfaceName)
	return c
}

// Start 开始捕获
func (c *PCAPCapture) Start() {
	if c == nil || c.handle == nil {
		return
	}

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())

	go func() {
		for {
			select {
			case <-c.stopChan:
				return
			case packet := <-packetSource.Packets():
				if packet != nil {
					c.processPacket(packet)
				}
			}
		}
	}()
}

// Stop 停止捕获
func (c *PCAPCapture) Stop() {
	if c == nil {
		return
	}
	close(c.stopChan)
	if c.handle != nil {
		c.handle.Close()
	}
}

// processPacket 处理数据包
func (c *PCAPCapture) processPacket(packet gopacket.Packet) {
	// 解析 IP 层
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

	// 获取 payload 大小
	payloadLen := int(ip.Length) - int(ip.IHL)*4

	if payloadLen <= 0 {
		return
	}

	// 更新流量统计
	c.traffic[srcIP] = &PCAPTraffic{
		BytesOut: c.traffic[srcIP].BytesOut + int64(payloadLen),
		Packets:  c.traffic[srcIP].Packets + 1,
	}
	c.traffic[dstIP] = &PCAPTraffic{
		BytesIn: c.traffic[dstIP].BytesIn + int64(payloadLen),
		Packets:  c.traffic[dstIP].Packets + 1,
	}
}

// GetTraffic 获取流量
func (c *PCAPCapture) GetTraffic() map[string]int64 {
	if c == nil {
		return nil
	}

	result := make(map[string]int64)
	for ip, t := range c.traffic {
		result[ip] = t.BytesIn + t.BytesOut
	}
	return result
}

// GetNetworkInterfaces 获取网卡列表
func GetNetworkInterfaces() []string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("[PCAP] 获取网卡列表失败: %v", err)
		return nil
	}

	var ifaces []string
	for _, device := range devices {
		ifaces = append(ifaces, device.Name)
	}
	return ifaces
}
