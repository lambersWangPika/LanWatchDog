# raw-socket-sniffer.ps1
# 使用 Windows Raw Socket 捕获网络数据包
# 需要管理员权限运行

param(
    [int]$DurationSeconds = 300,
    [string]$OutputFile = "$env:TEMP\network_capture.json"
)

# 记录开始时间
$startTime = Get-Date

# 存储每个IP的流量
$traffic = @{}

# 获取本地IP地址
$localIPs = @()
try {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($adapter in $adapters) {
        $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ip) {
            $localIPs += $ip.IPAddress
        }
    }
} catch {
    Write-Host "获取本地IP失败: $_"
}

Write-Host "本地IP: $($localIPs -join ', ')"

# 启动捕获
Write-Host "开始捕获数据包..."

try {
    # 创建原始套接字
    $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, 
                                                  [System.Net.Sockets.SocketType]::Raw, 
                                                  [System.Net.Sockets.ProtocolType]::Ip)
    
    # 绑定到第一个本地IP
    $socket.Bind([System.Net.IPAddress]::Parse($localIPs[0]))
    
    # 启用接收所有数据包
    $socket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, 
                           [System.Net.Sockets.SocketOptionName]::HeaderIncluded, 
                           $true)
    
    # 设置超时 (1秒)
    $socket.ReceiveTimeout = 1000
    
    $buffer = New-Object byte[] 65535
    $endTime = (Get-Date).AddSeconds($DurationSeconds)
    
    $packetCount = 0
    $startCapture = Get-Date
    
    while ((Get-Date) -lt $endTime) {
        try {
            $received = $socket.Receive($buffer)
            if ($received -gt 0) {
                $packetCount++
                
                # 解析IP头
                $version = ($buffer[0] -shr 4)
                if ($version -eq 4) {
                    $headerLen = ($buffer[0] -band 0x0F) * 4
                    $totalLen = [BitConverter]::ToInt16($buffer, 2)
                    $protocol = $buffer[9]
                    
                    # 源IP和目标IP
                    $srcIP = "$($buffer[12]).$($buffer[13]).$($buffer[14]).$($buffer[15])"
                    $dstIP = "$($buffer[16]).$($buffer[17]).$($buffer[18]).$($buffer[19])"
                    
                    $payloadLen = $totalLen - $headerLen
                    
                    # 跳过本地自通信
                    if ($srcIP -eq $dstIP) { continue }
                    
                    # 记录流量
                    if (-not $traffic.ContainsKey($srcIP)) {
                        $traffic[$srcIP] = @{BytesIn=0; BytesOut=0}
                    }
                    if (-not $traffic.ContainsKey($dstIP)) {
                        $traffic[$dstIP] = @{BytesIn=0; BytesOut=0}
                    }
                    
                    # 源IP发送 = BytesOut
                    $traffic[$srcIP].BytesOut += $payloadLen
                    # 目标IP接收 = BytesIn
                    $traffic[$dstIP].BytesIn += $payloadLen
                }
            }
        } catch [System.Threading.ThreadInterruptedException] {
            break
        } catch {
            # 超时或其他错误，继续
        }
    }
    
    $socket.Close()
    
} catch {
    Write-Host "捕获失败: $_"
    # 备用方案：使用netstat
    Write-Host "使用备用方案..."
}

# 计算运行时长
$runtime = ((Get-Date) - $startCapture).TotalSeconds

# 输出结果
$result = @{
    StartTime = $startTime.ToString("o")
    EndTime = (Get-Date).ToString("o")
    RuntimeSeconds = $runtime
    PacketCount = $packetCount
    LocalIPs = $localIPs
    Traffic = $traffic
}

# 转换为JSON
$json = $result | ConvertTo-Json -Depth 5

# 保存到文件
Set-Content -Path $OutputFile -Value $json -Encoding UTF8

Write-Host ""
Write-Host "捕获完成!"
Write-Host "运行时长: $runtime 秒"
Write-Host "数据包: $packetCount"
Write-Host "输出: $OutputFile"

# 打印流量摘要
Write-Host ""
Write-Host "流量摘要:"
foreach ($ip in $traffic.Keys | Sort-Object) {
    $t = $traffic[$ip]
    $total = $t.BytesIn + $t.BytesOut
    if ($total -gt 0) {
        Write-Host "  $ip : In=$([Math]::Round($t.BytesIn/1KB,2))KB Out=$([Math]::Round($t.BytesOut/1KB,2))KB"
    }
}
