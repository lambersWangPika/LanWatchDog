# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Is Administrator: $isAdmin"

if (-not $isAdmin) {
    Write-Host "[ERROR] Please run as Administrator"
    exit 1
}

# 获取所有网络适配器
Write-Host "`n=== Network Adapters ==="
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress | Format-Table

# 获取本地IP
Write-Host "`n=== Local IPs ==="
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object IPAddress, InterfaceAlias | Format-Table

# 尝试不同的方法
Write-Host "`n=== Test Raw Socket ==="

try {
    $socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Raw,
        [System.Net.Sockets.ProtocolType]::Ip
    )
    Write-Host "[OK] Socket created"

    # 尝试绑定到每个IP
    $ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 3

    foreach ($ipObj in $ips) {
        $ip = $ipObj.IPAddress
        Write-Host "`nTrying IP: $ip"

        try {
            $endpoint = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Parse($ip), 0)
            $socket.Bind($endpoint)
            Write-Host "[OK] Bound to $ip"

            # 尝试各种选项
            $socket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::HeaderIncluded, $true)
            Write-Host "[OK] HeaderIncluded"

            # 尝试 IOControl
            $ioctl = 0x9800000C  # SIO_RCVALL
            $mode = [byte[]](1, 0, 0, 0)
            $socket.IOControl($ioctl, $mode, $null)
            Write-Host "[OK] IOControl SIO_RCVALL"

            $socket.ReceiveTimeout = 1000

            $buffer = New-Object byte[] 65535
            $received = $socket.Receive($buffer)

            if ($received -gt 0) {
                Write-Host "[OK] Received $received bytes"
                $version = ($buffer[0] -shr 4)
                Write-Host "  IP Version: $version"
            } else {
                Write-Host "[INFO] No data received in 1 second"
            }

            break

        } catch {
            Write-Host "[ERROR] $ip : $_"
        }
    }

    $socket.Close()

} catch {
    Write-Host "[FAILED] $_"
}
