$ErrorActionPreference = "Continue"

Write-Host "=== Test Raw Socket Capture ==="

try {
    $socket = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Raw,
        [System.Net.Sockets.ProtocolType]::Ip
    )
    Write-Host "[OK] Socket created"

    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Select-Object -First 1

    if (-not $ip) {
        Write-Host "[ERROR] No IP found"
        exit 1
    }

    $ipAddr = $ip.IPAddress
    Write-Host "[INFO] Local IP: $ipAddr"

    $endpoint = New-Object System.Net.IPEndpoint([System.Net.IPAddress]::Parse($ipAddr), 0)
    $socket.Bind($endpoint)
    Write-Host "[OK] Bind success"

    $socket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::HeaderIncluded, $true)
    Write-Host "[OK] HeaderIncluded set"

    $socket.ReceiveTimeout = 1000

    $buffer = New-Object byte[] 65535
    $endTime = (Get-Date).AddSeconds(5)
    $packetCount = 0

    Write-Host "[INFO] Start capturing 5 seconds..."

    while ((Get-Date) -lt $endTime) {
        try {
            $received = $socket.Receive($buffer)
            if ($received -gt 0) {
                $packetCount++

                if ($packetCount -le 5) {
                    $version = ($buffer[0] -shr 4)
                    if ($version -eq 4 -and $received -ge 20) {
                        $srcIP = "$($buffer[12]).$($buffer[13]).$($buffer[14]).$($buffer[15])"
                        $dstIP = "$($buffer[16]).$($buffer[17]).$($buffer[18]).$($buffer[19])"
                        Write-Host "  Packet $packetCount : $srcIP -> $dstIP"
                    }
                }
            }
        } catch {
        }
    }

    Write-Host "[OK] Captured $packetCount packets"
    $socket.Close()
    exit 0

} catch {
    Write-Host "[FAILED] $_"
    exit 1
}
