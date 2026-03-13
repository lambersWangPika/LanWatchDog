@echo off
echo ========================================
echo   LanWatchDog v1.3.1 - PCAP 支持
echo ========================================
echo.

echo [1/3] 检查 npcap 是否已安装...
reg query "HKLM\SYSTEM\CurrentControlSet\Services\npcap" >nul 2>&1
if %errorlevel%==0 (
    echo [OK] npcap 已安装
) else (
    echo [!] npcap 未安装
    echo.
    echo 请手动下载并安装 npcap:
    echo   1. 访问: https://npcap.com/dist/npcap-1.78.exe
    echo   2. 下载后双击运行安装
    echo   3. 安装时勾选 "Npcap Loopback Adapter" 和 "Install npcap in WinPcap API-compatible mode"
    echo.
    echo 或点击这里自动下载:
    start https://npcap.com/dist/npcap-1.78.exe
    echo.
    echo 安装完成后按任意键继续...
    pause >nul
)

echo.
echo [2/3] 备份旧版本...
if exist nm.exe.bak del nm.exe.bak
if exist nm.exe ren nm.exe nm.exe.bak
echo [OK] 已备份到 nm.exe.bak

echo.
echo [3/3] 检查新版本...
if exist nm_new.exe del nm_new.exe
if exist nm.exe (
    echo [!] 请先将新的 nm.exe 放到此文件夹
    echo 按任意键退出...
    pause >nul
    exit /b 1
)

echo.
echo ========================================
echo 安装完成！
echo.
echo 启动程序: nm.exe
echo.
echo 在设置页面启用 "PCAP 精确流量" 可获得设备级流量统计
echo ========================================
pause
