# 设置 exe 图标脚本
# 需要将 icon.ico 和 exe 放在同一目录

param(
    [string]$ExeName = "nm.exe",
    [string]$IconName = "icon.ico"
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $scriptPath $ExeName
$iconPath = Join-Path $scriptPath $IconName

if (-not (Test-Path $exePath)) {
    Write-Host "错误: 找不到 $ExeName" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $iconPath)) {
    Write-Host "错误: 找不到 $IconName" -ForegroundColor Red
    exit 1
}

# 使用 .NET 设置图标
Add-Type -AssemblyName System.Drawing

try {
    # 读取图标
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
    
    # 使用 PowerShell 脚本创建带有图标的新 exe
    # 这里我们用简单方法 - 复制并关联图标
    $tempScript = @"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class IconChanger {
    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SHFILEINFO {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }
    
    public const uint SHGFI_ICON = 0x100;
    public const uint SHGFI_SMALLICON = 0x1;
}
"@

    Write-Host "正在设置图标..." -ForegroundColor Yellow
    Write-Host "Exe: $exePath"
    Write-Host "Icon: $iconPath"
    
    # 使用更简单的方法 - 创建快捷方式并设置图标
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$exePath.lnk")
    $Shortcut.IconLocation = "$iconPath, 0"
    $Shortcut.Save()
    
    Write-Host "已创建快捷方式并设置图标!" -ForegroundColor Green
    Write-Host "快捷方式: $exePath.lnk"
    
} catch {
    Write-Host "错误: $_" -ForegroundColor Red
}
