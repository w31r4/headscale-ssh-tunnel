<#
.SYNOPSIS
    一个用于通过 SSH 隧道安全连接到 Headscale 的 PowerShell 命令行工具。

.DESCRIPTION
    此脚本重写了 'hs-connect.sh' 的核心功能，使其能够在 Windows PowerShell 环境中运行。
    它负责管理 SSH 隧道、获取 Headscale 预授权密钥以及激活本地 Tailscale 节点。
    脚本会自动处理管理员权限提升、首次运行配置和依赖项检查。

.PARAMETER Command
    指定要执行的操作。接受 'start', 'stop', 'status', 'help'。

.EXAMPLE
    .\hs-connect.ps1 start
    启动 SSH 隧道并激活 Headscale 节点。

.EXAMPLE
    .\hs-connect.ps1 stop
    关闭 SSH 隧道并清理相关进程。

.EXAMPLE
    .\hs-connect.ps1 status
    检查隧道和 Tailscale 节点的当前状态。

.NOTES
    作者: w31rd
    版本: 1.0.0
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('start', 'stop', 'status', 'help')]
    [string]$Command = 'help'
)

# --- 自动提权 ---
# 检查当前是否为管理员，如果不是，则使用管理员权限重新启动脚本
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "脚本需要管理员权限，正在尝试自动提权..."
    # 构建重新启动脚本所需的所有参数
    $arguments = "& '$($MyInvocation.MyCommand.Path)' $Command"
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

# --- 配置和设置 ---

# 定义配置路径
$ConfigDir = Join-Path $env:LOCALAPPDATA "hs-connect"
$ConfigFile = Join-Path $ConfigDir "config.json"
$PidFile = Join-Path $ConfigDir "hs-connect.pid"

# 全局配置变量
$Global:Config = $null

# 交互式首次运行配置函数
function Setup-Config {
    Write-Host "--- 首次运行配置向导 ---" -ForegroundColor Yellow
    Write-Host "未找到配置文件，让我们现在创建一个。"
    Write-Host "将在 '$ConfigFile' 创建新的配置文件。"
    Write-Host ""

    # 提示用户输入
    $params = @{
        SERVER_IP        = Read-Host "请输入 Headscale 服务器的 IP 地址 (SERVER_IP)"
        HEADSCALE_DOMAIN = Read-Host "请输入 Headscale 的域名 (HEADSCALE_DOMAIN)"
        SSH_USER         = Read-Host "请输入用于 SSH 登录的用户名 (SSH_USER)"
        SSH_KEY_PATH     = Read-Host "请输入 SSH 密钥的绝对路径 (SSH_KEY_PATH) [默认: ~\ssh\id_rsa]"
        USER             = Read-Host "请输入要创建预授权密钥的 Headscale 用户名 (USER)"
    }

    # 处理默认值
    if ([string]::IsNullOrWhiteSpace($params.SSH_KEY_PATH)) {
        $params.SSH_KEY_PATH = Join-Path $HOME ".ssh\id_rsa"
    }

    # 创建配置目录
    if (-not (Test-Path $ConfigDir)) {
        Write-Host "-> 正在创建配置目录: $ConfigDir"
        New-Item -Path $ConfigDir -ItemType Directory | Out-Null
    }

    # 将配置写入文件
    Write-Host "-> 正在写入配置文件..."
    $params | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8

    Write-Host ""
    Write-Host "✅ 配置已成功保存到 '$ConfigFile'。" -ForegroundColor Green
    Write-Host "   请重新运行您之前的命令，例如: .\hs-connect.ps1 $Command"
    exit 0
}

# 加载配置
function Load-Config {
    if (Test-Path $ConfigFile) {
        try {
            $Global:Config = Get-Content $ConfigFile | ConvertFrom-Json
        }
        catch {
            Write-Error "❌ 配置文件 '$ConfigFile' 解析失败。请检查其 JSON 格式是否正确，或删除它以重新生成。"
            exit 1
        }
    }
    else {
        # 如果没有找到配置文件，则运行设置向导
        Setup-Config
    }
}


# --- 依赖和环境检查 ---

# 检查依赖项
function Test-Dependencies {
    $missingDeps = $false
    $dependencies = "tailscale", "ssh", "ssh-add"
    foreach ($cmd in $dependencies) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            Write-Error "❌ 错误：缺少核心依赖 '$cmd'。请确保它已安装并在系统的 PATH 中。"
            $missingDeps = $true
        }
    }
    if ($missingDeps) {
        exit 1
    }
}

# 检查 hosts 文件
function Test-HostsFile {
    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    $expectedEntry = "127.0.0.1 $($Global:Config.HEADSCALE_DOMAIN)"
    if (-not (Select-String -Path $hostsFile -Pattern $expectedEntry -Quiet)) {
        Write-Error "❌ 错误: hosts 文件缺少必要的条目。"
        Write-Host "   -> 请以管理员权限编辑 '$hostsFile' 文件，并添加以下行："
        Write-Host "      $expectedEntry" -ForegroundColor Cyan
        exit 1
    }
}


# --- 脚本核心逻辑 ---

# 主控制函数
function main {
    # 捕获终止性错误 (包括 Ctrl+C)，确保清理
    trap {
        Write-Warning "`n脚本被意外终止或发生错误，正在执行清理..."
        # 只有在 start 或 status 命令执行期间才需要清理
        if ($Command -eq 'start') {
            Stop-SshTunnel
        }
        # 使用 break 退出脚本
        break
    }

    # 对于非 'help' 命令，加载配置并执行检查
    if ($Command -ne 'help') {
        Load-Config
        Test-Dependencies
        Test-HostsFile
    }

    switch ($Command) {
        'start' {
            Start-AndActivate
        }
        'stop' {
            Stop-SshTunnel
        }
        'status' {
            Get-ConnectionStatus
        }
        'help' {
            Show-Help
        }
        default {
            Show-Help
        }
    }
}

# --- 业务逻辑函数 ---

function Get-AuthKey {
    Write-Host "`n--- 第1步: 远程获取8小时临时预授权密钥 ---" -ForegroundColor Yellow
    $sshCommand = "sudo headscale preauthkeys create --user $($Global:Config.USER) --ephemeral --expiration 8h"
    $sshArgs = @(
        "-i", $Global:Config.SSH_KEY_PATH,
        "$($Global:Config.SSH_USER)@$($Global:Config.SERVER_IP)",
        $sshCommand
    )

    try {
        # 执行 ssh 并将错误流重定向到成功流，以便统一处理
        $output = ssh $sshArgs 2>&1
        
        # 优先在所有返回的行中搜索符合密钥格式的行
        $key = $null
        foreach ($line in $output) {
            # 确保处理的是字符串，并清理
            $trimmedLine = $line.ToString().Trim()
            if ($trimmedLine -match '^[a-f0-9]{48}$') {
                $key = $trimmedLine
                break # 找到密钥就跳出循环
            }
        }

        # 如果成功找到了密钥，就直接返回，忽略其他所有输出（包括无害的错误信息）
        if ($key) {
            Write-Host "   -> 成功获取到8小时临时密钥: $($key.Substring(0, 12))..." -ForegroundColor Green
            return $key
        }
        
        # 只有在完全找不到密钥的情况下，才认为执行失败，并打印所有原始输出以供调试
        Write-Error "   -> 错误：执行 SSH 命令失败，且未能在返回内容中找到有效的预授权密钥。"
        Write-Host "   -> SSH 返回的全部原始输出:"
        foreach ($line in $output) {
            Write-Host "     - $($line.ToString())"
        }
        Write-Host "   -> 请检查服务器返回的错误信息，并确认 Headscale 服务是否正常。"
        return $null
    }
    catch {
        # 此块将捕获其他终止性错误。
        Write-Error "   -> 错误：执行 SSH 命令时发生意外异常。"
        Write-Host "   -> 异常详情: $($_.Exception.Message)"
        return $null
    }
}

function Start-SshTunnel {
    Write-Host "`n--- 第2步: 启动 SSH 隧道 ---" -ForegroundColor Yellow
    
    Write-Host "   -> 正在后台启动 SSH 隧道..."
    $sshArgs = @(
        "-L", "443:localhost:443",
        "-i", $Global:Config.SSH_KEY_PATH,
        "-N", # 不执行远程命令
        "-o", "ExitOnForwardFailure=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "BatchMode=yes",
        "$($Global:Config.SSH_USER)@$($Global:Config.SERVER_IP)"
    )

    $process = Start-Process ssh -ArgumentList $sshArgs -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
    
    if (-not $process) {
        Write-Error "   -> 错误：无法启动 SSH 进程。请检查 ssh.exe 是否在 PATH 中，以及 SSH 参数是否正确。"
        return $false
    }

    Write-Host "   -> 正在验证隧道端口(443)是否可用..."
    $timeout = 5
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $tunnelReady = $false
    $sshPid = $null

    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        $connection = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
        if ($connection) {
            $sshPid = $connection.OwningProcess
            if ($sshPid -eq $process.Id) {
                $tunnelReady = $true
                break
            }
        }
        Start-Sleep -Seconds 1
    }
    $timer.Stop()

    if ($tunnelReady) {
        $sshPid | Set-Content -Path $PidFile
        Write-Host "   -> SSH 隧道已启动，进程 PID: $sshPid" -ForegroundColor Green
        return $true
    } else {
        Write-Error "   -> 错误：SSH 隧道已启动 (PID: $($process.Id))，但在 $timeout 秒内无法验证端口 443 的监听状态。"
        Write-Host "   -> 这可能是一个临时问题或配置错误。请检查防火墙或 SSH 服务器日志。"
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        return $false
    }
}

function Invoke-NodeActivation($authKey) {
    Write-Host "`n--- 第3步: 登录并激活 Headscale 节点 ---" -ForegroundColor Yellow
    $tsArgs = @(
        "up",
        "--login-server=https://$($Global:Config.HEADSCALE_DOMAIN)",
        "--authkey=$authKey",
        "--accept-routes"
    )
    
    tailscale $tsArgs

    # 检查结果
    $tsIp = tailscale ip -4 2>$null
    if ($tsIp) {
        Write-Host ""
        Write-Host "✅ 恭喜！Headscale 节点已成功激活并在线！" -ForegroundColor Green
        Write-Host "   -> 本机 IP: $tsIp"
        tailscale status
        return $true
    } else {
        Write-Host ""
        Write-Error "❌ 激活失败。请检查 tailscale 日志 (在事件查看器 'Windows 日志' -> '应用程序' 中查找 'tailscaled')。"
        return $false
    }
}

function Start-AndActivate {
    Write-Host "--- 准备工作: 清理旧的连接和进程 ---" -ForegroundColor Yellow
    tailscale down | Out-Null
    Stop-SshTunnel # 确保端口和进程是干净的

    # 检查 SSH Agent 中是否有密钥
    if ((ssh-add -l 2>$null).Count -eq 0) {
        Write-Error "❌ 错误：SSH Agent 中没有已加载的密钥。"
        Write-Host "   -> 请在运行此脚本前，确保您已在 PowerShell 中执行 'ssh-add' 加载了正确的密钥。"
        Write-Host "   -> 例如: ssh-add ~\.ssh\id_rsa"
        exit 1
    }

    $authKey = Get-AuthKey
    if (-not $authKey) { exit 1 }

    if (-not (Start-SshTunnel)) {
        Stop-SshTunnel
        exit 1
    }

    if (-not (Invoke-NodeActivation -authKey $authKey)) {
        Stop-SshTunnel
        exit 1
    }
}

function Stop-SshTunnel {
    Write-Host "--- 正在关闭 SSH 隧道 ---" -ForegroundColor Yellow
    $tunnelKilled = $false

    # 1. 尝试通过 PID 文件关闭
    if (Test-Path $PidFile) {
        $pid = Get-Content $PidFile
        if ($pid -and (Get-Process -Id $pid -ErrorAction SilentlyContinue)) {
            Stop-Process -Id $pid -Force
            Write-Host "   -> 隧道进程 (PID: $pid) 已通过 PID 文件关闭。"
            $tunnelKilled = $true
        } else {
            Write-Host "   -> PID 文件中的进程 ($pid) 无效或已不存在。"
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "   -> 未找到 PID 文件，将尝试通过端口查找。"
    }

    # 2. 强制检查并关闭任何占用 443 端口的 SSH 隧道进程
    $zombieConnection = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
    if ($zombieConnection) {
        $process = Get-Process -Id $zombieConnection.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and $process.ProcessName -eq 'ssh') {
            Write-Host "   -> 发现残留的 SSH 隧道进程 (PID: $($process.Id)) 正在监听 443 端口，正在强制关闭..." -ForegroundColor Yellow
            Stop-Process -Id $process.Id -Force
            Start-Sleep -Seconds 1
            if (-not (Get-Process -Id $process.Id -ErrorAction SilentlyContinue)) {
                Write-Host "   -> 残留进程 (PID: $($process.Id)) 已被强制关闭。"
                $tunnelKilled = $true
            } else {
                Write-Warning "   -> 警告：无法关闭残留的隧道进程 (PID: $($process.Id))。请手动检查。"
            }
        }
    }
    
    if (-not $tunnelKilled) {
        Write-Host "   -> 未找到正在运行的隧道进程。"
    }
    
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "✅ 清理完成！" -ForegroundColor Green
}

function Get-ConnectionStatus {
    Write-Host "--- 检查连接状态 ---" -ForegroundColor Yellow
    
    # 1. 检查 SSH 隧道
    $tunnelRunning = $false
    if (Test-Path $PidFile) {
        $pid = Get-Content $PidFile
        if ($pid -and (Get-Process -Id $pid -ErrorAction SilentlyContinue)) {
            Write-Host "✅ SSH 隧道: 正在运行 (PID: $pid)" -ForegroundColor Green
            $tunnelRunning = $true
        }
    }
    if (-not $tunnelRunning) {
        # 即使没有 PID 文件，也检查一下端口
        $connection = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
        if ($connection) {
            Write-Host "✅ SSH 隧道: 正在运行 (PID: $($connection.OwningProcess)) - [通过端口检测]" -ForegroundColor Green
        } else {
            Write-Host "❌ SSH 隧道: 未运行" -ForegroundColor Red
        }
    }

    # 2. 检查 Tailscale 节点状态
    try {
        $statusOutput = tailscale status --json
        $status = $statusOutput | ConvertFrom-Json
        if ($status.BackendState -eq 'Running') {
            $tsIp = tailscale ip -4 2>$null
            Write-Host "✅ Tailscale 节点: 在线 (IP: $tsIp)" -ForegroundColor Green
            Write-Host ""
            tailscale status
        } else {
            Write-Host "❌ Tailscale 节点: 服务未运行 ($($status.BackendState))" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Tailscale 节点: 离线或未激活" -ForegroundColor Red
    }
}

function Show-Help {
    Write-Host @"
hs-connect: Headscale SSH 隧道连接工具 (PowerShell版)

一个用于通过 SSH 隧道安全连接到 Headscale 的命令行工具。

用法:
  .\hs-connect.ps1 <command>

可用命令:
  start     启动 SSH 隧道并激活 Headscale 节点
  stop      关闭 SSH 隧道并清理进程
  status    检查隧道和节点的当前连接状态
  help      显示此帮助信息

示例:
  .\hs-connect.ps1 start
  .\hs-connect.ps1 status

该工具会自动请求所需的管理员权限。首次运行时将引导您完成配置。
"@
}


# --- 脚本入口 ---
main