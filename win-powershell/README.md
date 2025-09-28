# msh (Matryoshka-SHell) - PowerShell 版 (v4.0)

本项目提供一个名为 `msh.ps1` 的 PowerShell 脚本，用于在无法直接进行 TLS 连接到 Headscale 服务器的情况下，通过建立 SSH 隧道来安全地注册和连接 Tailscale 节点。

这是 `msh` 项目的 Windows/PowerShell 实现。

## 核心原理

在某些网络环境中，服务提供商可能会对出站的 TLS 连接进行深度包检测（DPI）或特征审查，这可能导致标准的 Headscale 连接被中断或失败。

为了绕过这种审查，本工具采用了一种 SSH 隧道技术：

1.  **建立隧道**：通过 SSH 在本地 Windows 机器和您的 Headscale 服务器之间建立一个安全的隧道。
2.  **端口转发**：它将本机的 `443` 端口转发到 Headscale 服务器上的 `localhost:443`。这意味着，当 Tailscale 客户端尝试连接 `https://<你的域名>` 时，由于 `hosts` 文件的配置，流量实际上被导向到 `127.0.0.1:443`，也就是 SSH 隧道的入口。
3.  **安全通信**：流量通过 SSH 隧道安全地传输到您的服务器，然后在服务器内部直接访问 Headscale 服务。由于流量被封装在 SSH 协议内，外部网络无法审查其内部的 TLS 握手过程，从而成功规避了连接问题。

整个过程可以简化为：
`Tailscale 客户端 -> 本地 443 端口 -> SSH 隧道 -> Headscale 服务器 -> Headscale 服务`

## 特性

- **交互式配置**：首次运行时自动引导用户完成所有必要配置，无需手动编辑文件。
- **智能的环境检查**：启动前自动检查 `tailscale.exe`, `ssh.exe` 等核心依赖，并验证 `hosts` 文件配置。
- **健壮的进程管理**：
    - **杜绝僵尸进程**：在启动前和结束后，通过 PID 文件和端口查询强制查找并清理任何残留的隧道进程。
    - **自动提权**：脚本会自动检测是否需要管理员权限，并提示用户进行提权。
- **清晰的错误处理**：在 SSH 连接失败或配置错误时提供清晰的错误信息。
- **优雅的退出机制**：通过 `trap` 捕获中断信号 (`Ctrl+C`)，确保任何情况下都能清理残留进程。
- **状态检查**：提供 `status` 命令，快速了解隧道和节点的当前状态。

## 前提条件

在运行脚本前，请确保您已完成以下配置。

1.  **安装 Tailscale for Windows**: 从 [Tailscale 官网](https://tailscale.com/download/windows) 下载并安装。
2.  **安装 OpenSSH Client**:
    - Windows 10 和 11 通常已内置。您可以在 PowerShell 中运行 `ssh -V` 来验证。
    - 如果未安装，请打开 "设置" > "应用" > "可选功能"，点击 "添加功能"，然后搜索并安装 "OpenSSH 客户端"。
3.  **修改 Hosts 文件**:
    - 以 **管理员权限** 打开记事本或其他文本编辑器。
    - 打开文件 `C:\Windows\System32\drivers\etc\hosts`。
    - 在文件末尾添加以下行，并将 `your.headscale.domain.com` 替换为您的真实 Headscale 域名：
      ```
      127.0.0.1 your.headscale.domain.com
      ```
    - *(脚本会自动检查该配置是否存在)*
4.  **配置 SSH 免密登录**:
    - 确保您可以从本地 Windows 机器通过 SSH 密钥免密码登录到您的 Headscale 服务器。
5.  **SSH Agent 配置 (重要)**:
    - 脚本会检查您的 SSH Agent 中是否已加载私钥。在运行脚本前，请在 **PowerShell 终端** 中执行以下命令来启动 agent 并加载密钥：
      ```powershell
      # 启动 SSH Agent 服务 (如果尚未运行)
      Start-Service ssh-agent

      # 将私钥添加到 Agent (将路径替换为您的私钥路径)
      ssh-add ~\.ssh\id_rsa
      ```

## 用法

1.  打开一个 **PowerShell** 终端 (建议使用 Windows Terminal)。
2.  导航到 `win-powershell` 目录。
3.  根据需要执行以下命令：

### 首次运行与配置
当您第一次运行 `start` 或 `status` 命令时，工具会启动一个交互式的设置向导，引导您完成配置。

配置文件将被保存在以下位置：
`C:\Users\<你的用户名>\AppData\Local\msh\config.json`

配置文件内容示例：
```json
{
  "SERVER_IP": "1.2.3.4",
  "HEADSCALE_DOMAIN": "your.headscale.domain.com",
  "SSH_USER": "root",
  "SSH_KEY_PATH": "C:\\Users\\YourUser\\.ssh\\id_rsa",
  "USER": "your-headscale-user",
  "TUNNEL_PORT": 443
}
```

### 可用命令

#### 启动隧道并激活节点
```powershell
.\msh.ps1 start [Options]
```
- **描述**: 这是最常用的命令。它会清理旧进程、获取预授权密钥、建立 SSH 隧道，并激活本地 Tailscale 节点。
- **选项**:
  - `-Port <端口号>`: 临时指定隧道的本地端口，覆盖配置文件中的 `TUNNEL_PORT`。
  - `-Expiration <时长>`: 指定预授权密钥的有效期，例如 `12h` (12 小时), `30d` (30 天)。默认为 `8h`。

**示例：**
```powershell
# 使用默认配置启动
.\msh.ps1 start

# 使用 10443 端口，并设置密钥有效期为30天
.\msh.ps1 start -Port 10443 -Expiration 30d
```

#### 关闭隧道
```powershell
.\msh.ps1 stop
```
- **描述**: 关闭由脚本启动的 SSH 隧道并清理所有相关进程。

#### 检查连接状态
```powershell
.\msh.ps1 status
```
- **描述**: 检查 SSH 隧道和 Tailscale 节点的当前状态。

#### 仅激活节点
```powershell
.\msh.ps1 activate [Options]
```
- **描述**: 此命令仅获取预授权密钥并激活节点，它**不会**创建新的 SSH 隧道。适用于多个客户端（例如 Windows 和 WSL）共享同一个隧道的情况。
- **选项**:
  - `-Expiration <时长>`: 指定预授权密钥的有效期。

#### 使用已有密钥激活
```powershell
.\msh.ps1 link -Key <预授权密钥> [-Port <端口号>]
```
- **描述**: 直接使用一个已经存在的预授权密钥来激活节点。此命令非常智能：它会先检查 SSH 隧道是否存在，如果不存在，则会自动为您启动一个。
- **选项**:
  - `-Port <端口号>`: 在自动启动隧道时，可以临时指定一个端口。
- **示例**:
  ```powershell
  .\msh.ps1 link -Key hskey-e-a1b2c3d4e5f6...
  ```

#### 显示帮助
```powershell
.\msh.ps1 help
```

## Windows + WSL 协作模式

在 Windows 11 (22H2 或更高版本) 上使用 WSL2 时，推荐启用 **`mirrored` 网络模式**。这允许 WSL 和 Windows 共享网络接口，从而实现更高级的协作。

在这种模式下，正确的做法是：**在 Windows 上建立主隧道，然后在 WSL 中“借用”该隧道来激活节点。**

**工作流程：**

1.  **在 Windows PowerShell 中启动主隧道 (当前脚本)**:
  ```powershell
  # 运行 start 命令
  .\msh.ps1 start
  ```
  这会在 Windows 上建立唯一的 SSH 隧道，并激活 Windows 的 Tailscale 节点。

2.  **在 WSL 终端中激活节点**:
  - 打开您的 WSL 终端。
  - 确保您已经在 WSL 中安装了 `msh` 的 Bash 版本。
  - 运行 `activate` 命令：
  ```bash
  # 这会借用 Windows 的隧道来激活 WSL 的节点
  msh activate
  ```

完成后，您的 Windows 和 WSL 将作为两个独立的设备出现在 Headscale 网络中，并且都能正常通信。

## 故障排查

- **错误：未能从服务器获取有效的预授权密钥 / SSH 错误详情...**
  - 这个错误通常意味着 SSH 密钥认证失败。请检查：
    1.  您的 SSH 免密登录是否配置正确。可以手动测试：`ssh -i <您的密钥路径> <用户名>@<服务器IP>`。
    2.  确保运行脚本前，您的 SSH 密钥已通过 `ssh-add` 添加到 SSH Agent 中。可以通过 `ssh-add -l` 确认。
    3.  检查 `config.json` 文件中的服务器 IP、SSH 用户名和密钥路径是否正确。
    4.  服务器上的 Headscale 服务是否正在正常运行。

- **错误：hosts 文件缺少必要的条目。**
  - 请按照“前提条件”中的说明，以管理员权限编辑 `hosts` 文件。

- **错误：缺少核心依赖 'xxx'。**
  - 请根据提示安装缺失的程序，并确保其路径已添加到系统的 `PATH` 环境变量中。

- **脚本无响应或卡住**
  - 可能是由于 `ssh` 命令在等待密码输入。请确保您的 SSH 密钥是免密登录的。