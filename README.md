# Headscale SSH 隧道连接脚本 (v3.0)

本项目提供一个高度健壮的 Shell 脚本 `hs-connect.sh`，用于在无法直接进行 TLS 连接到 Headscale 服务器的情况下，通过建立 SSH 隧道来安全地注册和连接 Tailscale 节点。

与普通脚本不同，本项目注重**易用性**、**健壮性**和**安全性**，内置了完整的配置引导、环境检查和进程管理机制。

## 核心原理

在某些网络环境中，服务提供商可能会对出站的 TLS 连接进行深度包检测（DPI）或特征审查，这可能导致标准的 Headscale 连接被中断或失败。

为了绕过这种审查，本脚本采用了一种 SSH 隧道技术：

1.  **建立隧道**：脚本通过 SSH 在本地机器和您的 Headscale 服务器之间建立一个安全的隧道。
2.  **端口转发**：它将本机的 `443` 端口转发到 Headscale 服务器上的 `localhost:443`。这意味着，当 Tailscale 客户端尝试连接 `https://<你的域名>` 时，由于 `/etc/hosts` 文件的配置，流量实际上被导向到 `127.0.0.1:443`，也就是 SSH 隧道的入口。
3.  **安全通信**：流量通过 SSH 隧道安全地传输到您的服务器，然后在服务器内部直接访问 Headscale 服务。由于流量被封装在 SSH 协议内，外部网络无法审查其内部的 TLS 握手过程，从而成功规避了连接问题。

整个过程可以简化为：
`Tailscale 客户端 -> 本地 443 端口 -> SSH 隧道 -> Headscale 服务器 -> Headscale 服务`

## 特性

- **配置与逻辑分离**：通过 `config.sh` 管理所有个人配置，脚本更新不影响配置。
- **自动环境检查**：启动前自动检查 `tailscale`, `ssh`, `nc` 等依赖，以及 `/etc/hosts` 文件配置。
- **精确的进程管理**：使用 PID 文件 (`/var/run/hs-connect.pid`) 精确控制隧道进程，避免误操作。
- **健壮的错误处理**：在每一步都进行验证，并在失败时提供清晰的指引。
- **优雅的退出机制**：通过 `trap` 捕获中断信号，确保任何情况下都能清理残留进程。
- **状态检查**：提供 `status` 命令，快速了解隧道和节点的当前状态。

## 配置步骤

1.  **复制配置文件**
    将配置文件模板 `config.sh.example` 复制为 `config.sh`。
    ```bash
    cp config.sh.example config.sh
    ```

2.  **编辑配置文件**
    打开 `config.sh` 文件，并填入您自己的信息：
    - `SERVER_IP`: 您的云服务器的公网 IP 地址。
    - `HEADSCALE_DOMAIN`: 您的 Headscale 服务的域名。
    - `SSH_USER`: 您用于登录云服务器的 SSH 用户名。
    - `SSH_KEY_PATH`: 您在本地机器上存放的 SSH 私钥的绝对路径 (例如：`/home/user/.ssh/id_rsa`)。
    - `USER`: 您在 Headscale 中为该设备指定的用户名（或称 Namespace）。

## 前提条件

在运行脚本前，请确保您已完成以下配置。脚本会自动检查这些条件，并在不满足时给出提示。

1.  **修改 Hosts 文件**：
    在您的 **本地客户端机器** 上，编辑 `/etc/hosts` 文件 (需要 `sudo` 权限)，添加以下行：
    ```
    127.0.0.1 your.headscale.domain.com
    ```
    *(脚本会自动检查该配置是否存在)*

2.  **配置 SSH 免密登录**：
    确保您可以从本地机器通过 SSH 密钥免密码登录到您的 Headscale 服务器。

3.  **SSH Agent 配置**：
    脚本会检查您的 SSH Agent 中是否已加载私钥。在运行脚本前，请确保执行了以下命令来加载密钥：
    ```bash
    eval $(ssh-agent -s)
    ssh-add /path/to/your/private_key
    ```

## 用法

为脚本添加可执行权限：
```bash
chmod +x hs-connect.sh
```

### 启动隧道并激活节点
```bash
sudo ./hs-connect.sh start
```

### 关闭隧道
```bash
sudo ./hs-connect.sh stop
```

### 检查连接状态
```bash
sudo ./hs-connect.sh status
```

## 故障排查

- **错误: 配置文件 'config.sh' 未找到!**
  -> 您需要将 `config.sh.example` 复制为 `config.sh` 并填写您的配置。

- **错误: /etc/hosts 文件缺少必要的条目。**
  -> 请按照“前提条件”中的说明，编辑 `/etc/hosts` 文件。

- **错误：缺少核心依赖 'xxx'。**
  -> 请根据提示安装缺失的命令行工具。例如，在 Debian/Ubuntu 上：`sudo apt-get install openssh-client netcat-openbsd`。

- **错误：未能从服务器获取有效的预授权密钥。**
  -> 请检查：
    1.  `config.sh` 中的服务器信息和 Headscale 用户名是否正确。
    2.  您的 SSH 免密登录是否仍然有效。
    3.  服务器上的 Headscale 服务是否正在正常运行。

- **错误：SSH 隧道在10秒内未能成功监听端口 443。**
  -> 请检查：
    1.  本地的 `443` 端口是否已被其他程序占用 (`sudo lsof -i:443`)。
    2.  服务器的防火墙是否允许 SSH 连接。