# Headscale SSH 隧道连接脚本

本项目提供一个 Shell 脚本 `hs-connect.sh`，用于在无法直接进行 TLS 连接到 Headscale 服务器的情况下，通过建立 SSH 隧道来安全地注册和连接 Tailscale 节点。

## 核心原理

在某些网络环境中，服务提供商可能会对出站的 TLS 连接进行深度包检测（DPI）或特征审查，这可能导致标准的 Headscale 连接被中断或失败。

为了绕过这种审查，本脚本采用了一种 SSH 隧道技术：

1.  **建立隧道**：脚本通过 SSH 在本地机器和您的 Headscale 服务器之间建立一个安全的隧道。
2.  **端口转发**：它将本机的 `443` 端口转发到 Headscale 服务器上的 `localhost:443`。这意味着，当 Tailscale 客户端尝试连接 `https://<你的域名>` 时，由于 `/etc/hosts` 文件的配置，流量实际上被导向到 `127.0.0.1:443`，也就是 SSH 隧道的入口。
3.  **安全通信**：流量通过 SSH 隧道安全地传输到您的服务器，然后在服务器内部直接访问 Headscale 服务。由于流量被封装在 SSH 协议内，外部网络无法审查其内部的 TLS 握手过程，从而成功规避了连接问题。

整个过程可以简化为：
`Tailscale 客户端 -> 本地 443 端口 -> SSH 隧道 -> Headscale 服务器 -> Headscale 服务`

## 前提条件

在使用此脚本前，请确保您已完成以下配置：

1.  **修改 Hosts 文件**：
    在您的 **本地客户端机器** 上，编辑 `/etc/hosts` 文件 (需要 `sudo` 权限)，添加以下行，将您的 Headscale 域名指向本地回环地址：
    ```
    127.0.0.1 your.headscale.domain.com
    ```
    例如：
    ```
    127.0.0.1 headscale.zflink.site
    ```

2.  **配置 SSH 免密登录**：
    确保您可以从本地机器通过 SSH 密钥免密码登录到您的 Headscale 服务器。如果尚未配置，请先生成 SSH 密钥并将公钥添加到服务器的 `~/.ssh/authorized_keys` 文件中。

3.  **SSH Agent 配置**：
    脚本会检查您的 SSH Agent 中是否已加载私钥。在运行脚本前，请确保执行了以下命令来加载密钥：
    ```bash
    eval $(ssh-agent -s)
    ssh-add /path/to/your/private_key
    ```

## 配置说明

在首次使用 `hs-connect.sh` 脚本前，请打开脚本文件并修改以下变量：

-   `SERVER_IP`: 您的云服务器的公网 IP 地址。
-   `HEADSCALE_DOMAIN`: 您的 Headscale 服务的域名。
-   `SSH_USER`: 您用于登录云服务器的 SSH 用户名。
-   `SSH_KEY_PATH`: 您在本地机器上存放的 SSH 私钥的绝对路径 (例如：`/home/user/.ssh/id_rsa`)。
-   `USER`: 您在 Headscale 中为该设备指定的用户名（或称 Namespace）。

## 用法

将脚本放置在任意目录，并为其添加可执行权限：
```bash
chmod +x hs-connect.sh
```

### 启动隧道并激活节点

使用 `sudo` 权限运行 `start` 命令。脚本会自动完成获取预授权密钥、建立隧道和激活 Tailscale 节点的全部流程。

```bash
sudo ./hs-connect.sh start
```

### 关闭隧道

当您不再需要连接时，运行 `stop` 命令来关闭 SSH 隧道，释放本地端口。

```bash
sudo ./hs-connect.sh stop