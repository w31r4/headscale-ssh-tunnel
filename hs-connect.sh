#!/bin/bash

# =================================================================
#        Headscale SSH 隧道连接与激活脚本 (v3.0 - 重构版)
# =================================================================
#
#   用法:
#   sudo ./hs-connect.sh start   - 启动隧道并自动激活节点
#   sudo ./hs-connect.sh stop    - 关闭隧道
#
# =================================================================

# --- 脚本核心逻辑 ---

# --- Auto-elevation to root ---
# If not running as root, re-execute with sudo -E to preserve environment
if [[ $EUID -ne 0 ]]; then
   echo "脚本需要 root 权限，正在尝试使用 sudo 自动提权..."
   # Use exec to replace the current process with the new one
   exec sudo -E "$0" "$@"
fi

# --- Configuration and Setup ---

# Define config paths. When under sudo, HOME is /root, so we need the real user's home.
# SUDO_USER is set by sudo. If not set, we are not in sudo, but the root check above handles that.
REAL_HOME=$(getent passwd "${SUDO_USER:-$(whoami)}" | cut -d: -f6)
USER_CONFIG_DIR="$REAL_HOME/.config/hs-connect"
USER_CONFIG_FILE="$USER_CONFIG_DIR/config.sh"
SYSTEM_CONFIG_FILE="/etc/hs-connect/config.sh"
PID_FILE="/var/run/hs-connect.pid"

# Interactive first-run setup function
setup_config() {
    echo "--- 首次运行配置向导 ---"
    echo "未找到配置文件，让我们现在创建一个。"
    echo "将在 '$USER_CONFIG_FILE' 创建新的配置文件。"
    echo ""

    # Prompt for user input
    read -p "请输入 Headscale 服务器的 IP 地址 (SERVER_IP): " SERVER_IP
    read -p "请输入 Headscale 的域名 (HEADSCALE_DOMAIN): " HEADSCALE_DOMAIN
    read -p "请输入用于 SSH 登录的用户名 (SSH_USER): " SSH_USER
    read -p "请输入 SSH 密钥的绝对路径 (SSH_KEY_PATH) [默认: $REAL_HOME/.ssh/id_rsa]: " SSH_KEY_PATH
    SSH_KEY_PATH=${SSH_KEY_PATH:-"$REAL_HOME/.ssh/id_rsa"}
    read -p "请输入要创建预授权密钥的 Headscale 用户名 (USER): " USER

    # Create config directory and set ownership
    echo "-> 正在创建配置目录: $USER_CONFIG_DIR"
    mkdir -p "$USER_CONFIG_DIR"
    chown -R "$SUDO_USER:$SUDO_GID" "$USER_CONFIG_DIR"

    # Write config file and set ownership
    echo "-> 正在写入配置文件..."
    # Use a temporary file to avoid permission issues with cat redirection
    local temp_config
    temp_config=$(mktemp)
    cat > "$temp_config" << EOL
#!/bin/bash
# Headscale 连接配置

# Headscale 服务器的 IP 地址
SERVER_IP="$SERVER_IP"

# Headscale 的域名
HEADSCALE_DOMAIN="$HEADSCALE_DOMAIN"

# 用于 SSH 登录的用户名
SSH_USER="$SSH_USER"

# SSH 密钥的绝对路径
SSH_KEY_PATH="$SSH_KEY_PATH"

# Headscale 用户名 (用于创建 pre-auth key)
USER="$USER"
EOL
    
    mv "$temp_config" "$USER_CONFIG_FILE"
    chown "$SUDO_USER:$SUDO_GID" "$USER_CONFIG_FILE"

    echo ""
    echo "✅ 配置已成功保存到 '$USER_CONFIG_FILE'。"
    echo "   请重新运行您之前的命令，例如: $0 $1"
    exit 0
}

# Load configuration
if [ -f "$USER_CONFIG_FILE" ]; then
    source "$USER_CONFIG_FILE"
elif [ -f "$SYSTEM_CONFIG_FILE" ]; then
    source "$SYSTEM_CONFIG_FILE"
else
    # If no config is found, run the setup wizard.
    # This part is reached only when running as root (due to auto-elevation).
    setup_config "$@"
fi

# --- Dependency and Environment Checks ---

# Check dependencies
check_dependencies() {
    local missing_deps=0
    for cmd in tailscale nc ssh ssh-add; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "❌ 错误：缺少核心依赖 '$cmd'。请先安装它。"
            missing_deps=1
        fi
    done
    if [ "$missing_deps" -eq 1 ]; then
        exit 1
    fi
}

# Check /etc/hosts file
check_hosts_file() {
    # This check can only run after config is loaded
    local expected_entry="127.0.0.1 $HEADSCALE_DOMAIN"
    if ! grep -q "$expected_entry" /etc/hosts; then
        echo "❌ 错误: /etc/hosts 文件缺少必要的条目。"
        echo "   -> 请以 root 权限编辑 /etc/hosts 文件，并添加以下行："
        echo "      $expected_entry"
        exit 1
    fi
}

# --- Run pre-flight checks ---
check_dependencies
check_hosts_file

# --- 业务逻辑函数 ---

get_auth_key() {
    echo "--- 第1步: 远程获取8小时临时预授权密钥 ---"
    local key
    key=$(ssh -i "$SSH_KEY_PATH" -t "$SSH_USER@$SERVER_IP" \
      "sudo headscale preauthkeys create --user $USER --ephemeral --expiration 8h" | tail -n 1)
    
    key=$(echo "$key" | tr -d '\r')

    if [[ ! "$key" =~ ^[a-f0-9]{48}$ ]]; then
        echo "   -> 错误：未能从服务器获取有效的预授权密钥。"
        echo "   -> 获取到的原始输出: '$key'"
        echo "   -> 请检查远程服务器上的 Headscale 服务是否正常，以及 SSH 免密登录是否配置正确。"
        return 1
    fi
    echo "   -> 成功获取到8小时临时密钥: ${key:0:12}..."
    AUTH_KEY=$key # 将密钥赋值给全局变量
    return 0
}

start_tunnel() {
    echo ""
    echo "--- 第2步: 启动 SSH 隧道 ---"
    if [ -f "$PID_FILE" ] && ps -p $(cat "$PID_FILE") > /dev/null; then
        echo "   -> SSH 隧道已在运行 (PID: $(cat "$PID_FILE"))。"
        return 0
    fi

    echo "   -> 正在后台启动 SSH 隧道..."
    ssh -L 443:localhost:443 -i "$SSH_KEY_PATH" -fN -o ExitOnForwardFailure=yes "$SSH_USER@$SERVER_IP"
    local SSH_PID=$!
    echo "$SSH_PID" > "$PID_FILE"
    
    echo "   -> 等待隧道端口(443)可用..."
    for i in {1..10}; do
        if nc -z 127.0.0.1 443 &>/dev/null; then
            echo "   -> 隧道端口已准备就绪。"
            echo "   -> SSH 隧道成功启动 (PID: $SSH_PID)！"
            return 0
        fi
        sleep 1
    done

    echo "   -> 错误：SSH 隧道在10秒内未能成功监听端口 443。"
    echo "   -> 请检查 'ssh -L 443:localhost:443' 命令是否成功，或检查防火墙设置。"
    return 1
}

activate_node() {
    echo ""
    echo "--- 第3步: 登录并激活 Headscale 节点 ---"
    tailscale up --login-server="https://$HEADSCALE_DOMAIN" --authkey="$AUTH_KEY" --accept-routes

    if tailscale ip -4 &>/dev/null; then
         local TS_IP=$(tailscale ip -4)
         echo ""
         echo "✅ 恭喜！Headscale 节点已成功激活并在线！"
         echo "   -> 本机 IP: $TS_IP"
         tailscale status
         return 0
    else
         echo ""
         echo "❌ 激活失败。请检查 tailscale 日志 (sudo journalctl -u tailscaled -n 50)。"
         return 1
    fi
}

# --- 主控制函数 ---

start_and_activate() {
    echo "--- 准备工作: 确保 tailscale 处于关闭状态 ---"
    tailscale down >/dev/null 2>&1
    
    if ! ssh-add -l >/dev/null 2>&1; then
        # 检查是否在 sudo 环境下，并且 SSH_AUTH_SOCK 丢失
        if [[ -n "$SUDO_USER" ]] && [[ -z "$SSH_AUTH_SOCK" ]]; then
            echo "❌ 错误：在 sudo 环境下无法连接到 SSH Agent。"
            echo "   -> 这是因为 sudo 默认会重置环境变量。"
            echo "   -> 请尝试使用 'sudo -E' 来运行此脚本，以保留您的用户环境:"
            echo "      sudo -E ./hs-connect.sh $1"
        else
            echo "❌ 错误：SSH Agent 中没有已加载的密钥，或无法连接。"
            echo "   -> 请确保您的 SSH 密钥已通过 'ssh-add' 加载。"
            echo "   -> 如果您正在使用 sudo，请尝试 'sudo -E'。"
        fi
        exit 1
    fi

    if ! get_auth_key; then
        exit 1
    fi

    if ! start_tunnel; then
        stop_tunnel
        exit 1
    fi

    if ! activate_node; then
        stop_tunnel
        exit 1
    fi
}

# 关闭隧道
stop_tunnel() {
    echo "--- 正在关闭 SSH 隧道 ---"
    if [ -f "$PID_FILE" ]; then
        local SSH_PID=$(cat "$PID_FILE")
        if ps -p "$SSH_PID" > /dev/null; then
            kill "$SSH_PID"
            echo "   -> 隧道进程 (PID: $SSH_PID) 已关闭。"
        else
            echo "   -> 找到 PID 文件，但未找到对应的隧道进程。"
        fi
        rm -f "$PID_FILE"
    else
        echo "   -> 未找到 PID 文件，可能隧道未通过此脚本启动。"
    fi
    echo "✅ 清理完成！"
}

# 设置 trap，捕获退出信号并执行清理
trap 'stop_tunnel' SIGINT SIGTERM

# 检查状态
check_status() {
    echo "--- 检查连接状态 ---"
    
    # 1. 检查 SSH 隧道
    if [ -f "$PID_FILE" ] && ps -p $(cat "$PID_FILE") > /dev/null; then
        echo "✅ SSH 隧道: 正在运行 (PID: $(cat "$PID_FILE"))"
    else
        echo "❌ SSH 隧道: 未运行"
    fi

    # 2. 检查 Tailscale 节点状态
    # 'tailscale status' 的退出代码比 'tailscale ip' 更能准确反映服务状态
    if tailscale status &>/dev/null; then
        local TS_IP
        TS_IP=$(tailscale ip -4) || TS_IP="获取中..."
        echo "✅ Tailscale 节点: 在线 (IP: $TS_IP)"
        echo ""
        tailscale status
    else
        echo "❌ Tailscale 节点: 离线或未激活"
    fi
}

# 显示帮助信息
show_help() {
    echo "hs-connect: Headscale SSH 隧道连接工具"
    echo ""
    echo "一个用于通过 SSH 隧道安全连接到 Headscale 的命令行工具。"
    echo ""
    echo "用法:"
    echo "  hs-connect <command>"
    echo ""
    echo "可用命令:"
    echo "  start     启动 SSH 隧道并激活 Headscale 节点"
    echo "  stop      关闭 SSH 隧道并清理进程"
    echo "  status    检查隧道和节点的当前连接状态"
    echo "  help      显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  hs-connect start"
    echo "  hs-connect status"
    echo ""
    echo "该工具会自动使用 sudo 获取所需权限。首次运行时将引导您完成配置。"
}

# 根据用户输入的参数执行操作
case "$1" in
    start)
        start_and_activate
        ;;
    stop)
        stop_tunnel
        ;;
    status)
        check_status
        ;;
    h|help|-h|--help)
        show_help
        exit 0
        ;;
    *)
        show_help
        exit 1
        ;;
esac