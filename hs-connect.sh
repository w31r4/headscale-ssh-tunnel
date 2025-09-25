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

# 获取脚本所在目录，以便定位配置文件
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
CONFIG_FILE="$SCRIPT_DIR/config.sh"
PID_FILE="/var/run/hs-connect.pid"

# 检查配置文件是否存在
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ 错误：配置文件 'config.sh' 未找到！"
    echo "   -> 请将 'config.sh.example' 复制为 'config.sh'，并填入您的配置信息。"
    exit 1
fi

# 加载配置
source "$CONFIG_FILE"

# 检查依赖
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

# 检查 /etc/hosts 文件
check_hosts_file() {
    local expected_entry="127.0.0.1 $HEADSCALE_DOMAIN"
    if ! grep -q "$expected_entry" /etc/hosts; then
        echo "❌ 错误: /etc/hosts 文件缺少必要的条目。"
        echo "   -> 请以 root 权限编辑 /etc/hosts 文件，并添加以下行："
        echo "      $expected_entry"
        exit 1
    fi
}

# --- 主逻辑执行前 ---
check_dependencies
check_hosts_file

# 检查脚本是否以 root/sudo 权限运行
if [[ $EUID -ne 0 ]]; then
   echo "错误：此脚本需要使用 sudo 权限运行。"
   echo "用法: sudo ./hs-connect.sh [start|stop|status]"
   exit 1
fi

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
    
    if ! ssh-add -l >/dev/null; then
        echo "❌ 错误：SSH Agent 中没有已加载的密钥。"
        echo "   -> 请先执行以下命令加载您的 SSH 密钥，然后再重新运行此脚本："
        echo "      eval \$(ssh-agent -s)"
        echo "      ssh-add $SSH_KEY_PATH"
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
    if tailscale ip -4 &>/dev/null; then
        local TS_IP=$(tailscale ip -4)
        echo "✅ Tailscale 节点: 在线 (IP: $TS_IP)"
        echo ""
        tailscale status
    else
        echo "❌ Tailscale 节点: 离线或未激活"
    fi
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
    *)
        echo "用法:"
        echo "  sudo ./hs-connect.sh [start|stop|status]"
        exit 1
        ;;
esac