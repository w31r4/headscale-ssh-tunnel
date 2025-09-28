#!/bin/bash

# =================================================================
#        Headscale SSH 隧道连接与激活脚本 (v3.1 - WSL 协作版)
# =================================================================
#
#   用法:
#   sudo ./hs-connect.sh start      - 启动隧道并自动激活节点
#   sudo ./hs-connect.sh stop       - 关闭隧道
#   sudo ./hs-connect.sh activate   - 仅激活节点 (用于共享已存在的隧道)
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
USER_CONFIG_DIR="$REAL_HOME/.config/msh"
USER_CONFIG_FILE="$USER_CONFIG_DIR/config.sh"
SYSTEM_CONFIG_FILE="/etc/msh/config.sh"
PID_FILE="/var/run/msh.pid"

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
    read -p "请输入用于 SSH 隧道的本地端口 (TUNNEL_PORT) [默认: 443]: " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-443}

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
# msh (Matryoshka-SHell) 连接配置

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

# SSH 隧道本地端口
TUNNEL_PORT="$TUNNEL_PORT"
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
    for cmd in tailscale nc ssh ssh-add lsof; do
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
# For 'start' command, we need all checks. For 'activate', we don't check hosts file as tunnel is assumed.
if [[ "$1" == "start" ]]; then
    check_dependencies
    check_hosts_file
fi


# --- 业务逻辑函数 ---

get_auth_key() {
    local expiration=${1:-"8h"} # 默认有效期为 8 小时
    echo "--- 第1步: 远程获取临时预授权密钥 (有效期: $expiration) ---"
    local key
    key=$(ssh -i "$SSH_KEY_PATH" -t "$SSH_USER@$SERVER_IP" \
      -o PasswordAuthentication=no -o BatchMode=yes \
      "sudo headscale preauthkeys create --user $USER --ephemeral --expiration $expiration" | tail -n 1)
    
    key=$(echo "$key" | tr -d '\r')

    if [[ ! "$key" =~ ^[a-f0-9]{48}$ ]]; then
        echo "   -> 错误：未能从服务器获取有效的预授权密钥。"
        echo "   -> 获取到的原始输出: '$key'"
        echo "   -> 请检查远程服务器上的 Headscale 服务是否正常，以及 SSH 免密登录是否配置正确。"
        return 1
    fi
    echo "   -> 成功获取到密钥: ${key:0:12}..."
    AUTH_KEY=$key # 将密钥赋值给全局变量
    return 0
}

start_tunnel() {
    local port=${1:-$TUNNEL_PORT} # 优先使用参数，否则使用配置
    port=${port:-443}

    echo ""
    echo "--- 第2步: 启动 SSH 隧道 (端口: $port) ---"
    
    echo "   -> 正在后台启动 SSH 隧道..."
    # 使用 -f 将 ssh 转入后台，-N 不执行远程命令，-o ExitOnForwardFailure=yes 如果端口无法监听则失败
    local output
    output=$(ssh -L "$port:localhost:443" -i "$SSH_KEY_PATH" -fN \
      -o ExitOnForwardFailure=yes -o PasswordAuthentication=no -o BatchMode=yes \
      "$SSH_USER@$SERVER_IP" 2>&1)
    
    # ssh -f 会自行 fork 到后台，它的父进程会立即退出，所以 $! 在这里不可靠。
    # 我们需要通过端口再次找到 PID。
    local SSH_PID
    # 使用更健壮的方式查找 PID
    for pid in $(lsof -t -i TCP:"$port" -s TCP:LISTEN); do
        if [ -f "/proc/$pid/comm" ] && grep -q "ssh" "/proc/$pid/comm"; then
            SSH_PID=$pid
            break
        fi
    done

    if [ -z "$SSH_PID" ]; then
        echo "   -> 错误：无法启动 SSH 隧道。SSH 进程未找到。"
        if [ -n "$output" ]; then
            echo "   -> SSH 错误信息: $output"
        fi
        echo "   -> 请检查端口 $port 是否被占用，或检查 SSH 连接配置。"
        return 1
    fi

    # 将 PID 和端口号都写入 PID 文件，方便停止
    echo "$SSH_PID:$port" > "$PID_FILE"
    echo "   -> SSH 隧道已启动，进程 PID: $SSH_PID"

    echo "   -> 正在验证隧道端口($port)是否可用..."
    for i in {1..5}; do
        if nc -z 127.0.0.1 "$port" &>/dev/null; then
            echo "   -> 隧道端口已准备就绪。"
            return 0
        fi
        sleep 1
    done

    echo "   -> 错误：SSH 隧道已启动 (PID: $SSH_PID)，但在5秒内无法连接到端口 $port。"
    echo "   -> 这可能是一个临时问题或配置错误。请检查防火墙或 SSH 服务器日志。"
    # 清理失败的隧道
    kill "$SSH_PID"
    rm -f "$PID_FILE"
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
    local tunnel_port="$TUNNEL_PORT"
    local expiration="8h"

    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)
                tunnel_port="$2"
                shift 2
                ;;
            --expiration)
                expiration="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    echo "--- 准备工作: 清理旧的连接和进程 ---"
    tailscale down >/dev/null 2>&1
    stop_tunnel # 确保端口和进程是干净的
    
    # 检查 SSH Agent
    check_ssh_agent

    if ! get_auth_key "$expiration"; then
        exit 1
    fi

    if ! start_tunnel "$tunnel_port"; then
        stop_tunnel
        exit 1
    fi

    if ! activate_node; then
        stop_tunnel
        exit 1
    fi
}

# 只激活，不创建隧道
activate_only() {
    local expiration="8h"
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expiration)
                expiration="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    check_ssh_agent

    if ! get_auth_key "$expiration"; then
        exit 1
    fi

    if ! activate_node; then
        exit 1
    fi
}

# 使用给定的密钥直接激活
link_node() {
    local key="$1"
    local tunnel_port="$TUNNEL_PORT"
    shift # 移除 key

    # 解析 --port 参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)
                tunnel_port="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [[ -z "$key" ]]; then
        echo "❌ 错误: 'link' 命令需要一个预授权密钥作为参数。"
        echo "   -> 用法: $0 link <your-pre-auth-key> [--port <端口>]"
        exit 1
    fi

    if [[ ! "$key" =~ ^[a-f0-9]{48}$ ]]; then
        echo "❌ 错误: 提供的密钥格式无效。"
        exit 1
    fi

    # 检查隧道状态，如果不存在则启动
    if ! is_tunnel_running; then
        echo "   -> 未检测到活动的 SSH 隧道，正在尝试启动一个..."
        if ! start_tunnel "$tunnel_port"; then
            stop_tunnel
            exit 1
        fi
    else
        echo "   -> 检测到已存在的 SSH 隧道，将直接使用。"
    fi

    AUTH_KEY=$key
    activate_node
}

check_ssh_agent() {
    # 在 sudo 环境下，必须以原始用户身份执行此检查。
    if [[ -n "$SUDO_USER" ]]; then
        if ! sudo -u "$SUDO_USER" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" ssh-add -l >/dev/null 2>&1; then
            echo "❌ 错误：在 sudo 环境下，用户 '$SUDO_USER' 的 SSH Agent 中没有已加载的密钥。"
            echo "   -> 请在运行此脚本前，确保您已在普通用户 shell 中执行 'ssh-add' 加载了正确的密钥。"
            echo "   -> 例如: ssh-add ~/.ssh/id_rsa"
            exit 1
        fi
    else
        # 在非 sudo 环境中 (理论上不应发生，因为脚本会自动提权)
        if ! ssh-add -l >/dev/null 2>&1; then
            echo "❌ 错误：SSH Agent 中没有已加载的密钥。"
            echo "   -> 请执行 'ssh-add' 加载密钥后重试。"
            exit 1
        fi
    fi
}

# 关闭隧道
stop_tunnel() {
    echo "--- 正在关闭 SSH 隧道 ---"
    local tunnel_killed=false

    # 1. 尝试通过 PID 文件关闭
    if [ -f "$PID_FILE" ]; then
        local pid_info
        pid_info=$(cat "$PID_FILE")
        local SSH_PID=${pid_info%:*}
        
        if [ -n "$SSH_PID" ] && ps -p "$SSH_PID" > /dev/null; then
            kill "$SSH_PID"
            echo "   -> 隧道进程 (PID: $SSH_PID) 已通过 PID 文件关闭。"
            tunnel_killed=true
        else
            echo "   -> PID 文件中的进程 ($SSH_PID) 无效或已不存在。"
        fi
        rm -f "$PID_FILE"
    else
        echo "   -> 未找到 PID 文件，将尝试通过端口查找。"
    fi

    # 2. 强制检查并关闭任何残留的 SSH 隧道进程
    # 使用 lsof 查找所有监听端口的 ssh 进程
    local zombie_pids
    zombie_pids=$(lsof -i -P -n | grep LISTEN | grep ssh | awk '{print $2}')
    
    if [ -n "$zombie_pids" ]; then
        for pid in $zombie_pids; do
            # 确保我们不会意外杀死其他用户的 ssh 进程
            if ps -p "$pid" > /dev/null; then
                echo "   -> 发现残留的 SSH 隧道进程 (PID: $pid)，正在强制关闭..."
                kill -9 "$pid"
                sleep 1
                if ! ps -p "$pid" > /dev/null; then
                    echo "   -> 残留进程 (PID: $pid) 已被强制关闭。"
                    tunnel_killed=true
                else
                    echo "   -> 警告：无法关闭残留的隧道进程 (PID: $pid)。"
                fi
            fi
        done
    fi

    if [ "$tunnel_killed" = false ]; then
        echo "   -> 未找到正在运行的隧道进程。"
    fi
    
    # 确保 PID 文件最终被删除
    rm -f "$PID_FILE"
    echo "✅ 清理完成！"
}

# 设置 trap，捕获退出信号并执行清理
trap 'stop_tunnel' SIGINT SIGTERM

# 检查状态
check_status() {
    echo "--- 检查连接状态 ---"
    
    # 1. 检查 SSH 隧道
    if ! is_tunnel_running "verbose"; then
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

is_tunnel_running() {
    local verbose=$1
    # 1. 尝试通过 PID 文件检查
    if [ -f "$PID_FILE" ]; then
        local pid_info
        pid_info=$(cat "$PID_FILE")
        local SSH_PID=${pid_info%:*}
        local port=${pid_info#*:}
        
        if [ -n "$SSH_PID" ] && ps -p "$SSH_PID" > /dev/null; then
            if [[ "$verbose" == "verbose" ]]; then
                echo "✅ SSH 隧道: 正在运行 (PID: $SSH_PID, 端口: $port) [通过PID文件检测]"
            fi
            return 0 # 0 表示 true (成功)
        fi
    fi

    # 2. 如果 PID 文件无效或不存在，则通过端口检测
    local listening_ssh_pid
    listening_ssh_pid=$(lsof -i -P -n | grep LISTEN | grep ssh | awk '{print $2}' | head -n 1)
    if [ -n "$listening_ssh_pid" ]; then
        if [[ "$verbose" == "verbose" ]]; then
            local port
            port=$(lsof -i -P -n -p "$listening_ssh_pid" | grep LISTEN | awk '{print $9}' | cut -d: -f2)
            echo "✅ SSH 隧道: 正在运行 (PID: $listening_ssh_pid, 端口: $port) [通过端口检测]"
        fi
        return 0
    fi

    return 1 # 1 表示 false (失败)
}

# 显示帮助信息
show_help() {
    echo "msh (Matryoshka-SHell): Headscale SSH 隧道连接工具 (v4.0)"
    echo ""
    echo "一个通过 SSH 隧道安全连接到 Headscale 的命令行工具。"
    echo ""
    echo "用法:"
    echo "  msh <command> [options]"
    echo ""
    echo "可用命令:"
    echo "  start               启动 SSH 隧道并激活 Headscale 节点"
    echo "    --port <端口>     临时指定 SSH 隧道的本地端口 (覆盖配置)"
    echo "    --expiration <时长> 临时指定预授权密钥的有效期 (例如: 12h, 30d)"
    echo ""
    echo "  stop                关闭 SSH 隧道并清理进程"
    echo "  status              检查隧道和节点的当前连接状态"
    echo ""
    echo "  activate            仅获取密钥并激活节点 (用于共享已存在的隧道)"
    echo "    --expiration <时长> 临时指定预授权密钥的有效期"
    echo ""
    echo "  link <密钥>         使用已有的密钥激活节点 (如果隧道不存在会自动启动)"
    echo "    --port <端口>     在自动启动隧道时指定端口"
    echo "  help                显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  hs-connect start"
    echo "  hs-connect start --port 10443 --expiration 30d"
    echo "  hs-connect link <your-pre-auth-key>"
    echo ""
    echo "该工具会自动使用 sudo 获取所需权限。首次运行时将引导您完成配置。"
}

# 根据用户输入的参数执行操作
main() {
    local command="$1"
    shift # 移除命令，剩下的都是参数

    case "$command" in
        start)
            start_and_activate "$@"
            ;;
        stop)
            stop_tunnel
            ;;
        status)
            check_status
            ;;
        activate)
            activate_only "$@"
            ;;
        link)
            link_node "$@"
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
}

main "$@"