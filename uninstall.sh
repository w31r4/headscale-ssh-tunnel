#!/bin/bash

# 检查是否以 root 权限运行
if [ "$(id -u)" -ne 0 ]; then
  echo "此脚本需要以 sudo 或 root 权限运行。" >&2
  exit 1
fi

# 定义安装路径和配置文件路径
INSTALL_PATH="/usr/local/bin/msh"
# 如果使用 sudo, $HOME 可能是 /root, 所以我们尝试获取原始用户的家目录
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME=$HOME
fi
USER_CONFIG_DIR="$USER_HOME/.config/msh"
SYSTEM_CONFIG_DIR="/etc/msh"

# 移除主程序
if [ -f "$INSTALL_PATH" ]; then
  echo "正在移除 msh 主程序..."
  rm -f "$INSTALL_PATH"
  echo "msh 已从 $INSTALL_PATH 移除。"
else
  echo "msh 主程序未找到，可能已被卸载。"
fi

# 询问是否删除配置文件
read -p "是否要删除所有相关的配置文件？(y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "正在删除用户配置文件..."
  if [ -d "$USER_CONFIG_DIR" ]; then
    # 以原始用户身份删除，以处理权限问题
    if [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" rm -rf "$USER_CONFIG_DIR"
    else
        rm -rf "$USER_CONFIG_DIR"
    fi
    echo "用户配置文件目录 '$USER_CONFIG_DIR' 已删除。"
  else
    echo "用户配置文件目录未找到。"
  fi

  echo "正在删除系统配置文件..."
  if [ -d "$SYSTEM_CONFIG_DIR" ]; then
    rm -rf "$SYSTEM_CONFIG_DIR"
    echo "系统配置文件目录 '$SYSTEM_CONFIG_DIR' 已删除。"
  else
    echo "系统配置文件目录未找到。"
  fi
else
  echo "保留配置文件。"
fi

echo "msh 卸载完成。"

exit 0