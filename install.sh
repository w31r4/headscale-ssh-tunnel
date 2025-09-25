#!/bin/bash

# 检查是否以 root 权限运行
if [ "$(id -u)" -ne 0 ]; then
  echo "此脚本需要以 sudo 或 root 权限运行。" >&2
  exit 1
fi

# 定义源文件和目标路径
SOURCE_FILE="hs-connect.sh"
INSTALL_DIR="/usr/local/bin"
INSTALL_PATH="$INSTALL_DIR/hs-connect"

# 检查源文件是否存在
if [ ! -f "$SOURCE_FILE" ]; then
    echo "错误: 主脚本 '$SOURCE_FILE' 未找到。" >&2
    exit 1
fi

# 复制文件并设置权限
echo "正在安装 hs-connect..."
cp "$SOURCE_FILE" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# 检查是否成功安装
if [ -f "$INSTALL_PATH" ] && [ -x "$INSTALL_PATH" ]; then
  echo "hs-connect 已成功安装到 $INSTALL_PATH"
  echo "现在你可以在系统的任何地方使用 'hs-connect' 命令。"
  echo "例如，运行 'hs-connect status' 来检查状态。"
else
  echo "安装失败。请检查权限和路径是否正确。" >&2
  exit 1
fi

exit 0