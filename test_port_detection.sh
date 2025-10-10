#!/bin/bash

# =================================================================
#        MSH 端口检测功能测试脚本
# =================================================================
#
# 测试新的端口检测和激活功能
#
# =================================================================

echo "=== MSH 端口检测功能测试 ==="
echo ""

# 测试端口检测功能
echo "1. 测试端口自动检测功能..."
echo "   运行: detect_windows_tunnel_port"
detected_port=$(./msh.sh status 2>/dev/null | grep "检测到Windows SSH隧道在端口" | awk '{print $NF}')
if [[ -n "$detected_port" ]]; then
    echo "   ✅ 检测到端口: $detected_port"
else
    echo "   ❌ 未检测到端口"
fi
echo ""

# 测试帮助信息
echo "2. 测试帮助信息是否包含新功能..."
if ./msh.sh help | grep -q "智能端口检测版"; then
    echo "   ✅ 帮助信息已更新"
else
    echo "   ❌ 帮助信息未更新"
fi
echo ""

# 测试activate命令的端口参数
echo "3. 测试activate命令的端口参数支持..."
if ./msh.sh help | grep -q "activate.*--port"; then
    echo "   ✅ activate命令支持--port参数"
else
    echo "   ❌ activate命令不支持--port参数"
fi
echo ""

# 测试错误处理
echo "4. 测试错误处理改进..."
if ./msh.sh activate --port 99999 2>&1 | grep -q "无法连接"; then
    echo "   ✅ 错误处理已改进"
else
    echo "   ❌ 错误处理需要改进"
fi
echo ""

# 显示当前状态
echo "5. 当前系统状态:"
echo "   运行: msh status"
./msh.sh status 2>/dev/null || echo "   需要运行完整的msh命令来测试"
echo ""

echo "=== 测试完成 ==="
echo ""
echo "使用建议:"
echo "  1. 在Windows上:  .\\msh.ps1 start  [--port 10443]"
echo "  2. 在WSL中:      msh activate    [--port 10443]"
echo "  3. 查看状态:     msh status"
echo ""
echo "故障排查:"
echo "  - 如果自动检测失败，手动指定端口: msh activate --port 10443"
echo "  - 检查Windows隧道状态: .\\msh.ps1 status"
echo "  - 查看SSH监听端口: netstat -tlnp | grep ssh"