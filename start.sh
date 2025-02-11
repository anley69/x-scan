#!/bin/bash

echo "=== X-Scan 启动脚本 ==="

# 检查 Python 环境
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到 Python3，请先安装 Python3"
    exit 1
fi

# 检查 pip
if ! command -v pip3 &> /dev/null; then
    echo "错误: 未找到 pip3，请先安装 pip3"
    exit 1
fi

# 检查 GeoLite2 数据库文件
if [ ! -f "GeoLite2-Country.mmdb" ]; then
    echo "警告: 未找到 GeoLite2-Country.mmdb 文件"
    echo "请下载 GeoLite2-Country.mmdb 文件并放置在当前目录"
    read -p "是否继续运行？(y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 创建虚拟环境（如果不存在）
if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python3 -m venv venv
fi

# 激活虚拟环境
echo "激活虚拟环境..."
source venv/bin/activate

# 安装依赖
echo "安装依赖..."
pip install -r requirements.txt

# 运行主程序
echo "启动 X-Scan..."
python tool.py

# 退出虚拟环境
deactivate

echo "程序已退出"

