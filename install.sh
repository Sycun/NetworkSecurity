#!/bin/bash

# 自动检测操作系统并安装依赖
OS="$(uname -s)"

case $OS in
    Linux)
        # Debian/Ubuntu
        if [ -f /etc/debian_version ]; then
            sudo apt update
            sudo apt install -y python3-pip libpcap-dev
        # RedHat/CentOS
        elif [ -f /etc/redhat-release ]; then
            sudo yum install -y python3-pip libpcap-devel
        fi
        ;;
    Darwin)
        # 检测Homebrew安装
        if ! command -v brew &> /dev/null; then
            echo "请先安装Homebrew: https://brew.sh/"
            exit 1
        fi
        brew install libpcap
        ;;
    *)
        echo "不支持的OS: $OS"
        exit 1
        ;;
esac

# 安装Python依赖
pip3 install -r requirements.txt