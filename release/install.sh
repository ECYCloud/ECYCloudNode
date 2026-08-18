#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}未检测到系统版本，请联系脚本作者！${plain}\n" && exit 1
fi

arch=$(arch)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64-v8a"
elif [[ $arch == "s390x" ]]; then
    arch="s390x"
else
    arch="64"
    echo -e "${red}检测架构失败，使用默认架构: ${arch}${plain}"
fi

echo "架构: ${arch}"

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
    exit 2
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}请使用 CentOS 7 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n" && exit 1
    fi
fi

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release -y
	    yum install wget curl unzip tar crontabs socat iptables -y
    else
        apt update -y
	    apt install wget curl unzip tar cron socat iptables -y
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/ECYCloudNode.service ]]; then
        return 2
    fi
    if systemctl is-active --quiet ECYCloudNode; then
        return 0
    else
        return 1
    fi
}

install_acme() {
    curl https://get.acme.sh | sh
}

install_ECYCloudNode() {
    if [[ -e /usr/local/ECYCloudNode/ ]]; then
        rm /usr/local/ECYCloudNode/ -rf
    fi

    mkdir /usr/local/ECYCloudNode/ -p
	cd /usr/local/ECYCloudNode/

    if  [ $# == 0 ] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/ECYCloud/ECYCloudNode/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}检测 ECYCloudNode 版本失败，可能是超出 Github API 限制，请稍后再试，或手动指定 ECYCloudNode 版本安装${plain}"
            exit 1
        fi
        echo -e "检测到 ECYCloudNode 最新版本：${last_version}，开始安装"
        wget -q -N -O /usr/local/ECYCloudNode/ECYCloudNode-linux.zip https://github.com/ECYCloud/ECYCloudNode/releases/download/${last_version}/ECYCloudNode-linux-${arch}.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 ECYCloudNode 失败，请确保你的服务器能够下载 Github 的文件${plain}"
            exit 1
        fi
    else
        if [[ $1 == v* ]]; then
            last_version=$1
	else
	    last_version="v"$1
	fi
        url="https://github.com/ECYCloud/ECYCloudNode/releases/download/${last_version}/ECYCloudNode-linux-${arch}.zip"
        echo -e "开始安装 ECYCloudNode ${last_version}"
        wget -q -N -O /usr/local/ECYCloudNode/ECYCloudNode-linux.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 ECYCloudNode ${last_version} 失败，请确保此版本存在${plain}"
            exit 1
        fi
    fi

    unzip ECYCloudNode-linux.zip
    rm ECYCloudNode-linux.zip -f
    chmod +x ECYCloudNode
    mkdir /etc/ECYCloudNode/ -p
    rm /etc/systemd/system/ECYCloudNode.service -f
    file="https://github.com/ECYCloud/ECYCloudNode/raw/main/release/ECYCloudNode.service"
    wget -q -N -O /etc/systemd/system/ECYCloudNode.service ${file}
    #cp -f ECYCloudNode.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl stop ECYCloudNode
    systemctl enable ECYCloudNode

    # 禁用 rsyslog 防止日志写满磁盘
    # rsyslog 会将 systemd journal 转写到 /var/log/syslog 导致无限增长
    # journald 自身有大小限制，禁用 rsyslog 后不会撑爆磁盘
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        systemctl stop rsyslog
        systemctl disable rsyslog
        echo -e "${green}已禁用 rsyslog 以防止日志写满磁盘${plain}"
    fi

    # 配置 journald 日志保留时间为 3 天（ECYCloudNode 日志全部进 journald）
    # 使用 drop-in 配置文件而非直接改 journald.conf，避免覆盖用户其他设置
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/ecycloudnode-retention.conf <<EOF
[Journal]
MaxRetentionSec=3day
EOF
    systemctl restart systemd-journald 2>/dev/null
    journalctl --vacuum-time=3d >/dev/null 2>&1
    echo -e "${green}已配置 journald 日志保留 3 天${plain}"

    echo -e "${green}ECYCloudNode ${last_version}${plain} 安装完成，已设置开机自启"
    cp geoip.dat /etc/ECYCloudNode/
    cp geosite.dat /etc/ECYCloudNode/

    if [[ ! -f /etc/ECYCloudNode/config.yml ]]; then
        cp config.yml /etc/ECYCloudNode/
        echo -e ""
        echo -e "全新安装，请先参看教程：https://github.com/ECYCloud/ECYCloudNode，配置必要的内容"
    else
        systemctl start ECYCloudNode
        sleep 3
        check_status
        local start_result=$?
        echo -e ""
        # 这里只在启动失败时给出警告，避免在上层脚本（如 ECYCloudNode update）
        # 再次根据实际状态给出成功/失败提示时出现相互矛盾的“重启成功”字样。
        if [[ ${start_result} != 0 ]]; then
            echo -e "${red}ECYCloudNode 可能启动失败，请稍后使用 ECYCloudNode log 查看日志信息，若无法启动，则可能更改了配置格式，请前往 wiki 查看：https://github.com/ECYCloud/ECYCloudNode/wiki${plain}"
        fi
    fi

    if [[ ! -f /etc/ECYCloudNode/dns.json ]]; then
        cp dns.json /etc/ECYCloudNode/
    fi
    if [[ ! -f /etc/ECYCloudNode/route.json ]]; then
        cp route.json /etc/ECYCloudNode/
    fi
    if [[ ! -f /etc/ECYCloudNode/custom_outbound.json ]]; then
        cp custom_outbound.json /etc/ECYCloudNode/
    fi
    if [[ ! -f /etc/ECYCloudNode/custom_inbound.json ]]; then
        cp custom_inbound.json /etc/ECYCloudNode/
    fi
    if [[ ! -f /etc/ECYCloudNode/rulelist ]]; then
        cp rulelist /etc/ECYCloudNode/
    fi
    curl -o /usr/bin/ECYCloudNode -Ls https://raw.githubusercontent.com/ECYCloud/ECYCloudNode/main/release/ECYCloudNode.sh
    chmod +x /usr/bin/ECYCloudNode
    ln -sfn /usr/bin/ECYCloudNode /usr/bin/ecycloudnode
    cd $cur_dir
    rm -f install.sh
    echo -e ""
    echo "ECYCloudNode 管理脚本使用方法 (亦可用 ecycloudnode): "
    echo "------------------------------------------"
    echo "ECYCloudNode                    - 显示管理菜单 (功能更多)"
    echo "ECYCloudNode start              - 启动 ECYCloudNode"
    echo "ECYCloudNode stop               - 停止 ECYCloudNode"
    echo "ECYCloudNode restart            - 重启 ECYCloudNode"
    echo "ECYCloudNode status             - 查看 ECYCloudNode 状态"
    echo "ECYCloudNode enable             - 设置 ECYCloudNode 开机自启"
    echo "ECYCloudNode disable            - 取消 ECYCloudNode 开机自启"
    echo "ECYCloudNode log                - 查看 ECYCloudNode 日志"
    echo "ECYCloudNode update             - 更新 ECYCloudNode"
    echo "ECYCloudNode update x.x.x       - 更新 ECYCloudNode 指定版本"
    echo "ECYCloudNode config             - 显示配置文件内容"
    echo "ECYCloudNode install            - 安装 ECYCloudNode"
    echo "ECYCloudNode uninstall          - 卸载 ECYCloudNode"
    echo "ECYCloudNode version            - 查看 ECYCloudNode 与各内核版本"
    echo "ECYCloudNode unlockcheck         - 节点解锁检测"
    echo "ECYCloudNode enable_firewall    - 开启防火墙"
    echo "ECYCloudNode disable_firewall   - 关闭防火墙"
    echo "ECYCloudNode enable_ipv6        - 开启 IPv6"
    echo "ECYCloudNode disable_ipv6       - 关闭 IPv6"
    echo "------------------------------------------"
}

echo -e "${green}开始安装${plain}"
install_base
# install_acme
install_ECYCloudNode $1
