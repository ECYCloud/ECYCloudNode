#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

version="v1.0.0"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误: ${plain} 必须使用root用户运行此脚本！\n" && exit 1

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

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [默认$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "是否重启ECYCloudNode" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}按回车返回主菜单: ${plain}" && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/ECYCloud/ECYCloudNode/main/release/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    if [[ $# == 0 ]]; then
        echo && echo -n -e "输入指定版本(默认最新版): " && read version
    else
        version=$2
    fi
#    confirm "本功能会强制重装当前最新版，数据不会丢失，是否继续?" "n"
#    if [[ $? != 0 ]]; then
#        echo -e "${red}已取消${plain}"
#        if [[ $1 != 0 ]]; then
#            before_show_menu
#        fi
#        return 0
#    fi
		bash <(curl -Ls https://raw.githubusercontent.com/ECYCloud/ECYCloudNode/main/release/install.sh) $version
		if [[ $? == 0 ]]; then
			# 安装脚本执行成功后，根据实际重启结果只给出“成功/失败”两种提示，避免误导维护人员
			sleep 3
			check_status
			if [[ $? == 0 ]]; then
				echo -e "${green}更新完成，重启 ECYCloudNode 成功，请使用 ECYCloudNode log 查看运行日志。${plain}"
			else
				echo -e "${red}更新完成，重启 ECYCloudNode 失败，请使用 ECYCloudNode log 查看运行日志。${plain}"
			fi
			# 无论通过菜单还是命令行调用，完成后都直接退出脚本，保持与原有行为一致
			exit
		fi

    # 安装脚本执行失败时，仅在菜单模式下返回主菜单；命令行模式直接结束并保留错误输出
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

config() {
    echo "ECYCloudNode在修改配置后会自动尝试重启"
    vi /etc/ECYCloudNode/config.yml
    sleep 2
    check_status
    case $? in
        0)
            echo -e "ECYCloudNode状态: ${green}已运行${plain}"
            ;;
        1)
            echo -e "检测到您未启动ECYCloudNode或ECYCloudNode自动重启失败，是否查看日志？[Y/n]" && echo
            read -e -p "(默认: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "ECYCloudNode状态: ${red}未安装${plain}"
    esac
}

uninstall() {
    confirm "确定要卸载 ECYCloudNode 吗?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    systemctl stop ECYCloudNode
    systemctl disable ECYCloudNode
    rm -f /etc/systemd/system/ECYCloudNode.service
    systemctl daemon-reload
    systemctl reset-failed
    rm -rf /etc/ECYCloudNode /usr/local/ECYCloudNode

    echo ""
    echo -e "卸载成功，如果你想删除此脚本，则退出脚本后运行 ${green}rm /usr/bin/ECYCloudNode /usr/bin/ecycloudnode -f${plain} 进行删除"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "${green}ECYCloudNode已运行，无需再次启动，如需重启请选择重启${plain}"
    else
        systemctl start ECYCloudNode
        sleep 3
        check_status
        if [[ $? == 0 ]]; then
            echo -e "${green}ECYCloudNode 启动成功，请使用 ECYCloudNode log 查看运行日志${plain}"
        else
            echo -e "${red}ECYCloudNode可能启动失败，请稍后使用 ECYCloudNode log 查看日志信息${plain}"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    systemctl stop ECYCloudNode
    sleep 3
    check_status
    if [[ $? == 1 ]]; then
        echo -e "${green}ECYCloudNode 停止成功${plain}"
    else
        echo -e "${red}ECYCloudNode停止失败，可能是因为停止时间超过了两秒，请稍后查看日志信息${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    systemctl restart ECYCloudNode
    sleep 3
    check_status
    if [[ $? == 0 ]]; then
        echo -e "${green}ECYCloudNode 重启成功，请使用 ECYCloudNode log 查看运行日志${plain}"
    else
        echo -e "${red}ECYCloudNode可能启动失败，请稍后使用 ECYCloudNode log 查看日志信息${plain}"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    systemctl status ECYCloudNode --no-pager -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    systemctl enable ECYCloudNode
    if [[ $? == 0 ]]; then
        echo -e "${green}ECYCloudNode 设置开机自启成功${plain}"
    else
        echo -e "${red}ECYCloudNode 设置开机自启失败${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    systemctl disable ECYCloudNode
    if [[ $? == 0 ]]; then
        echo -e "${green}ECYCloudNode 取消开机自启成功${plain}"
    else
        echo -e "${red}ECYCloudNode 取消开机自启失败${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    journalctl -u ECYCloudNode.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

install_bbr() {
    # 检查并安装 wget 依赖
    if ! command -v wget &> /dev/null; then
        echo -e "${yellow}检测到系统未安装 wget，正在自动安装...${plain}"
        if [[ x"${release}" == x"centos" ]]; then
            yum install wget -y
        elif [[ x"${release}" == x"ubuntu" || x"${release}" == x"debian" ]]; then
            apt update -y && apt install wget -y
        elif [[ -f /etc/alpine-release ]]; then
            apk add wget
        elif [[ -f /etc/arch-release ]]; then
            pacman -S --noconfirm wget
        elif [[ -f /etc/fedora-release ]]; then
            dnf install wget -y
        elif [[ -f /etc/SuSE-release ]] || [[ -f /etc/opensuse-release ]]; then
            zypper install -y wget
        else
            echo -e "${red}未知系统，请手动安装 wget 后重试${plain}"
            return 1
        fi
        if ! command -v wget &> /dev/null; then
            echo -e "${red}wget 安装失败，请手动安装后重试${plain}"
            return 1
        fi
        echo -e "${green}wget 安装成功${plain}"
    fi

    # 询问是否更新系统
    echo ""
    echo -e "${yellow}======================================${plain}"
    echo -e "${green}推荐在安装 BBR 前更新系统${plain}"
    echo -e "${yellow}更新系统可以确保安装最新的内核和依赖包${plain}"
    echo -e "${yellow}======================================${plain}"
    echo ""
    read -p "是否更新系统？(推荐) [Y/n]: " update_confirm
    if [[ x"${update_confirm}" == x"" || x"${update_confirm}" == x"y" || x"${update_confirm}" == x"Y" ]]; then
        echo -e "${green}正在更新系统...${plain}"
        if [[ x"${release}" == x"centos" ]]; then
            if command -v dnf &> /dev/null; then
                # CentOS 8+ / RHEL 8+ 使用 dnf
                dnf upgrade -y --refresh
            else
                # CentOS 7 / RHEL 7 使用 yum
                yum update -y
            fi
        elif [[ x"${release}" == x"ubuntu" || x"${release}" == x"debian" ]]; then
            # Debian/Ubuntu 完整升级
            apt update -y && apt full-upgrade -y
        elif [[ -f /etc/alpine-release ]]; then
            # Alpine 完整升级（--available 确保升级所有可用包）
            apk update && apk upgrade --available
        elif [[ -f /etc/arch-release ]]; then
            # Arch Linux 完整系统升级
            pacman -Syu --noconfirm
        elif [[ -f /etc/fedora-release ]]; then
            # Fedora 完整升级
            dnf upgrade -y --refresh
        elif [[ -f /etc/SuSE-release ]] || [[ -f /etc/opensuse-release ]]; then
            # openSUSE 完整升级（使用 update 而非 dup，更稳妥）
            zypper refresh && zypper update -y
        elif [[ -f /etc/gentoo-release ]]; then
            # Gentoo 完整升级
            emerge --sync && emerge -uDN @world
        elif command -v apt-get &> /dev/null; then
            # 其他基于 apt 的系统
            apt-get update -y && apt-get dist-upgrade -y
        elif command -v yum &> /dev/null; then
            # 其他基于 yum 的系统
            yum update -y
        elif command -v dnf &> /dev/null; then
            # 其他基于 dnf 的系统
            dnf upgrade -y --refresh
        elif command -v pacman &> /dev/null; then
            # 其他基于 pacman 的系统
            pacman -Syu --noconfirm
        elif command -v apk &> /dev/null; then
            # 其他基于 apk 的系统
            apk update && apk upgrade --available
        elif command -v zypper &> /dev/null; then
            # 其他基于 zypper 的系统
            zypper refresh && zypper update -y
        else
            echo -e "${yellow}未知系统类型，跳过系统更新${plain}"
        fi
        echo -e "${green}系统更新完成${plain}"
    else
        echo -e "${yellow}已跳过系统更新${plain}"
    fi

    echo ""
    echo -e "${green}开始安装 BBR...${plain}"
    # 使用 teddysun 的 BBR 脚本
    wget -N --no-check-certificate https://raw.githubusercontent.com/teddysun/across/master/bbr.sh && chmod +x bbr.sh && bash bbr.sh
    local bbr_status=$?
    rm -f bbr.sh 2>/dev/null

    if [[ $bbr_status == 0 ]]; then
        echo ""
        echo -e "${green}BBR 脚本执行完成${plain}"
    else
        echo ""
        echo -e "${red}BBR 安装脚本执行失败，请检查网络连接或手动运行脚本${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

update_shell() {
    wget -O /usr/bin/ECYCloudNode -N --no-check-certificate https://raw.githubusercontent.com/ECYCloud/ECYCloudNode/main/release/ECYCloudNode.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "${red}下载脚本失败，请检查本机能否连接 Github${plain}"
        before_show_menu
    else
        chmod +x /usr/bin/ECYCloudNode
        ln -sfn /usr/bin/ECYCloudNode /usr/bin/ecycloudnode
        echo -e "${green}升级脚本成功，请重新运行脚本${plain}" && exit 0
    fi
}

enable_firewall() {
    echo -e "${green}正在开启防火墙...${plain}"
    echo ""

    local has_firewall=false

    # ufw (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 ufw，正在开启...${plain}"
        ufw --force enable
        if [[ $? == 0 ]]; then
            echo -e "${green}ufw 已开启${plain}"
        else
            echo -e "${red}ufw 开启失败${plain}"
        fi
    fi

    # firewalld (CentOS/RHEL/Fedora)
    if command -v firewall-cmd &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 firewalld，正在开启...${plain}"
        systemctl start firewalld
        systemctl enable firewalld
        if [[ $? == 0 ]]; then
            echo -e "${green}firewalld 已开启并设置开机自启${plain}"
        else
            echo -e "${red}firewalld 开启失败${plain}"
        fi
    fi

    # iptables
    if command -v iptables &> /dev/null; then
        has_firewall=true
        local restored=false
        # 尝试从常见位置恢复已保存的规则
        if [[ -f /etc/iptables/rules.v4 ]]; then
            echo -e "${yellow}检测到 iptables，正在从 /etc/iptables/rules.v4 恢复规则...${plain}"
            iptables-restore < /etc/iptables/rules.v4
            restored=true
        elif [[ -f /etc/sysconfig/iptables ]]; then
            echo -e "${yellow}检测到 iptables，正在从 /etc/sysconfig/iptables 恢复规则...${plain}"
            iptables-restore < /etc/sysconfig/iptables
            restored=true
        fi

        if [[ "${restored}" == true ]]; then
            echo -e "${green}iptables 规则已恢复${plain}"
        else
            echo -e "${yellow}未找到 iptables 已保存的规则文件，跳过恢复${plain}"
        fi

        # ip6tables
        if command -v ip6tables &> /dev/null; then
            local restored6=false
            if [[ -f /etc/iptables/rules.v6 ]]; then
                ip6tables-restore < /etc/iptables/rules.v6
                restored6=true
            elif [[ -f /etc/sysconfig/ip6tables ]]; then
                ip6tables-restore < /etc/sysconfig/ip6tables
                restored6=true
            fi

            if [[ "${restored6}" == true ]]; then
                echo -e "${green}ip6tables 规则已恢复${plain}"
            else
                echo -e "${yellow}未找到 ip6tables 已保存的规则文件，跳过恢复${plain}"
            fi
        fi
    fi

    # nftables
    if command -v nft &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 nftables，正在开启...${plain}"
        systemctl start nftables
        systemctl enable nftables
        if [[ $? == 0 ]]; then
            echo -e "${green}nftables 已开启并设置开机自启${plain}"
        else
            echo -e "${red}nftables 开启失败${plain}"
        fi
    fi

    if [[ "${has_firewall}" == false ]]; then
        echo -e "${yellow}未检测到已知的防火墙服务${plain}"
    else
        echo ""
        echo -e "${green}防火墙开启完成${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable_firewall() {
    echo -e "${green}正在关闭防火墙...${plain}"
    echo ""

    local has_firewall=false

    # ufw (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 ufw，正在关闭...${plain}"
        ufw disable
        if [[ $? == 0 ]]; then
            echo -e "${green}ufw 已关闭${plain}"
        else
            echo -e "${red}ufw 关闭失败${plain}"
        fi
    fi

    # firewalld (CentOS/RHEL/Fedora)
    if command -v firewall-cmd &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 firewalld，正在关闭...${plain}"
        systemctl stop firewalld
        systemctl disable firewalld
        if [[ $? == 0 ]]; then
            echo -e "${green}firewalld 已关闭并禁用开机自启${plain}"
        else
            echo -e "${red}firewalld 关闭失败${plain}"
        fi
    fi

    # iptables
    if command -v iptables &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 iptables，正在清空规则...${plain}"
        iptables -F
        iptables -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        echo -e "${green}iptables 规则已清空${plain}"

        # ip6tables
        if command -v ip6tables &> /dev/null; then
            ip6tables -F
            ip6tables -X
            ip6tables -P INPUT ACCEPT
            ip6tables -P FORWARD ACCEPT
            ip6tables -P OUTPUT ACCEPT
            echo -e "${green}ip6tables 规则已清空${plain}"
        fi
    fi

    # nftables
    if command -v nft &> /dev/null; then
        has_firewall=true
        echo -e "${yellow}检测到 nftables，正在清空规则...${plain}"
        nft flush ruleset
        if systemctl is-active --quiet nftables; then
            systemctl stop nftables
            systemctl disable nftables
        fi
        echo -e "${green}nftables 规则已清空${plain}"
    fi

    if [[ "${has_firewall}" == false ]]; then
        echo -e "${yellow}未检测到已知的防火墙服务${plain}"
    else
        echo ""
        echo -e "${green}防火墙关闭完成${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable_ipv6() {
    echo -e "${green}正在开启 IPv6...${plain}"
    echo ""

    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sysctl -w net.ipv6.conf.default.disable_ipv6=0
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0

    # 移除持久化配置
    if [[ -f /etc/sysctl.d/99-disable-ipv6.conf ]]; then
        rm -f /etc/sysctl.d/99-disable-ipv6.conf
        echo -e "${green}已移除 /etc/sysctl.d/99-disable-ipv6.conf${plain}"
    fi

    # 清理 sysctl.conf 中的相关配置
    if grep -q "net.ipv6.conf.*disable_ipv6" /etc/sysctl.conf 2>/dev/null; then
        sed -i '/net.ipv6.conf.*disable_ipv6/d' /etc/sysctl.conf
        echo -e "${green}已清理 /etc/sysctl.conf 中的 IPv6 禁用配置${plain}"
    fi

    sysctl -p &> /dev/null

    echo ""
    echo -e "${green}IPv6 已开启${plain}"

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable_ipv6() {
    echo -e "${green}正在关闭 IPv6...${plain}"
    echo ""

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1

    # 写入持久化配置
    cat > /etc/sysctl.d/99-disable-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

    sysctl -p &> /dev/null

    echo ""
    echo -e "${green}IPv6 已关闭，重启后仍然生效${plain}"

    if [[ $# == 0 ]]; then
        before_show_menu
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

check_enabled() {
    temp=$(systemctl is-enabled ECYCloudNode)
    if [[ x"${temp}" == x"enabled" ]]; then
        return 0
    else
        return 1;
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${red}ECYCloudNode已安装，请不要重复安装${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${red}请先安装ECYCloudNode${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
        0)
            echo -e "ECYCloudNode状态: ${green}已运行${plain}"
            show_enable_status
            ;;
        1)
            echo -e "ECYCloudNode状态: ${yellow}未运行${plain}"
            show_enable_status
            ;;
        2)
            echo -e "ECYCloudNode状态: ${red}未安装${plain}"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "是否开机自启: ${green}是${plain}"
    else
        echo -e "是否开机自启: ${red}否${plain}"
    fi
}

show_ECYCloudNode_version() {
    echo -e "${green}ECYCloudNode 与各内核版本：${plain}"
    /usr/local/ECYCloudNode/ECYCloudNode version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_kernel_version() {
    echo -e "${green}各内核版本：${plain}"
    /usr/local/ECYCloudNode/ECYCloudNode kernels
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

run_unlockcheck() {
    echo -e "${green}正在执行节点解锁检测...${plain}"
    echo ""
    /usr/local/ECYCloudNode/ECYCloudNode unlockcheck
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_usage() {
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
    echo "ECYCloudNode kernels            - 查看各内核版本"
    echo "ECYCloudNode unlockcheck         - 节点解锁检测"
    echo "ECYCloudNode enable_firewall    - 开启防火墙"
    echo "ECYCloudNode disable_firewall   - 关闭防火墙"
    echo "ECYCloudNode enable_ipv6        - 开启 IPv6"
    echo "ECYCloudNode disable_ipv6       - 关闭 IPv6"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
  ${green}ECYCloudNode 后端管理脚本${plain}
--- https://github.com/ECYCloud/ECYCloudNode ---
  ${green}0.${plain} 修改配置
————————————————
  ${green}1.${plain} 安装 ECYCloudNode
  ${green}2.${plain} 更新 ECYCloudNode
  ${green}3.${plain} 卸载 ECYCloudNode
————————————————
  ${green}4.${plain} 启动 ECYCloudNode
  ${green}5.${plain} 停止 ECYCloudNode
  ${green}6.${plain} 重启 ECYCloudNode
  ${green}7.${plain} 查看 ECYCloudNode 状态
  ${green}8.${plain} 查看 ECYCloudNode 日志
————————————————
  ${green}9.${plain} 设置 ECYCloudNode 开机自启
 ${green}10.${plain} 取消 ECYCloudNode 开机自启
————————————————
 ${green}11.${plain} 一键安装 bbr (最新内核)
 ${green}12.${plain} 查看 ECYCloudNode 与各内核版本
 ${green}13.${plain} 升级维护脚本
 ${green}14.${plain} 节点解锁检测
————————————————
 ${green}15.${plain} 开启防火墙
 ${green}16.${plain} 关闭防火墙
 ${green}17.${plain} 开启 IPv6
 ${green}18.${plain} 关闭 IPv6
 ${green}19.${plain} 查看各内核版本
 "
 #后续更新可加入上方字符串中
    show_status
    echo && read -p "请输入选择 [0-19]: " num

    case "${num}" in
        0) config
        ;;
        1) check_uninstall && install
        ;;
        2) check_install && update
        ;;
        3) check_install && uninstall
        ;;
        4) check_install && start
        ;;
        5) check_install && stop
        ;;
        6) check_install && restart
        ;;
        7) check_install && status
        ;;
        8) check_install && show_log
        ;;
        9) check_install && enable
        ;;
        10) check_install && disable
        ;;
        11) install_bbr
        ;;
        12) check_install && show_ECYCloudNode_version
        ;;
        13) update_shell
        ;;
        14) check_install && run_unlockcheck
        ;;
        15) enable_firewall
        ;;
        16) disable_firewall
        ;;
        17) enable_ipv6
        ;;
        18) disable_ipv6
        ;;
        19) check_install && show_kernel_version
        ;;
        *) echo -e "${red}请输入正确的数字 [0-19]${plain}"
        ;;
    esac
}


if [[ $# > 0 ]]; then
    case $1 in
        "start") check_install 0 && start 0
        ;;
        "stop") check_install 0 && stop 0
        ;;
        "restart") check_install 0 && restart 0
        ;;
        "status") check_install 0 && status 0
        ;;
        "enable") check_install 0 && enable 0
        ;;
        "disable") check_install 0 && disable 0
        ;;
        "log") check_install 0 && show_log 0
        ;;
        "update") check_install 0 && update 0 $2
        ;;
        "config") config $*
        ;;
        "install") check_uninstall 0 && install 0
        ;;
        "uninstall") check_install 0 && uninstall 0
        ;;
        "version") check_install 0 && show_ECYCloudNode_version 0
        ;;
        "kernels") check_install 0 && show_kernel_version 0
        ;;
        "update_shell") update_shell
        ;;
        "unlockcheck") check_install 0 && run_unlockcheck 0
        ;;
        "enable_firewall") enable_firewall 0
        ;;
        "disable_firewall") disable_firewall 0
        ;;
        "enable_ipv6") enable_ipv6 0
        ;;
        "disable_ipv6") disable_ipv6 0
        ;;
        *) show_usage
    esac
else
    show_menu
fi
