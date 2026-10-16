#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用 root 用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue 2>/dev/null | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue 2>/dev/null | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue 2>/dev/null | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version 2>/dev/null | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version 2>/dev/null | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version 2>/dev/null | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    release="debian"
fi

arch=$(arch)
if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="amd64"
else
    echo -e "${red}当前仅支持 x86_64 / amd64 架构系统，检测到: ${arch}${plain}"
    exit 1
fi

echo "架构: ${arch}"

install_base() {
    local missing=()
    command -v wget >/dev/null 2>&1      || missing+=("wget")
    command -v curl >/dev/null 2>&1      || missing+=("curl" "ca-certificates")
    command -v tar >/dev/null 2>&1       || missing+=("tar")
    command -v nft >/dev/null 2>&1       || missing+=("nftables")
    command -v ip >/dev/null 2>&1        || missing+=("iproute2")
    command -v conntrack >/dev/null 2>&1 || missing+=("conntrack")
    command -v jq >/dev/null 2>&1        || missing+=("jq")

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${green}正在安装基础依赖 (${missing[*]})...${plain}"
        if [[ x"${release}" == x"centos" ]]; then
            yum install -y wget curl tar ca-certificates nftables iproute conntrack-tools jq
        else
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y -q
            apt-get install -y -q --no-install-recommends wget curl tar ca-certificates nftables iproute2 conntrack jq
        fi
    fi

    # 初始化 /dev/net/tun
    modprobe tun 2>/dev/null || true
    mkdir -p /dev/net
    if [[ ! -c /dev/net/tun ]]; then
        mknod /dev/net/tun c 10 200 2>/dev/null || true
        chmod 666 /dev/net/tun 2>/dev/null || true
    fi
}

cleanup_legacy() {
    # 自动停止并禁用占用大量内存的官方 cloudflare-warp (warp-svc) 守护进程（Sooya 已内置零内存开销的原生 Rust WARP 内核）
    if systemctl is-active --quiet warp-svc 2>/dev/null; then
        echo -e "${yellow}检测到官方 warp-svc 正在后台运行，正在停止并切换至 Sooya 内置极速 Rust WARP 内核以释放内存...${plain}"
        systemctl stop warp-svc 2>/dev/null || true
        systemctl disable warp-svc 2>/dev/null || true
    fi
    pkill -9 -f warp-svc 2>/dev/null || true

    # 清理旧版 chainproxy 残留并平滑迁移数据目录
    if systemctl is-active --quiet chainproxy 2>/dev/null; then
        systemctl stop chainproxy 2>/dev/null || true
    fi
    if [[ -f /etc/systemd/system/chainproxy.service ]]; then
        systemctl disable chainproxy 2>/dev/null || true
        rm -f /etc/systemd/system/chainproxy.service
    fi
    rm -f /usr/local/bin/chainproxy /usr/bin/chainproxy

    if [[ -d /var/lib/chainproxy && ! -d /var/lib/sooya ]]; then
        mv /var/lib/chainproxy /var/lib/sooya
    fi
    mkdir -p /var/lib/sooya
    chmod 700 /var/lib/sooya
}

config_after_install() {
    local setting_args=()
    [[ -n "${PANEL_USER:-}" ]] && setting_args+=("--username" "$PANEL_USER")
    [[ -n "${PANEL_PASS:-}" ]] && setting_args+=("--password" "$PANEL_PASS")
    [[ -n "${PANEL_PORT:-}" ]] && setting_args+=("--port" "$PANEL_PORT")

    if [[ ${#setting_args[@]} -gt 0 ]]; then
        /usr/local/sooya/sooya --data-dir /var/lib/sooya setting "${setting_args[@]}" >/dev/null 2>&1 || true
        return
    fi

    if [[ -t 0 ]]; then
        echo -e "${yellow}出于安全考虑，安装/更新完成后可自定义面板端口与账户密码${plain}"
        read -r -p "确认是否现在自定义设置?[y/n] (默认 n 使用 54321 与 admin): " config_confirm
        if [[ x"${config_confirm}" == x"y" || x"${config_confirm}" == x"Y" ]]; then
            read -r -p "请设置您的账户名: " config_account
            echo -e "${yellow}您的账户名将设定为:${config_account}${plain}"
            read -r -p "请设置您的账户密码: " config_password
            echo -e "${yellow}您的账户密码将设定为:${config_password}${plain}"
            read -r -p "请设置面板访问端口: " config_port
            echo -e "${yellow}您的面板访问端口将设定为:${config_port}${plain}"
            echo -e "${yellow}确认设定，设定中...${plain}"
            /usr/local/sooya/sooya --data-dir /var/lib/sooya setting \
                --username "${config_account:-admin}" \
                --password "${config_password:-admin}" \
                --port "${config_port:-54321}" >/dev/null 2>&1 || true
            echo -e "${green}账户密码及端口设定完成！${plain}"
        else
            /usr/local/sooya/sooya --data-dir /var/lib/sooya setting --show >/dev/null 2>&1 || true
            echo -e "${yellow}已保持默认/现有面板配置，可通过 sooya 命令随时修改。${plain}"
        fi
    else
        /usr/local/sooya/sooya --data-dir /var/lib/sooya setting --show >/dev/null 2>&1 || true
    fi
}

install_sooya() {
    systemctl stop sooya 2>/dev/null || true
    cleanup_legacy
    cd /usr/local/ || exit 1

    if [[ $# == 0 ]]; then
        last_version=$(curl -Ls -m 6 "https://api.github.com/repos/Grandova/WG-Chain-Warp/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -n "$last_version" ]]; then
            echo -e "检测到 Sooya 最新版本：${green}${last_version}${plain}，开始安装..."
            pkg_url="https://github.com/Grandova/WG-Chain-Warp/releases/download/${last_version}/sooya-linux-${arch}.tar.gz"
        else
            last_version="latest"
            echo -e "开始下载 Sooya 最新预编译版本..."
            pkg_url="https://github.com/Grandova/WG-Chain-Warp/releases/latest/download/sooya-linux-${arch}.tar.gz"
        fi
    else
        last_version=$1
        pkg_url="https://github.com/Grandova/WG-Chain-Warp/releases/download/${last_version}/sooya-linux-${arch}.tar.gz"
        echo -e "开始安装 Sooya ${green}${last_version}${plain}..."
    fi

    if ! wget -N --no-check-certificate -O "/usr/local/sooya-linux-${arch}.tar.gz" "${pkg_url}"; then
        echo -e "${red}下载 Sooya 预编译安装包失败，请确保您的服务器能够连接 GitHub 下载文件！${plain}"
        exit 1
    fi

    if [[ -e /usr/local/sooya/ ]]; then
        rm -rf /usr/local/sooya/
    fi

    tar -zxvf "sooya-linux-${arch}.tar.gz" >/dev/null
    rm -f "sooya-linux-${arch}.tar.gz"
    cd sooya || exit 1
    chmod +x sooya
    cp -f sooya.service /etc/systemd/system/sooya.service
    ln -sf /usr/local/sooya/sooya /usr/bin/sooya
    ln -sf /usr/local/sooya/sooya /usr/local/bin/sooya

    config_after_install

    systemctl daemon-reload
    systemctl enable sooya >/dev/null 2>&1 || true
    systemctl start sooya

    local panel_port panel_user panel_pass panel_path server_ip
    panel_port=$(jq -r '.port // 54321' /var/lib/sooya/panel.json 2>/dev/null || echo "54321")
    panel_user=$(jq -r '.username // "admin"' /var/lib/sooya/panel.json 2>/dev/null || echo "admin")
    panel_pass=$(jq -r '.password // "admin"' /var/lib/sooya/panel.json 2>/dev/null || echo "admin")
    panel_path=$(jq -r '.base_path // "/"' /var/lib/sooya/panel.json 2>/dev/null || echo "/")
    server_ip=$(curl -s4m 3 https://api.ipify.org 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || echo "<服务器IP>")

    echo -e ""
    echo -e "${green}Sooya ${last_version}${plain} 安装完成，面板已启动！"
    echo -e ""
    echo -e "Web 面板地址: ${cyan}http://${server_ip}:${panel_port}${panel_path}${plain}"
    echo -e "登录用户名  : ${cyan}${panel_user}${plain}"
    echo -e "登录密  码  : ${cyan}${panel_pass}${plain}"
    echo -e ""
    echo -e "Sooya 管理脚本使用方法: "
    echo -e "----------------------------------------------"
    echo -e "sooya              - 显示管理菜单 (功能更多)"
    echo -e "sooya start        - 启动 Sooya 面板"
    echo -e "sooya stop         - 停止 Sooya 面板与代理"
    echo -e "sooya restart      - 重启 Sooya 面板"
    echo -e "sooya status       - 查看 Sooya 状态"
    echo -e "sooya enable       - 设置 Sooya 开机自启"
    echo -e "sooya disable      - 取消 Sooya 开机自启"
    echo -e "sooya log          - 查看 Sooya 日志"
    echo -e "sooya update       - 更新 Sooya 面板"
    echo -e "sooya uninstall    - 卸载 Sooya 面板"
    echo -e "----------------------------------------------"
    cd "$cur_dir" || true
}

echo -e "${green}开始安装 Sooya${plain}"
install_base
install_sooya "$@"
