#!/usr/bin/env bash
# ==============================================================================
# chainproxy - Linux 链式 WireGuard + WARP 代理与 Web 控制台一键安装脚本
# 支持系统: Debian 12/13, Ubuntu 22.04/24.04 (amd64)
# 支持全自动静默安装，可选环境变量: PANEL_PORT=54321 PANEL_USER=admin PANEL_PASS=admin
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

echo -e "${CYAN}"
echo "=================================================================="
echo "          chainproxy 链式 WireGuard + WARP 一键安装脚本           "
echo "       x-ui 风格 Web 控制台 | 零失联回程保护 | WARP 自动注册      "
echo "=================================================================="
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
    log_err "本脚本需要 root 权限执行，请使用 sudo 或 root 用户运行。"
    exit 1
fi

ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    log_err "目前仅支持 amd64 / x86_64 架构 Linux 系统，当前检测到: $ARCH"
    exit 1
fi

log_info "正在检测操作系统版本..."
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log_ok "检测到系统: ${PRETTY_NAME:-Linux}"
fi

# 1. 按需极速安装核心网络依赖 (若已齐备则跳过 apt-get update 节省时间)
MISSING_PKGS=()
command -v nft >/dev/null 2>&1       || MISSING_PKGS+=("nftables")
command -v ip >/dev/null 2>&1        || MISSING_PKGS+=("iproute2")
command -v conntrack >/dev/null 2>&1 || MISSING_PKGS+=("conntrack")
command -v curl >/dev/null 2>&1      || MISSING_PKGS+=("curl" "ca-certificates")
command -v jq >/dev/null 2>&1        || MISSING_PKGS+=("jq")
command -v tar >/dev/null 2>&1       || MISSING_PKGS+=("tar")

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    log_info "正在安装缺失依赖工具 (${MISSING_PKGS[*]})..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -q
    apt-get install -y -q --no-install-recommends nftables iproute2 conntrack curl jq ca-certificates tar
    log_ok "系统依赖安装完成"
else
    log_ok "核心网络依赖已齐备 (nftables, iproute2, conntrack, curl, jq, tar)"
fi

# 1.1 检查并初始化 /dev/net/tun 设备 (支持 Docker / LXC / Incus 等容器与标准 VPS 环境)
modprobe tun 2>/dev/null || true
mkdir -p /dev/net
if [[ ! -c /dev/net/tun ]]; then
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 666 /dev/net/tun 2>/dev/null || true
fi
if [[ -c /dev/net/tun ]]; then
    log_ok "TUN 设备已就绪: /dev/net/tun"
else
    log_warn "未能创建 /dev/net/tun。若运行在 Incus/LXC/Docker 容器中，请在宿主机映射 TUN 字符设备。"
fi

# 2. 检查或安装 sing-box 代理引擎
log_info "正在检测/安装 sing-box 代理引擎..."
NEED_SINGBOX=0
if command -v sing-box >/dev/null 2>&1; then
    CURRENT_SB_VER=$(sing-box version 2>/dev/null | head -n 1 || true)
    log_ok "检测到现有 sing-box: $CURRENT_SB_VER"
else
    NEED_SINGBOX=1
fi

if [[ $NEED_SINGBOX -eq 1 ]]; then
    log_info "正在自动安装官方 sing-box..."
    INSTALLED_SB=0

    # 方式 1: 官方安装脚本
    if curl -fsSL https://sing-box.app/install.sh 2>/dev/null | bash 2>/dev/null; then
        INSTALLED_SB=1
    fi

    # 方式 2: 官方 Debian/Ubuntu APT 仓库
    if [[ $INSTALLED_SB -eq 0 ]]; then
        log_info "尝试通过官方 APT 存储库安装 sing-box..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc 2>/dev/null || true
        chmod 644 /etc/apt/keyrings/sagernet.asc 2>/dev/null || true
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" > /etc/apt/sources.list.d/sagernet.list
        apt-get update -y -q 2>/dev/null || true
        if apt-get install -y -q sing-box 2>/dev/null; then
            INSTALLED_SB=1
        fi
    fi

    # 方式 3: 从 GitHub Releases 稳定版本直链获取
    if [[ $INSTALLED_SB -eq 0 ]]; then
        log_info "尝试从 GitHub 下载 sing-box 预编译二进制..."
        for try_ver in "1.14.2" "1.13.2" "1.12.12"; do
            SB_TAR="sing-box-${try_ver}-linux-amd64.tar.gz"
            SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${try_ver}/${SB_TAR}"
            TMP_DIR=$(mktemp -d)
            if curl -fsSL "$SB_URL" -o "${TMP_DIR}/${SB_TAR}" 2>/dev/null; then
                if tar -xzf "${TMP_DIR}/${SB_TAR}" -C "${TMP_DIR}" 2>/dev/null; then
                    install -m 755 "${TMP_DIR}/sing-box-${try_ver}-linux-amd64/sing-box" /usr/local/bin/sing-box
                    rm -rf "$TMP_DIR"
                    INSTALLED_SB=1
                    break
                fi
            fi
            rm -rf "$TMP_DIR"
        done
    fi
fi

REAL_SB=$(command -v sing-box 2>/dev/null || true)
if [[ -z "$REAL_SB" || ! -x "$REAL_SB" ]]; then
    log_err "未能找到可执行的 sing-box，请检查安装路径。"
    exit 1
fi
if ! "$REAL_SB" version >/dev/null 2>&1; then
    log_err "sing-box 已存在但无法执行: $REAL_SB"
    "$REAL_SB" version || true
    exit 1
fi
log_ok "sing-box 部署就绪: $("$REAL_SB" version | head -n 1)"

# 3. 安装 chainproxy 单二进制程序
log_info "正在部署 chainproxy 主程序..."
CHAINPROXY_BIN="/usr/local/bin/chainproxy"
install_chainproxy() {
    local staged="${CHAINPROXY_BIN}.new.$$"
    chmod 755 "$1" 2>/dev/null || true
    if ! install -m 755 "$1" "$staged" 2>/dev/null; then
        log_err "无法写入目标路径: $staged"
        return 1
    fi
    if ! "$staged" --version >/dev/null 2>&1; then
        rm -f "$staged"
        log_err "下载或编译的 chainproxy 无法执行，保留现有程序。"
        return 1
    fi
    if systemctl is-active --quiet chainproxy; then
        log_info "正在平滑更新 chainproxy 服务实例..."
        systemctl stop chainproxy || true
    fi
    mv -f "$staged" "$CHAINPROXY_BIN"
}

if [[ -f "./target/release/chainproxy" ]]; then
    install_chainproxy "./target/release/chainproxy"
    log_ok "已安装当前编译的二进制程序: $CHAINPROXY_BIN"
elif command -v cargo >/dev/null 2>&1 && [[ -f "./Cargo.toml" ]]; then
    log_info "正在通过本地 Rust 工具链编译 release 版本..."
    cargo build --release
    install_chainproxy "./target/release/chainproxy"
    log_ok "编译并安装完成: $CHAINPROXY_BIN"
else
    log_info "正在拉取最新预编译 chainproxy 静态二进制..."
    TMP_DIR=$(mktemp -d)
    DOWNLOADED=0
    for try_url in \
        "https://github.com/Grandova/WG-Chain-Warp/releases/latest/download/chainproxy-linux-amd64"; do
        if curl -fsSL "$try_url" -o "${TMP_DIR}/chainproxy" 2>/dev/null; then
            if install_chainproxy "${TMP_DIR}/chainproxy"; then
                log_ok "下载预编译静态二进制完成: $CHAINPROXY_BIN"
                DOWNLOADED=1
                break
            fi
        fi
    done

    if [[ $DOWNLOADED -eq 0 ]]; then
        if command -v git >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
            log_warn "拉取预编译程序失败，正在通过 git clone 源码并本地编译..."
            CLONE_DIR=$(mktemp -d)
            if git clone --depth=1 https://github.com/Grandova/WG-Chain-Warp.git "$CLONE_DIR"; then
                if (cd "$CLONE_DIR" && cargo build --release) && install_chainproxy "$CLONE_DIR/target/release/chainproxy"; then
                    log_ok "源码拉取并编译安装完成: $CHAINPROXY_BIN"
                    DOWNLOADED=1
                fi
            fi
            rm -rf "$CLONE_DIR"
        fi
    fi

    if [[ $DOWNLOADED -eq 0 ]]; then
        log_err "未能成功获取或编译 chainproxy。请检查网络后重试。"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    rm -rf "$TMP_DIR"
fi

if ! "$CHAINPROXY_BIN" --version >/dev/null 2>&1; then
    log_err "chainproxy 运行自检失败，无法在当前系统执行: $CHAINPROXY_BIN"
    "$CHAINPROXY_BIN" --version || true
    exit 1
fi
log_ok "主程序自检通过: $("$CHAINPROXY_BIN" --version 2>&1)"

ln -sf "$CHAINPROXY_BIN" /usr/bin/chainproxy

# 4. 创建安全运行数据目录 (权限 700) 并初始化 Web 面板配置
DATA_DIR="/var/lib/chainproxy"
mkdir -p "$DATA_DIR/versions"
chmod 700 "$DATA_DIR"

# 若环境变量指定了自定义面板参数则自动写入，否则保留现有配置或生成默认配置 (54321 / admin / admin)
SETTING_ARGS=()
[[ -n "${PANEL_USER:-}" ]] && SETTING_ARGS+=("--username" "$PANEL_USER")
[[ -n "${PANEL_PASS:-}" ]] && SETTING_ARGS+=("--password" "$PANEL_PASS")
[[ -n "${PANEL_PORT:-}" ]] && SETTING_ARGS+=("--port" "$PANEL_PORT")

if [[ ${#SETTING_ARGS[@]} -gt 0 ]]; then
    "$CHAINPROXY_BIN" --data-dir "$DATA_DIR" setting "${SETTING_ARGS[@]}" >/dev/null 2>&1 || true
    log_ok "已应用环境变量指定的 Web 面板配置"
else
    "$CHAINPROXY_BIN" --data-dir "$DATA_DIR" setting --show >/dev/null 2>&1 || true
fi

# 5. 配置并启动 systemd 后台服务
SERVICE_DST="/etc/systemd/system/chainproxy.service"
log_info "正在配置并启动 systemd 守护服务..."

cat > "$SERVICE_DST" << 'EOF'
[Unit]
Description=chainproxy - Linux Chained WireGuard VPN & Web Management Panel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/chainproxy
ExecStartPre=-/bin/sh -c 'test -e /dev/net/tun || (mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun 2>/dev/null || true)'
ExecStart=/usr/local/bin/chainproxy --api 127.0.0.1:8880 --data-dir /var/lib/chainproxy --singbox sing-box daemon
ExecStop=/usr/local/bin/chainproxy stop
Restart=always
RestartSec=3s
KillMode=mixed
TimeoutStopSec=15s
LimitNOFILE=1048576
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable chainproxy >/dev/null 2>&1 || true
systemctl restart chainproxy

# 快速轮询检测服务就绪 (每 0.25s 检测一次)
DAEMON_OK=0
for _ in {1..24}; do
    if curl -s "http://127.0.0.1:8880/api/v1/status" >/dev/null 2>&1; then
        DAEMON_OK=1
        break
    fi
    sleep 0.25
done

if [[ $DAEMON_OK -eq 1 ]]; then
    log_ok "chainproxy 后台守护进程与 Web 控制台已成功启动！"
else
    log_warn "后台守护服务未能正常响应，输出排查信息:"
    systemctl status chainproxy --no-pager || true
    journalctl -u chainproxy -n 20 --no-pager || true
fi

PANEL_PORT_VAL=$(jq -r '.port // 54321' "$DATA_DIR/panel.json" 2>/dev/null || echo "54321")
PANEL_USER_VAL=$(jq -r '.username // "admin"' "$DATA_DIR/panel.json" 2>/dev/null || echo "admin")
PANEL_PASS_VAL=$(jq -r '.password // "admin"' "$DATA_DIR/panel.json" 2>/dev/null || echo "admin")
PANEL_PATH_VAL=$(jq -r '.base_path // "/"' "$DATA_DIR/panel.json" 2>/dev/null || echo "/")
SERVER_IP=$(curl -s4m 3 https://api.ipify.org 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || echo "<服务器IP>")

echo ""
echo -e "${GREEN}==================================================================${NC}"
echo -e "${GREEN}          🎉 chainproxy Web 控制台一键安装完成！                  ${NC}"
echo -e "${GREEN}==================================================================${NC}"
echo -e " Web 面板地址  : ${CYAN}http://${SERVER_IP}:${PANEL_PORT_VAL}${PANEL_PATH_VAL}${NC}"
echo -e " 登录用户名    : ${CYAN}${PANEL_USER_VAL}${NC}"
echo -e " 登录密  码    : ${CYAN}${PANEL_PASS_VAL}${NC}"
echo -e "------------------------------------------------------------------"
echo -e " 终端服务管理  : ${CYAN}chainproxy${NC} (启停服务 / 修改面板端口与密码 / 查看日志)"
echo -e " 命令行修改面板: ${CYAN}chainproxy setting --port 54321 --username admin --password 新密码${NC}"
echo -e "${GREEN}==================================================================${NC}"
echo -e "${YELLOW} 提示: 请在浏览器打开上方 Web 面板地址可视化管理 WireGuard / WARP / SOCKS5 节点${NC}"
echo ""
