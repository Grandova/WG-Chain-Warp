#!/usr/bin/env bash
# ==============================================================================
# chainproxy - Linux 链式 WireGuard 代理与 WARP 出口一键安装部署脚本
# 支持系统: Debian 12/13, Ubuntu 22.04/24.04 (amd64)
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
echo "        自动双层嵌套 | conntrack 回程保护 | WARP 自动注册         "
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

# 1. 安装核心网络依赖
log_info "正在更新软件包源并安装依赖工具 (nftables, iproute2, curl, jq, tar)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -q
apt-get install -y -q nftables iproute2 curl jq ca-certificates tar

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
    log_info "正在通过官方脚本安装 sing-box..."
    if curl -fsSL https://sing-box.app/install.sh 2>/dev/null | bash 2>/dev/null; then
        INSTALLED_SB=1
    fi

    # 方式 2: 若官方脚本受网络影响，使用官方 Debian/Ubuntu APT 仓库
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
        for try_ver in "1.11.5" "1.11.4" "1.11.0"; do
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

# 确保软链接到系统常用路径 (/usr/local/bin 和 /usr/bin)
REAL_SB=$(command -v sing-box 2>/dev/null || true)
if [[ -z "$REAL_SB" && -x "/usr/local/bin/sing-box" ]]; then
    REAL_SB="/usr/local/bin/sing-box"
elif [[ -z "$REAL_SB" && -x "/usr/bin/sing-box" ]]; then
    REAL_SB="/usr/bin/sing-box"
fi

if [[ -n "$REAL_SB" ]]; then
    ln -sf "$REAL_SB" /usr/local/bin/sing-box 2>/dev/null || true
    ln -sf "$REAL_SB" /usr/bin/sing-box 2>/dev/null || true
    log_ok "sing-box 部署就绪: $("$REAL_SB" version 2>/dev/null | head -n 1 || echo "$REAL_SB")"
else
    log_err "未能自动安装 sing-box，请手动执行以下命令安装后重试:"
    log_err "  curl -fsSL https://sing-box.app/install.sh | sudo bash"
    exit 1
fi

# 3. 安装 chainproxy 单二进制程序
log_info "正在部署 chainproxy 主程序..."
CHAINPROXY_BIN="/usr/local/bin/chainproxy"

if [[ -f "./target/release/chainproxy" ]]; then
    install -m 755 "./target/release/chainproxy" "$CHAINPROXY_BIN"
    log_ok "已安装当前编译的二进制程序: $CHAINPROXY_BIN"
elif command -v cargo >/dev/null 2>&1; then
    log_info "正在通过本地 Rust 工具链编译 release 版本..."
    cargo build --release
    install -m 755 "./target/release/chainproxy" "$CHAINPROXY_BIN"
    log_ok "编译并安装完成: $CHAINPROXY_BIN"
else
    # 尝试从预编译 Release 获取
    log_info "尝试拉取预编译 chainproxy 二进制..."
    TMP_DIR=$(mktemp -d)
    if curl -sSL "https://github.com/Grandova/WG-Chain-Warp/releases/latest/download/chainproxy-linux-amd64" -o "${TMP_DIR}/chainproxy" 2>/dev/null; then
        install -m 755 "${TMP_DIR}/chainproxy" "$CHAINPROXY_BIN"
        log_ok "下载预编译二进制完成: $CHAINPROXY_BIN"
    else
        log_warn "未拉取到预编译包，请确保在仓库目录下运行编译，或自行构建。"
    fi
    rm -rf "$TMP_DIR"
fi

ln -sf "$CHAINPROXY_BIN" /usr/bin/chainproxy

# 4. 创建安全运行数据目录 (权限 700)
DATA_DIR="/var/lib/chainproxy"
mkdir -p "$DATA_DIR/versions"
chmod 700 "$DATA_DIR"
log_ok "运行数据目录就绪: $DATA_DIR"

# 5. 配置并启动 systemd 后台服务
SERVICE_DST="/etc/systemd/system/chainproxy.service"
log_info "正在配置 systemd 守护服务..."

cat > "$SERVICE_DST" << 'EOF'
[Unit]
Description=chainproxy - Linux Chained WireGuard VPN & Proxy Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/chainproxy
ExecStart=/usr/local/bin/chainproxy --api 127.0.0.1:8880 --data-dir /var/lib/chainproxy --singbox sing-box daemon
ExecStop=/usr/local/bin/chainproxy stop
Restart=on-failure
RestartSec=3s
KillMode=mixed
TimeoutStopSec=15s
LimitNOFILE=1048576

# 系统资源保障
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable chainproxy
systemctl restart chainproxy

# 检查服务运行状态
log_info "正在检测后台守护进程响应..."
DAEMON_OK=0
for i in {1..8}; do
    sleep 1
    if curl -s "http://127.0.0.1:8880/api/v1/status" >/dev/null 2>&1; then
        DAEMON_OK=1
        break
    fi
done

if [[ $DAEMON_OK -eq 1 ]]; then
    log_ok "chainproxy 后台守护进程已成功启动并就绪 (127.0.0.1:8880)！"
else
    log_warn "后台守护服务未能正常响应，输出排查信息:"
    systemctl status chainproxy --no-pager || true
    journalctl -u chainproxy -n 20 --no-pager || true
fi

echo ""
echo -e "${GREEN}==================================================================${NC}"
echo -e "${GREEN}             🎉 chainproxy 一键安装与配置就绪！                   ${NC}"
echo -e "${GREEN}==================================================================${NC}"
echo -e " 命令行管理入口: ${CYAN}chainproxy${NC} (直接在终端输入即可启动中文面板)"
echo -e " 自动注册 WARP : ${CYAN}chainproxy warp-reg${NC}"
echo -e " 守护进程管理  : ${CYAN}systemctl restart chainproxy${NC}"
echo -e " REST API 地址 : ${CYAN}http://127.0.0.1:8880${NC}"
echo -e "${GREEN}==================================================================${NC}"
echo ""

# 如果是交互式终端，直接打开中文管理菜单
if [ -t 0 ]; then
    read -r -p "是否现在立即打开交互式中文管理菜单？(Y/n): " OPEN_MENU || true
    OPEN_MENU=${OPEN_MENU:-Y}
    if [[ "$OPEN_MENU" =~ ^[Yy]$ ]]; then
        exec "$CHAINPROXY_BIN" menu
    fi
fi
