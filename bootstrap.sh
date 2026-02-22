#!/bin/bash
########################################################################
# bootstrap.sh — Instalador do Addon WireGuard VPN para MK-AUTH
# Projeto : https://github.com/joseluisfreire/WireGuard-VPN-Addon
# Autor   : José Luis Freire
# Licença : MIT
########################################################################
set -euo pipefail

# ── Cores ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fatal() { echo -e "${RED}[ERRO]${NC}  $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╦ ╦┬┬─┐┌─┐╔═╗┬ ┬┌─┐┬─┐┌┬┐  ╦  ╦╔═╗╔╗╔"
echo "  ║║║│├┬┘├┤ ║ ╦│ │├─┤├┬┘ ││  ╚╗╔╝╠═╝║║║"
echo "  ╚╩╝┴┴└─└─┘╚═╝└─┘┴ ┴┴└──┴┘   ╚╝ ╩  ╝╚╝"
echo -e "${NC}"
echo -e "  ${BOLD}Addon para MK-AUTH${NC} — Instalador automático"
echo ""

# ── Verificações ──────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fatal "Execute como root: sudo bash bootstrap.sh"

MKAUTH_DIR="/opt/mk-auth/admin"
[[ ! -d "$MKAUTH_DIR/addons" ]] && fatal "MK-AUTH não encontrado em $MKAUTH_DIR/addons"

command -v curl > /dev/null 2>&1 || fatal "curl não encontrado. Instale: apt install curl"

# ── Constantes ────────────────────────────────────────────────────────
GITHUB_BASE="https://github.com/joseluisfreire"

# wireguard-tools-static
WG_TOOLS_REPO="wireguard-tools-static"
WG_TOOLS_TAG="v1.0.20250521"
WG_TOOLS_URL="${GITHUB_BASE}/${WG_TOOLS_REPO}/releases/download/${WG_TOOLS_TAG}"

# wg-mkauthd
WG_DAEMON_REPO="wg-mkauthd"
WG_DAEMON_TAG="v1.0.0"
WG_DAEMON_URL="${GITHUB_BASE}/${WG_DAEMON_REPO}/releases/download/${WG_DAEMON_TAG}"

# WireGuard-VPN-Addon (este repo)
ADDON_REPO="WireGuard-VPN-Addon"
ADDON_BRANCH="main"

WG_GROUP="wgmkauth"
WG_IFACE="wg0"
WG_CONF_DIR="/etc/wireguard"
SOCKET_PATH="/run/wgmkauth.sock"
DAEMON_BIN="/usr/local/sbin/wg-mkauthd"
WG_BIN="/usr/local/bin/wg"
WG_QUICK_BIN="/usr/local/bin/wg-quick"
LOG_FILE="/var/log/wg-mkauthd.log"
INITD_SCRIPT="/etc/init.d/wg-mkauthd"
ADDON_DIR="${MKAUTH_DIR}/addons/wireguard"
TMP_DIR=$(mktemp -d /tmp/wg-addon-XXXXXX)

trap "rm -rf $TMP_DIR" EXIT

# ══════════════════════════════════════════════════════════════════════
# 1. GRUPO wgmkauth + www-data
# ══════════════════════════════════════════════════════════════════════
info "Configurando grupo '${WG_GROUP}'..."

if getent group "$WG_GROUP" > /dev/null 2>&1; then
    ok "Grupo '${WG_GROUP}' já existe"
else
    groupadd "$WG_GROUP"
    ok "Grupo '${WG_GROUP}' criado"
fi

if id -nG www-data 2>/dev/null | grep -qw "$WG_GROUP"; then
    ok "www-data já pertence ao grupo '${WG_GROUP}'"
else
    usermod -aG "$WG_GROUP" www-data
    ok "www-data adicionado ao grupo '${WG_GROUP}'"
fi

# ══════════════════════════════════════════════════════════════════════
# 2. DIRETÓRIOS
# ══════════════════════════════════════════════════════════════════════
info "Criando diretórios..."

mkdir -p "$WG_CONF_DIR"
chmod 750 "$WG_CONF_DIR"
chown root:"$WG_GROUP" "$WG_CONF_DIR"
ok "$WG_CONF_DIR (750 root:${WG_GROUP})"

mkdir -p "$ADDON_DIR"
ok "$ADDON_DIR"

# ══════════════════════════════════════════════════════════════════════
# 3. MÓDULO KERNEL WIREGUARD
# ══════════════════════════════════════════════════════════════════════
info "Verificando módulo kernel wireguard..."

if lsmod | grep -q "^wireguard"; then
    ok "Módulo wireguard já carregado"
else
    modprobe wireguard 2>/dev/null || true
    if lsmod | grep -q "^wireguard"; then
        ok "Módulo wireguard carregado"
    else
        warn "Módulo wireguard NÃO disponível — verifique o kernel"
    fi
fi

# Persistir no boot
if [[ ! -f /etc/modules-load.d/wireguard.conf ]]; then
    mkdir -p /etc/modules-load.d
    echo "wireguard" > /etc/modules-load.d/wireguard.conf
    ok "wireguard persistido em /etc/modules-load.d/"
fi

# ══════════════════════════════════════════════════════════════════════
# 4. DOWNLOAD DOS BINÁRIOS
# ══════════════════════════════════════════════════════════════════════
info "Baixando binários estáticos..."

# ── wg ────────────────────────────────────────────────────────────────
info "  → wg (wireguard-tools-static ${WG_TOOLS_TAG})..."
curl -fsSL "${WG_TOOLS_URL}/wg" -o "${TMP_DIR}/wg" || fatal "Falha ao baixar wg"
install -m 0750 -o root -g "$WG_GROUP" "${TMP_DIR}/wg" "$WG_BIN"
ok "$WG_BIN (750 root:${WG_GROUP})"

# ── wg-quick ─────────────────────────────────────────────────────────
info "  → wg-quick (wireguard-tools-static ${WG_TOOLS_TAG})..."
curl -fsSL "${WG_TOOLS_URL}/wg-quick" -o "${TMP_DIR}/wg-quick" || fatal "Falha ao baixar wg-quick"
install -m 0750 -o root -g "$WG_GROUP" "${TMP_DIR}/wg-quick" "$WG_QUICK_BIN"
ok "$WG_QUICK_BIN (750 root:${WG_GROUP})"

# ── wg-mkauthd ───────────────────────────────────────────────────────
info "  → wg-mkauthd (${WG_DAEMON_TAG})..."
curl -fsSL "${WG_DAEMON_URL}/wg-mkauthd" -o "${TMP_DIR}/wg-mkauthd" || fatal "Falha ao baixar wg-mkauthd"
install -m 0750 -o root -g "$WG_GROUP" "${TMP_DIR}/wg-mkauthd" "$DAEMON_BIN"
ok "$DAEMON_BIN (750 root:${WG_GROUP})"

# ══════════════════════════════════════════════════════════════════════
# 5. DOWNLOAD DO ADDON (PHP/JS/CSS)
# ══════════════════════════════════════════════════════════════════════
info "Baixando addon WireGuard-VPN-Addon..."

ADDON_TARBALL="${GITHUB_BASE}/${ADDON_REPO}/archive/refs/heads/${ADDON_BRANCH}.tar.gz"
curl -fsSL "$ADDON_TARBALL" -o "${TMP_DIR}/addon.tar.gz" || fatal "Falha ao baixar addon"
tar -xzf "${TMP_DIR}/addon.tar.gz" -C "$TMP_DIR"

ADDON_SRC="${TMP_DIR}/${ADDON_REPO}-${ADDON_BRANCH}"
[[ ! -d "$ADDON_SRC" ]] && fatal "Estrutura do addon não encontrada após extração"
ok "Addon baixado e extraído"

# ── addon_wireguard.js na raiz dos addons ────────────────────────────
if [[ -f "${ADDON_SRC}/addon_wireguard.js" ]]; then
    cp -f "${ADDON_SRC}/addon_wireguard.js" "${MKAUTH_DIR}/addons/addon_wireguard.js"
    chown www-data:www-data "${MKAUTH_DIR}/addons/addon_wireguard.js"
    chmod 644 "${MKAUTH_DIR}/addons/addon_wireguard.js"
    ok "addon_wireguard.js → ${MKAUTH_DIR}/addons/"
fi

# ── Arquivos do diretório wireguard/ ─────────────────────────────────
if [[ -d "${ADDON_SRC}/wireguard" ]]; then
    cp -rf "${ADDON_SRC}/wireguard/"* "$ADDON_DIR/"
    chown -R www-data:www-data "$ADDON_DIR"
    find "$ADDON_DIR" -type f -exec chmod 644 {} \;
    chmod 755 "$ADDON_DIR"
    ok "wireguard/* → ${ADDON_DIR}/"
else
    warn "Diretório wireguard/ não encontrado no repo"
fi

# ══════════════════════════════════════════════════════════════════════
# 6. LOG + LOGROTATE
# ══════════════════════════════════════════════════════════════════════
info "Configurando log..."

touch "$LOG_FILE"
chown root:"$WG_GROUP" "$LOG_FILE"
chmod 0660 "$LOG_FILE"
ok "$LOG_FILE (660 root:${WG_GROUP})"

cat > /etc/logrotate.d/wg-mkauthd <<LOGROTATE
${LOG_FILE} {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0660 root ${WG_GROUP}
    postrotate
        ${INITD_SCRIPT} restart > /dev/null 2>&1 || true
    endscript
}
LOGROTATE
ok "Logrotate configurado"

# ══════════════════════════════════════════════════════════════════════
# 7. SCRIPT INIT.D (SYSVINIT)
# ══════════════════════════════════════════════════════════════════════
info "Instalando script init.d..."

cat > "$INITD_SCRIPT" <<'INITD'
#!/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
### BEGIN INIT INFO
# Provides:          wg-mkauthd
# Required-Start:    $remote_fs $network
# Required-Stop:     $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: WG-MKAuth unix socket daemon
### END INIT INFO

DAEMON=/usr/local/sbin/wg-mkauthd
NAME=wg-mkauthd
PIDFILE=/var/run/${NAME}.pid
DAEMON_OPTS="--auto-bring-up --auto-bring-down"

case "$1" in
  start)
    echo "Starting $NAME..."
    start-stop-daemon --start --quiet --background \
      --make-pidfile --pidfile "$PIDFILE" \
      --exec "$DAEMON" -- $DAEMON_OPTS
    ;;
  stop)
    echo "Stopping $NAME..."
    start-stop-daemon --stop --quiet --oknodo \
      --pidfile "$PIDFILE"
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "$NAME is running (pid $(cat "$PIDFILE"))"
      exit 0
    else
      echo "$NAME is not running"
      exit 3
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit 0
INITD

chmod 755 "$INITD_SCRIPT"
update-rc.d wg-mkauthd defaults
ok "init.d instalado + update-rc.d defaults"

# ══════════════════════════════════════════════════════════════════════
# 8. INICIAR DAEMON
# ══════════════════════════════════════════════════════════════════════
info "Iniciando wg-mkauthd..."

"$INITD_SCRIPT" stop  > /dev/null 2>&1 || true
sleep 1
"$INITD_SCRIPT" start > /dev/null 2>&1 || warn "Falha ao iniciar — verifique wg0.conf"

sleep 2

if [[ -S "$SOCKET_PATH" ]]; then
    SOCK_PERMS=$(stat -c "%A %U:%G" "$SOCKET_PATH" 2>/dev/null)
    ok "Socket ativo: ${SOCKET_PATH} (${SOCK_PERMS})"
else
    warn "Socket não encontrado — o daemon precisa de ${WG_CONF_DIR}/${WG_IFACE}.conf para operar"
fi

# ══════════════════════════════════════════════════════════════════════
# 9. VERIFICAÇÃO FINAL
# ══════════════════════════════════════════════════════════════════════
info "Verificação final..."

ERRORS=0

# Grupo
getent group "$WG_GROUP" > /dev/null 2>&1 && ok "Grupo ${WG_GROUP}" || { warn "Grupo ${WG_GROUP} ausente"; ERRORS=$((ERRORS+1)); }

# www-data no grupo
id -nG www-data 2>/dev/null | grep -qw "$WG_GROUP" && ok "www-data ∈ ${WG_GROUP}" || { warn "www-data fora do grupo"; ERRORS=$((ERRORS+1)); }

# Binários
[[ -x "$WG_BIN" ]]      && ok "$WG_BIN"      || { warn "$WG_BIN ausente";      ERRORS=$((ERRORS+1)); }
[[ -x "$WG_QUICK_BIN" ]] && ok "$WG_QUICK_BIN" || { warn "$WG_QUICK_BIN ausente"; ERRORS=$((ERRORS+1)); }
[[ -x "$DAEMON_BIN" ]]   && ok "$DAEMON_BIN"   || { warn "$DAEMON_BIN ausente";   ERRORS=$((ERRORS+1)); }

# Addon
[[ -f "${ADDON_DIR}/index.php" ]] && ok "Addon PHP instalado" || { warn "Addon PHP ausente"; ERRORS=$((ERRORS+1)); }

# Init.d
[[ -x "$INITD_SCRIPT" ]] && ok "init.d executável" || { warn "init.d ausente"; ERRORS=$((ERRORS+1)); }

# ══════════════════════════════════════════════════════════════════════
# RESUMO
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}  ✅  Addon WireGuard VPN para MK-AUTH — Instalado!         ${NC}"
else
    echo -e "${YELLOW}  ⚠️   Instalado com ${ERRORS} aviso(s) — verifique acima     ${NC}"
fi
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Componentes:${NC}"
echo -e "    Grupo:     ${CYAN}${WG_GROUP}${NC} (www-data é membro)"
echo -e "    Daemon:    ${CYAN}${DAEMON_BIN}${NC}"
echo -e "    Socket:    ${CYAN}${SOCKET_PATH}${NC} (0660 root:${WG_GROUP})"
echo -e "    wg:        ${CYAN}${WG_BIN}${NC}"
echo -e "    wg-quick:  ${CYAN}${WG_QUICK_BIN}${NC}"
echo -e "    Config:    ${CYAN}${WG_CONF_DIR}/${WG_IFACE}.conf${NC}"
echo -e "    Log:       ${CYAN}${LOG_FILE}${NC}"
echo -e "    Addon:     ${CYAN}${ADDON_DIR}/${NC}"
echo -e "    Init.d:    ${CYAN}${INITD_SCRIPT}${NC}"
echo ""
echo -e "  ${BOLD}Comandos úteis:${NC}"
echo -e "    ${YELLOW}/etc/init.d/wg-mkauthd start|stop|restart|status${NC}"
echo -e "    ${YELLOW}tail -f ${LOG_FILE}${NC}"
echo -e "    ${YELLOW}stat ${SOCKET_PATH}${NC}"
echo -e "    ${YELLOW}groups www-data${NC}"
echo ""
echo -e "  ${BOLD}Versões:${NC}"
echo -e "    wireguard-tools:  ${CYAN}${WG_TOOLS_TAG}${NC}"
echo -e "    wg-mkauthd:       ${CYAN}${WG_DAEMON_TAG}${NC}"
echo ""
