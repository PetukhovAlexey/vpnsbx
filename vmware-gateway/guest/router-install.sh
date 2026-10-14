#!/bin/bash
# router-install.sh — превращает свежую Ubuntu Server в роутер vmgw.
#   sudo bash router-install.sh [путь/к/lab.conf]
# Повторный запуск безопасен: хосты, профили и пробросы сохраняются.
# REBUILD=1 — пересобрать AmneziaWG. Обновить уже установленный роутер: update.sh router.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${1:-$HERE/lab.conf}"
KIT="$HERE/vmgw"
. "$HERE/lib.sh"

[ "$(id -u)" = 0 ] || die "запустите через sudo: sudo bash $0"
. /etc/os-release
[ "${ID:-}" = ubuntu ] || die "нужна Ubuntu Server (найдено: ${PRETTY_NAME:-?})"
[ -f "$CONF" ] || die "нет $CONF (его создаёт Setup.cmd на Windows рядом с этим скриптом)"
[ -f "$KIT/vmgw.py" ] || die "нет $KIT/vmgw.py: запускайте скрипт из папки комплекта"

read_labconf "$CONF"

MAC_RE='^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
iface_by_mac() {
    local d m
    for d in /sys/class/net/*; do
        m="$(cat "$d/address" 2>/dev/null)" || continue
        [ "$m" = "$1" ] && { basename "$d"; return 0; }
    done
    return 1
}
first_cidr() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4; exit}'; }

declare -A DEV
for role in MGMT LAN WAN; do
    mac="$(get ${role}_MAC | tr 'A-F-' 'a-f:')"
    [[ "$mac" =~ $MAC_RE ]] || die "lab.conf: неверный ${role}_MAC"
    L[${role}_MAC]="$mac"
    DEV[$role]="$(iface_by_mac "$mac")" || die "нет сетевой карты с MAC $mac (${role}); проверьте настройки ВМ"
done
say "Сетевые карты: управление ${DEV[MGMT]} → mgmt0, LAN ${DEV[LAN]} → lan0, WAN ${DEV[WAN]} → wan0"

MGMT_NET="$(get MGMT_NET)"
if [ -z "$MGMT_NET" ]; then
    MGMT_NET="$(first_cidr "${DEV[MGMT]}")"
    [ -n "$MGMT_NET" ] || die "не удалось определить сеть управления: укажите MGMT_NET в lab.conf"
fi
WAN_CIDR="$(first_cidr "${DEV[WAN]}")"
[ -n "$WAN_CIDR" ] || echo "ВНИМАНИЕ: у WAN (${DEV[WAN]}) сейчас нет адреса — LOCAL_NETS=auto не сработает"

# ---------------------------------------------------------------- резервная копия
BACKUP="/root/vmgw-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a /etc/netplan "$BACKUP/" 2>/dev/null || true
for f in /etc/nftables.conf /etc/sysctl.d/60-vmgw.conf /etc/dnsmasq.d/vmgw.conf; do
    [ -f "$f" ] && cp -a "$f" "$BACKUP/"
done

# ---------------------------------------------------------------- пакеты
say "Установка пакетов"
# shellcheck disable=SC2086
apt_install $ROUTER_PKGS

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    echo "ufw включён — выключаю: правилами управляет vmgw"
    ufw disable
fi

# ---------------------------------------------------------------- AmneziaWG
build_awg

# ---------------------------------------------------------------- vmgw
say "Установка vmgw"
install_router_files "$KIT"

SSH_PORT="$(get SSH_PORT 22)"
PANEL_PORT="$(get PANEL_PORT 8088)"
LAN_NET="$(get LAN_NET 192.168.150.0/24)"

# config.json и параметры для dnsmasq/netplan считает Python (проверка сетей).
OUT="$(VMGW_MGMT_NET="$MGMT_NET" VMGW_MGMT_ADDR="$(get MGMT_ADDR)" VMGW_LAN_NET="$LAN_NET" \
    VMGW_WAN_CIDR="$WAN_CIDR" VMGW_LOCAL_NETS="$(get LOCAL_NETS auto)" VMGW_ADMIN_NETS="$(get ADMIN_NETS)" \
    VMGW_SSH_PORT="$SSH_PORT" VMGW_PANEL_PORT="$PANEL_PORT" python3 -I - /etc/vmgw/config.json <<'PY'
import ipaddress, json, os, sys
E = os.environ

def die(m):
    print('ОШИБКА: ' + m, file=sys.stderr)
    sys.exit(1)

def net(s, what):
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        die('%s: неверная сеть %r' % (what, s))

def nets(s, what):
    return [net(x, what) for x in s.split(',') if x.strip()]

def port(s, what):
    if not s.isdigit() or not 1 <= int(s) <= 65535:
        die(what + ': неверный порт')
    return int(s)

mgmt = net(E['VMGW_MGMT_NET'], 'MGMT_NET')
lan = net(E['VMGW_LAN_NET'], 'LAN_NET')
for n, what in ((mgmt, 'MGMT_NET'), (lan, 'LAN_NET')):
    if n.version != 4 or n.prefixlen > 24 or n.prefixlen < 16:
        die(what + ': нужна IPv4-сеть с маской от /16 до /24')
if lan.overlaps(mgmt):
    die('LAN_NET пересекается с сетью управления')
try:
    ma = ipaddress.ip_address(E.get('VMGW_MGMT_ADDR') or str(mgmt[10]))
except ValueError:
    die('MGMT_ADDR: неверный адрес')
block = sorted({str(mgmt[2]) + '/32', str(mgmt[-2]) + '/32'})   # NAT-шлюз и DHCP VMware
if ma not in mgmt or ma in (mgmt[0], mgmt[1], mgmt[2], mgmt[-2], mgmt[-1]):
    die('MGMT_ADDR должен быть свободным адресом сети управления (не .0/.1/.2/.254/.255)')
wnet = None
if E.get('VMGW_WAN_CIDR'):
    wnet = ipaddress.ip_interface(E['VMGW_WAN_CIDR']).network
    if wnet.overlaps(lan) or wnet.overlaps(mgmt):
        die('сеть WAN %s пересекается с LAN или сетью управления: смените LAN_NET' % wnet)
ln = E.get('VMGW_LOCAL_NETS', 'auto').strip()
if ln == 'auto':
    local = [wnet] if wnet is not None and wnet.is_private else []
elif ln in ('', 'none'):
    local = []
else:
    local = nets(ln, 'LOCAL_NETS')
for n in local:
    if n.overlaps(lan) or n.overlaps(mgmt):
        die('LOCAL_NETS %s пересекается с LAN или сетью управления' % n)
admin = nets(E.get('VMGW_ADMIN_NETS', ''), 'ADMIN_NETS')
ssh, panel = port(E['VMGW_SSH_PORT'], 'SSH_PORT'), port(E['VMGW_PANEL_PORT'], 'PANEL_PORT')
if ssh == panel:
    die('SSH_PORT и PANEL_PORT совпадают')
try:
    hosts = json.load(open('/etc/vmgw/hosts.json'))
except FileNotFoundError:
    hosts = []
for h in hosts:
    if ipaddress.ip_address(h['ip']) not in lan:
        die('хост %s (%s) не попадает в новую LAN_NET; удалите его или верните прежнюю сеть' % (h['name'], h['ip']))
cfg = {'lan_if': 'lan0', 'wan_if': 'wan0', 'mgmt_if': 'mgmt0', 'lan_net': str(lan), 'mgmt_net': str(mgmt),
       'mgmt_addr': '%s/%d' % (ma, mgmt.prefixlen), 'mgmt_block': block, 'local_nets': [str(n) for n in local],
       'admin_nets': [str(n) for n in admin], 'ssh_port': ssh, 'panel_port': panel}
tmp = sys.argv[1] + '.tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=1)
    f.write('\n')
os.replace(tmp, sys.argv[1])
print('MGMT_CIDR=%s/%d' % (ma, mgmt.prefixlen))
print('MGMT_IP=%s' % ma)
print('LAN_CIDR=%s/%d' % (lan[1], lan.prefixlen))
print('LAN_GW=%s' % lan[1])
print('LAN_MASK=%s' % lan.netmask)
print('POOL_START=%s' % lan[200])
print('POOL_END=%s' % lan[250])
print('LOCAL=%s' % (','.join(cfg['local_nets']) or 'нет'))
PY
)" || die "проверка параметров lab.conf не прошла"
declare -A V
while IFS='=' read -r k v; do V[$k]="$v"; done <<< "$OUT"
chown root:vmgw-web /etc/vmgw/config.json
chmod 0640 /etc/vmgw/config.json
echo "Управление ${V[MGMT_CIDR]}, LAN ${V[LAN_CIDR]}, локальные сети: ${V[LOCAL]}"

# ---------------------------------------------------------------- сеть
say "Сеть: netplan"
for f in /etc/netplan/*.yaml; do
    [ -e "$f" ] && [ "$f" != /etc/netplan/60-vmgw.yaml ] && rm -f "$f"
done
if [ -d /etc/cloud/cloud.cfg.d ]; then
    echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-vmgw-disable-network-config.cfg
fi
cat > /etc/netplan/60-vmgw.yaml <<EOF
# vmgw: имена интерфейсов по MAC (меняются после перезагрузки).
network:
  version: 2
  renderer: networkd
  ethernets:
    mgmt0:
      match: {macaddress: "${L[MGMT_MAC]}"}
      set-name: mgmt0
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
      addresses: [${V[MGMT_CIDR]}]
    lan0:
      match: {macaddress: "${L[LAN_MAC]}"}
      set-name: lan0
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
      addresses: [${V[LAN_CIDR]}]
    wan0:
      match: {macaddress: "${L[WAN_MAC]}"}
      set-name: wan0
      dhcp4: true
      dhcp6: false
      accept-ra: false
      link-local: []
EOF
chmod 600 /etc/netplan/60-vmgw.yaml
netplan generate

# ---------------------------------------------------------------- dnsmasq (только DHCP)
write_dnsmasq "$LAN_NET" || true

# ---------------------------------------------------------------- ssh
say "SSH на порту $SSH_PORT"
mkdir -p /etc/ssh/sshd_config.d
echo "Port $SSH_PORT" > /etc/ssh/sshd_config.d/60-vmgw.conf
if ! grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
    && ! grep -qiE "^[[:space:]]*Port[[:space:]]+$SSH_PORT[[:space:]]*\$" /etc/ssh/sshd_config; then
    # OpenSSH до 8.2 (Ubuntu 18.04) не читает sshd_config.d: порт — в начало основного файла (до Match).
    cp -a /etc/ssh/sshd_config "$BACKUP/"
    sed -i -E 's/^([[:space:]]*Port[[:space:]])/#\1/I' /etc/ssh/sshd_config
    sed -i "1i Port $SSH_PORT" /etc/ssh/sshd_config
fi
sshd -t || die "sshd не принимает настройки: см. /etc/ssh/sshd_config"
PUBKEY="$(get SSH_PUBKEY)"
TARGET="${SUDO_USER:-}"
if [ -n "$PUBKEY" ] && [ -n "$TARGET" ] && [ "$TARGET" != root ]; then
    if [[ "$PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com)\ [A-Za-z0-9+/=]+( [^[:cntrl:]]*)?$ ]]; then
        HOME_DIR="$(getent passwd "$TARGET" | cut -d: -f6)"
        install -d -m 0700 -o "$TARGET" -g "$(id -gn "$TARGET")" "$HOME_DIR/.ssh"
        touch "$HOME_DIR/.ssh/authorized_keys"
        grep -qxF "$PUBKEY" "$HOME_DIR/.ssh/authorized_keys" || echo "$PUBKEY" >> "$HOME_DIR/.ssh/authorized_keys"
        chown "$TARGET:$(id -gn "$TARGET")" "$HOME_DIR/.ssh/authorized_keys"
        chmod 0600 "$HOME_DIR/.ssh/authorized_keys"
        echo "Ключ SSH хоста Windows добавлен пользователю $TARGET"
    else
        echo "ВНИМАНИЕ: SSH_PUBKEY в lab.conf не похож на публичный ключ — пропущен"
    fi
fi

# ---------------------------------------------------------------- хосты, правила, службы
say "Хосты из lab.conf"
IFS=',' read -r -a HOST_LIST <<< "$(get HOSTS)"
for item in "${HOST_LIST[@]}"; do
    item="${item// /}"
    [ -n "$item" ] || continue
    /usr/local/sbin/vmgw --no-apply host add "${item%%=*}" "${item#*=}" 2>&1 | head -1 || true
done

say "Правила межсетевого экрана и службы"
/usr/local/sbin/vmgw render
systemctl daemon-reload
# shellcheck disable=SC2086
systemctl enable $ROUTER_UNITS
# ssh (service или socket, как настроено в этой версии Ubuntu) включён пакетом;
# порт из sshd_config.d подхватывается после перезагрузки.

if [ ! -s /etc/vmgw/panel.pass ]; then
    say "Пароль веб-панели (минимум 8 символов)"
    if [ -t 0 ]; then
        until /usr/local/sbin/vmgw panel-password; do echo "Попробуйте ещё раз"; done
    else
        echo "Нет терминала: задайте позже командой  sudo vmgw panel-password"
    fi
fi
chgrp vmgw-web /etc/vmgw/panel.pass 2>/dev/null || true
write_stamp "$(kit_stamp "$HERE")"

cat <<EOF

============================================================
Роутер установлен. Резервные копии старых настроек: $BACKUP
После перезагрузки:
  SSH:     ssh -p $SSH_PORT ${SUDO_USER:-user}@${V[MGMT_IP]}
  Панель:  http://${V[MGMT_IP]}:$PANEL_PORT
  Консоль: sudo vmgw status | sudo vmgw help
LAN-сегмент ${V[LAN_CIDR]}: ВМ получают адреса по DHCP и общаются
между собой напрямую. В интернет — только через назначенный профиль.
============================================================
EOF
if [ -t 0 ] && [ "${NO_REBOOT:-}" != 1 ]; then
    read -r -p "Перезагрузить сейчас? [y/N] " a
    case "$a" in y|Y|д|Д) systemctl reboot ;; esac
fi
