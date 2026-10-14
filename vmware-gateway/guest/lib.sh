# lib.sh — общие функции router-install.sh, client-setup.sh и update.sh (подключается через source).

die() { echo "ОШИБКА: $*" >&2; exit 1; }
say() { echo; echo "== $*"; }

VERSION_FILE=/usr/local/lib/vmgw/VERSION
ROUTER_PKGS="nftables dnsmasq python3 openssh-server networkd-dispatcher openvpn sudo iproute2
    git build-essential pkg-config curl ca-certificates"

# ---------------------------------------------------------------- lab.conf (KEY=value, не исполняется)
declare -gA L
read_labconf() {
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in ''|*[!A-Z0-9_]*) die "lab.conf: неверная строка: $line" ;; esac
        val="${val#\"}"
        val="${val%\"}"
        L[$key]="$val"
    done < "$1"
}
get() { printf '%s' "${L[$1]:-${2:-}}"; }

# ---------------------------------------------------------------- версия комплекта
# Версия из файла VERSION + отпечаток содержимого комплекта. Тот же алгоритм
# в windows/VmGwCommon.ps1 (Get-KitStamp): по нему обновлялка сравнивает ВМ с комплектом.
kit_stamp() {
    local dir="$1" h
    h="$(cd "$dir" && find . -type f ! -name lab.conf ! -name README.md ! -path '*/__pycache__/*' -printf '%P\n' \
        | LC_ALL=C sort | while IFS= read -r f; do
            printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"
        done | sha256sum | cut -c1-12)"
    printf '%s+%s' "$(tr -d ' \r\n' < "$dir/VERSION")" "$h"
}
write_stamp() {
    install -d -m 0755 "$(dirname "$VERSION_FILE")"
    echo "$1" > "$VERSION_FILE.tmp"
    chmod 0644 "$VERSION_FILE.tmp"
    mv -f "$VERSION_FILE.tmp" "$VERSION_FILE"
}

# ---------------------------------------------------------------- пакеты
apt_install() {
    export DEBIAN_FRONTEND=noninteractive
    # Только что установленные службы (dnsmasq) не должны стартовать с настройками по умолчанию.
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d
    trap 'rm -f /usr/sbin/policy-rc.d' EXIT
    apt-get update
    apt-get install -y --no-install-recommends "$@"
    rm -f /usr/sbin/policy-rc.d
    trap - EXIT
}
missing_pkgs() {
    local p
    for p in "$@"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || printf '%s ' "$p"
    done
}

# ---------------------------------------------------------------- AmneziaWG
build_awg() {
    if [ -x /usr/bin/awg ] && [ -x /usr/local/bin/amneziawg-go ] && [ "${REBUILD:-}" != 1 ]; then
        say "AmneziaWG уже установлен (REBUILD=1 — пересобрать)"
        return
    fi
    say "Сборка AmneziaWG (amneziawg-go и amneziawg-tools)"
    local B=/var/cache/vmgw-build arch gofile gosha goref toolsref
    rm -rf "$B"
    mkdir -p "$B"
    case "$(dpkg --print-architecture)" in
        amd64) arch=amd64 ;;
        arm64) arch=arm64 ;;
        *) die "архитектура $(dpkg --print-architecture) не поддерживается" ;;
    esac
    # Официальный Go с go.dev: имя и sha256 из того же индекса.
    read -r gofile gosha < <(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -I -c '
import json, sys
for r in json.load(sys.stdin):
    if r.get("stable"):
        for f in r["files"]:
            if f["os"] == "linux" and f["arch"] == sys.argv[1] and f["kind"] == "archive":
                print(f["filename"], f["sha256"]); sys.exit()
sys.exit(1)' "$arch") || die "не удалось получить список версий Go с go.dev"
    [[ "$gofile" =~ ^go[0-9.]+\.linux-(amd64|arm64)\.tar\.gz$ ]] || die "неожиданное имя архива Go: $gofile"
    echo "Go: $gofile"
    curl -fsSL "https://go.dev/dl/$gofile" -o "$B/$gofile"
    echo "$gosha  $B/$gofile" | sha256sum -c --quiet - || die "sha256 архива Go не совпал"
    tar -C "$B" -xzf "$B/$gofile"

    latest_tag() { git -c versionsort.suffix=- ls-remote --tags --refs --sort=-v:refname "$1" | awk -F/ 'NR==1{print $3}'; }
    local GO_URL=https://github.com/amnezia-vpn/amneziawg-go
    local TOOLS_URL=https://github.com/amnezia-vpn/amneziawg-tools
    goref="$(get AWG_GO_REF)";       [ -n "$goref" ] || goref="$(latest_tag "$GO_URL")"
    toolsref="$(get AWG_TOOLS_REF)"; [ -n "$toolsref" ] || toolsref="$(latest_tag "$TOOLS_URL")"
    [ -n "$goref" ] && [ -n "$toolsref" ] || die "не удалось определить версии AmneziaWG (нет доступа к github.com?)"
    echo "amneziawg-go $goref, amneziawg-tools $toolsref"
    git clone -q --depth 1 --branch "$goref" "$GO_URL" "$B/amneziawg-go"
    git clone -q --depth 1 --branch "$toolsref" "$TOOLS_URL" "$B/amneziawg-tools"

    (
        export PATH="$B/go/bin:$PATH" GOPATH="$B/gopath" GOCACHE="$B/gocache" GOTOOLCHAIN=auto GOFLAGS=-buildvcs=false
        make -C "$B/amneziawg-go"
    )
    install -m 0755 "$B/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go.new
    mv -f /usr/local/bin/amneziawg-go.new /usr/local/bin/amneziawg-go
    make -C "$B/amneziawg-tools/src"
    make -C "$B/amneziawg-tools/src" install PREFIX=/usr WITH_WGQUICK=no WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no
    rm -rf "$B"
    /usr/bin/awg --version || true
}

# ---------------------------------------------------------------- файлы роутера
# Всё, что не зависит от сетей и настроек: код, юниты, sudoers, sysctl.
# Файлы, которые меняет этот блок (для резервной копии в update.sh):
ROUTER_FILES="usr/local/sbin/vmgw usr/local/lib/vmgw etc/sudoers.d/vmgw-web etc/systemd/system/vmgw.service
    etc/systemd/system/vmgw-awg@.service etc/systemd/system/vmgw-check.service etc/systemd/system/vmgw-check.timer
    etc/systemd/system/vmgw-web.service etc/systemd/system/nftables.service.d/vmgw.conf
    etc/networkd-dispatcher/routable.d/50-vmgw-wan etc/nftables.conf etc/sysctl.d/60-vmgw.conf etc/dnsmasq.d/vmgw.conf"
install_router_files() {
    local KIT="$1" u
    id vmgw-web >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vmgw-web
    install -d -m 0750 -o root -g vmgw-web /etc/vmgw
    chown root:vmgw-web /etc/vmgw
    chmod 0750 /etc/vmgw
    install -d -m 0755 /var/lib/vmgw /usr/local/lib/vmgw
    install -m 0755 "$KIT/vmgw.py" /usr/local/sbin/vmgw.new
    mv -f /usr/local/sbin/vmgw.new /usr/local/sbin/vmgw
    install -m 0755 "$KIT/vmgw-web.py" /usr/local/lib/vmgw/vmgw-web.py

    cat > /etc/sudoers.d/vmgw-web.tmp <<'EOF'
# Панель может вызвать ровно одну команду; запрос передаётся JSON через stdin.
Defaults:vmgw-web !syslog, !pam_session
vmgw-web ALL=(root) NOPASSWD: /usr/local/sbin/vmgw api
EOF
    chmod 0440 /etc/sudoers.d/vmgw-web.tmp
    visudo -cqf /etc/sudoers.d/vmgw-web.tmp || die "sudoers не прошёл проверку"
    mv -f /etc/sudoers.d/vmgw-web.tmp /etc/sudoers.d/vmgw-web

    cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# vmgw: правила генерирует `vmgw apply` (файл начинается с flush ruleset).
include "/etc/vmgw/ruleset.nft"
EOF
    install -D -m 0644 "$KIT/systemd/nftables-keep.conf" /etc/systemd/system/nftables.service.d/vmgw.conf
    for u in vmgw.service vmgw-awg@.service vmgw-check.service vmgw-check.timer vmgw-web.service; do
        install -m 0644 "$KIT/systemd/$u" "/etc/systemd/system/$u"
    done
    install -D -m 0755 -o root -g root "$KIT/systemd/50-vmgw-wan" /etc/networkd-dispatcher/routable.d/50-vmgw-wan

    cat > /etc/sysctl.d/60-vmgw.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
    sysctl --system >/dev/null
}

# Параметры DHCP по сети LAN: печатает LAN_GW, LAN_MASK, POOL_START, POOL_END.
lan_params() {
    python3 -I -c '
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
print("LAN_GW=%s\nLAN_MASK=%s\nPOOL_START=%s\nPOOL_END=%s" % (n[1], n.netmask, n[200], n[250]))' "$1"
}

# dnsmasq только для DHCP. Возвращает 0, если файл изменился.
write_dnsmasq() {
    local LAN_NET="$1" k v
    local -A P
    while IFS='=' read -r k v; do P[$k]="$v"; done < <(lan_params "$LAN_NET")
    cat > /etc/dnsmasq.d/vmgw.conf.tmp <<EOF
# vmgw: только DHCP в LAN-сегменте. DNS клиенты получают публичный и ходят к нему
# по своему пути выхода (через свой туннель).
port=0
interface=lan0
bind-dynamic
dhcp-authoritative
dhcp-range=lan0,${P[POOL_START]},${P[POOL_END]},${P[LAN_MASK]},12h
dhcp-option=lan0,option:router,${P[LAN_GW]}
dhcp-option=lan0,option:dns-server,1.1.1.1,9.9.9.9
dhcp-hostsfile=/var/lib/vmgw/dhcp-hosts
EOF
    touch /var/lib/vmgw/dhcp-hosts
    if [ -f /etc/default/dnsmasq ] && ! grep -q '^DNSMASQ_EXCEPT=' /etc/default/dnsmasq; then
        # Не регистрировать 127.0.0.1 как DNS роутера (DNS у dnsmasq выключен).
        echo 'DNSMASQ_EXCEPT="lo"' >> /etc/default/dnsmasq
    fi
    if cmp -s /etc/dnsmasq.d/vmgw.conf.tmp /etc/dnsmasq.d/vmgw.conf; then
        rm -f /etc/dnsmasq.d/vmgw.conf.tmp
        return 1
    fi
    mv -f /etc/dnsmasq.d/vmgw.conf.tmp /etc/dnsmasq.d/vmgw.conf
}

ROUTER_UNITS="nftables.service dnsmasq.service networkd-dispatcher.service vmgw.service vmgw-check.timer vmgw-web.service"

# ---------------------------------------------------------------- ведомая ВМ
write_client_sysctl() {
    # IPv6 в сегменте не маршрутизируется; выключаем, чтобы программы не ждали его.
    cat > /etc/sysctl.d/60-vmgw-client.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
    sysctl --system >/dev/null
}
