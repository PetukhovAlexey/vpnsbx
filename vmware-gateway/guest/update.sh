#!/bin/bash
# update.sh — приводит установленную ВМ vmgw в соответствие с этим комплектом.
#   sudo bash update.sh router [--rebuild-awg] [--force]
#   sudo bash update.sh client [--force]
# Обычно его запускает обновлялка с Windows (Update.cmd) по SSH. Вручную — из общей папки:
#   sudo bash /mnt/hgfs/vmgw/update.sh router
# Хосты, профили, пробросы, пароль панели и сетевые настройки не меняются.
# Если новая версия не проходит проверку правил или не применяется, роутер
# возвращается к прежним файлам.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

ROLE="${1:-}"
[ $# -gt 0 ] && shift
REBUILD=0
FORCE=0
for a in "$@"; do
    case "$a" in
        --rebuild-awg) REBUILD=1 ;;
        --force) FORCE=1 ;;
        *) die "неизвестный параметр: $a" ;;
    esac
done
case "$ROLE" in router|client) ;; *) die "использование: sudo bash $0 router|client [--rebuild-awg] [--force]" ;; esac
[ "$(id -u)" = 0 ] || die "запустите через sudo: sudo bash $0 $ROLE"

STAMP="$(kit_stamp "$HERE")"
OLD="$(cat "$VERSION_FILE" 2>/dev/null || echo 'не записана')"
if [ "$OLD" = "$STAMP" ] && [ "$FORCE" = 0 ] && [ "$REBUILD" = 0 ]; then
    echo "Уже актуально: $STAMP"
    exit 0
fi

# ---------------------------------------------------------------- ведомая ВМ
if [ "$ROLE" = client ]; then
    [ ! -f /etc/vmgw/config.json ] || die "это роутер vmgw — запустите: update.sh router"
    say "Ведомая ВМ: $OLD → $STAMP"
    write_client_sysctl
    write_stamp "$STAMP"
    echo "Готово: $STAMP"
    exit 0
fi

# ---------------------------------------------------------------- роутер
[ -f /etc/vmgw/config.json ] && [ -x /usr/local/sbin/vmgw ] \
    || die "здесь не установлен роутер vmgw — сначала router-install.sh"
say "Роутер: $OLD → $STAMP"
[ -f "$HERE/lab.conf" ] && read_labconf "$HERE/lab.conf"   # AWG_GO_REF / AWG_TOOLS_REF

# shellcheck disable=SC2086
MISSING="$(missing_pkgs $ROUTER_PKGS)"
if [ -n "$MISSING" ]; then
    say "Доустановка пакетов: $MISSING"
    # shellcheck disable=SC2086
    apt_install $MISSING
fi

BK=/var/lib/vmgw/update-backup
install -d -m 0700 "$BK"
BACKUP="$BK/$(date +%Y%m%d-%H%M%S).tar.gz"
EXISTING=()
for f in $ROUTER_FILES; do [ -e "/$f" ] && EXISTING+=("$f"); done
tar -C / -czf "$BACKUP" "${EXISTING[@]}"
# shellcheck disable=SC2012
ls -1t "$BK"/*.tar.gz | tail -n +6 | xargs -r rm -f
echo "Резервная копия: $BACKUP"

STARTED=0
DONE=0
DNSMASQ_CHANGED=0
rollback() {
    echo >&2
    echo "Откат к прежней версии из $BACKUP" >&2
    tar -C / -xzf "$BACKUP"
    systemctl daemon-reload || true
    /usr/local/sbin/vmgw apply >/dev/null || echo "ВНИМАНИЕ: vmgw apply после отката не прошёл" >&2
    [ "$DNSMASQ_CHANGED" = 0 ] || systemctl restart dnsmasq.service || true
    systemctl restart vmgw-web.service || true
}
on_exit() {
    local rc=$?
    if [ "$STARTED" = 1 ] && [ "$DONE" = 0 ]; then
        rollback
        echo "ОШИБКА: обновление не удалось, роутер работает на прежней версии ($OLD)" >&2
        exit 1
    fi
    exit $rc
}
trap on_exit EXIT
STARTED=1

say "Установка файлов"
install_router_files "$HERE/vmgw"
LAN_NET="$(python3 -I -c 'import json; print(json.load(open("/etc/vmgw/config.json"))["lan_net"])')"
if write_dnsmasq "$LAN_NET"; then DNSMASQ_CHANGED=1; fi
systemctl daemon-reload

say "Проверка правил"
/usr/local/sbin/vmgw render

if [ "$REBUILD" = 1 ]; then
    build_awg
fi

say "Применение"
if [ "$REBUILD" = 1 ]; then
    /usr/local/sbin/vmgw restart       # туннели переподнимаются новой сборкой
else
    /usr/local/sbin/vmgw apply         # работающие туннели не перезапускаются
fi
# Служба могла упасть при загрузке старой версией: без active systemd не выполнит vmgw stop при выключении.
systemctl is-active --quiet vmgw.service || systemctl start vmgw.service
[ "$DNSMASQ_CHANGED" = 0 ] || systemctl restart dnsmasq.service
# shellcheck disable=SC2086
systemctl enable --quiet $ROUTER_UNITS
systemctl restart vmgw-web.service
systemctl restart vmgw-check.timer
write_stamp "$STAMP"
DONE=1

say "Готово: $STAMP"
/usr/local/sbin/vmgw status || true
