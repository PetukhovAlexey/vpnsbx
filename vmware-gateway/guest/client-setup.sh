#!/bin/bash
# client-setup.sh — необязательная донастройка ведомой ВМ (Ubuntu Desktop).
#   sudo bash client-setup.sh            проверка сети
#   sudo bash client-setup.sh --ssh      + OpenSSH-сервер и ключ хоста Windows из lab.conf
# У ведомой ВМ одна сетевая карта — во внутреннем LAN-сегменте. Адрес, шлюз и DNS
# выдаёт роутер по DHCP; в интернет ВМ выходит только по своему профилю на роутере.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
[ "$(id -u)" = 0 ] || die "запустите через sudo: sudo bash $0 $*"
[ ! -f /etc/vmgw/config.json ] || die "это роутер vmgw, а не ведомая ВМ"

write_client_sysctl
write_stamp "$(kit_stamp "$HERE")"

if [ "${1:-}" = "--ssh" ]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server
    PUBKEY=""
    if [ -f "$HERE/lab.conf" ]; then
        PUBKEY="$(sed -n 's/^SSH_PUBKEY="\{0,1\}\([^"]*\)"\{0,1\}\r\{0,1\}$/\1/p' "$HERE/lab.conf" | head -1)"
    fi
    TARGET="${SUDO_USER:-}"
    if [ -n "$PUBKEY" ] && [ -n "$TARGET" ] && [ "$TARGET" != root ]; then
        HOME_DIR="$(getent passwd "$TARGET" | cut -d: -f6)"
        install -d -m 0700 -o "$TARGET" -g "$(id -gn "$TARGET")" "$HOME_DIR/.ssh"
        touch "$HOME_DIR/.ssh/authorized_keys"
        grep -qxF "$PUBKEY" "$HOME_DIR/.ssh/authorized_keys" || echo "$PUBKEY" >> "$HOME_DIR/.ssh/authorized_keys"
        chown "$TARGET:$(id -gn "$TARGET")" "$HOME_DIR/.ssh/authorized_keys"
        chmod 0600 "$HOME_DIR/.ssh/authorized_keys"
        echo "Ключ SSH хоста Windows добавлен пользователю $TARGET"
    fi
    echo "SSH-сервер установлен. Снаружи он доступен только через проброс порта на роутере"
    echo "(панель → «Проброс портов», например tcp 2201 → эта ВМ :22)."
fi

echo
echo "== Сеть этой ВМ"
ip -4 -br addr show scope global
ip -4 route show default
echo
echo "== Проверка выхода в интернет"
if ip=$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null); then
    echo "Внешний адрес: $ip  (должен совпадать с сервером профиля, назначенного этой ВМ)"
else
    echo "Интернета нет. Это нормально, если на роутере этой ВМ не назначен профиль"
    echo "или её туннель сейчас не работает. MAC этой ВМ для регистрации на роутере:"
    ip -br link | awk '$1 != "lo" {print "  " $1 "  " $3}'
fi
