#!/usr/bin/python3 -I
"""vmgw: controller of the VMware gateway VM.

One router, N hosts in the VMware LAN segment. Every host has its own egress
policy: a dedicated AmneziaWG tunnel, direct WAN, or blocked. Unknown hosts are
always blocked. The firewall is the source of truth for what may leave; the
policy routing only chooses the path, so a routing gap still fails closed.
"""
import base64
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

ETC = Path('/etc/vmgw')
PROFILES = ETC / 'profiles'
RUN = Path('/run/vmgw')
RULESET = ETC / 'ruleset.nft'
DHCP_HOSTS = Path('/var/lib/vmgw/dhcp-hosts')   # read by dnsmasq (unprivileged)
PANEL_PASS = ETC / 'panel.pass'
LEASES = Path('/var/lib/misc/dnsmasq.leases')
AWG = '/usr/bin/awg'

CORP_DIR = ETC / 'corporate'
CORP_SRC = CORP_DIR / 'client.ovpn'
CORP_AUTH = CORP_DIR / 'auth.txt'
CORP_CONF = Path('/etc/openvpn/client/vmgw-corp.conf')
CORP_UNIT = 'openvpn-client@vmgw-corp.service'
CORP_DEV = 'corp0'

TABLE_TUNNEL = 51800      # tunnel id k uses table 51800+k
TABLE_UNDERLAY = 51797    # where the encrypted AmneziaWG packets of the router go
TABLE_DIRECT = 51798
TABLE_BLOCK = 51799
FWMARK = 51797            # set by awg on its own UDP packets -> TABLE_UNDERLAY
PREF_UNDERLAY = 90
PREF_HOST = 1000          # host i uses rule priority 1000+i
PREF_CATCHALL = 30000
MAX_TUNNELS = 64
MAX_HOSTS = 180

PROFILE_RE = re.compile(r'^[^\W][\w .()+,-]{0,78}\.(vpn|conf)$')
HOST_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}$')
MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
HOSTNAME_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
WGQUICK_ONLY = {'address', 'dns', 'mtu', 'table', 'preup', 'postup', 'predown', 'postdown', 'saveconfig'}
MODES = ('blocked', 'direct', 'tunnel')


class Fail(Exception):
    pass


# ---------------------------------------------------------------- helpers

def run(args, check=True, data=None):
    p = subprocess.run(args, input=(data or '').encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        err = p.stderr.decode(errors='replace').strip().splitlines()
        raise Fail('Команда не выполнена: %s (%s)' % (' '.join(args[:3]), err[-1] if err else p.returncode))
    return p.stdout.decode(errors='replace').strip()


def save(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, str(path))


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def write_json(path, obj):
    save(path, json.dumps(obj, ensure_ascii=False, indent=1) + '\n')


def cfg():
    return read_json(ETC / 'config.json', None) or fail('Нет /etc/vmgw/config.json: запустите router-install.sh')


def fail(msg):
    raise Fail(msg)


def hosts():
    return read_json(ETC / 'hosts.json', [])


def forwards():
    return read_json(ETC / 'forwards.json', [])


def profiles():
    return read_json(ETC / 'profiles.json', {})


def state():
    return read_json(ETC / 'state.json', {'corporate': False})


# ---------------------------------------------------------------- profiles

def check_profile_name(name):
    if not isinstance(name, str) or Path(name).name != name or not PROFILE_RE.match(name) \
            or any(ord(c) < 32 for c in name):
        raise Fail('Имя профиля: буквы, цифры, пробел, .()+,- и окончание .vpn или .conf')


def amnezia_config(raw):
    """Return the native [Interface]/[Peer] text from a vpn:// export or a .conf file."""
    raw = raw.strip()
    if '[Interface]' in raw:
        return raw
    if not raw.startswith('vpn://'):
        raise Fail('Ожидается ссылка vpn:// из AmneziaVPN или файл .conf AmneziaWG')
    try:
        b = raw[6:]
        data = base64.urlsafe_b64decode(b + '=' * (-len(b) % 4))
    except Exception:
        raise Fail('Профиль vpn:// повреждён')
    body = None
    if len(data) > 4:
        declared = struct.unpack('>I', data[:4])[0]
        if declared <= 1000000:
            try:
                d = zlib.decompressobj()
                out = d.decompress(data[4:], 1000001)
                if d.eof and len(out) == declared:
                    body = out
            except zlib.error:
                pass
    try:
        obj = json.loads((body if body is not None else data).decode('utf-8'))
    except Exception:
        raise Fail('Профиль vpn:// повреждён')
    containers = obj.get('containers') if isinstance(obj, dict) else None
    if not isinstance(containers, list):
        raise Fail('В профиле нет контейнеров')
    default = obj.get('defaultContainer')
    containers = sorted(containers, key=lambda c: 0 if isinstance(c, dict) and c.get('container') == default else 1)
    for c in containers:
        if not isinstance(c, dict):
            continue
        for v in c.values():
            if isinstance(v, dict) and isinstance(v.get('last_config'), str):
                try:
                    native = json.loads(v['last_config']).get('config')
                except Exception:
                    continue
                if isinstance(native, str) and '[Interface]' in native:
                    return native
    raise Fail('В профиле нет конфигурации AmneziaWG (поддерживаются только AWG-профили)')


def parse_native(text):
    """Return (setconf text, info). Drops awg-quick-only keys, forces AllowedIPs 0.0.0.0/0."""
    section = None
    out, vals = [], {}
    count = {'[interface]': 0, '[peer]': 0}
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in '#;':
            continue
        if s.startswith('['):
            section = s.lower()
            if section not in count:
                raise Fail('Неизвестная секция ' + s[:20])
            count[section] += 1
            out.append('[Interface]' if section == '[interface]' else '[Peer]')
            continue
        if section is None or '=' not in s:
            raise Fail('Ошибка формата конфигурации')
        k, v = [x.strip() for x in s.split('=', 1)]
        if not re.match(r'^[A-Za-z][A-Za-z0-9]*$', k) or any(ord(c) < 32 for c in v):
            raise Fail('Недопустимая строка в конфигурации')
        key = (section, k.lower())
        if key in vals:
            raise Fail('Повтор параметра ' + k)
        vals[key] = v
        if section == '[interface]' and k.lower() in WGQUICK_ONLY:
            continue
        if section == '[peer]' and k.lower() == 'allowedips':
            v = '0.0.0.0/0'
        out.append(k + ' = ' + v)
    if count['[interface]'] != 1 or count['[peer]'] != 1:
        raise Fail('Нужны ровно одна секция [Interface] и одна [Peer]')
    for need in (('[interface]', 'privatekey'), ('[interface]', 'address'), ('[peer]', 'publickey'), ('[peer]', 'endpoint')):
        if need not in vals:
            raise Fail('В конфигурации нет ' + need[1])
    if ('[peer]', 'allowedips') not in vals:
        out.append('AllowedIPs = 0.0.0.0/0')
    addr = None
    for a in vals[('[interface]', 'address')].split(','):
        try:
            iface = ipaddress.ip_interface(a.strip())
        except ValueError:
            raise Fail('Неверный Address')
        if iface.version == 4:
            addr = iface
            break
    if addr is None:
        raise Fail('Нужен IPv4-адрес туннеля')
    ep = vals[('[peer]', 'endpoint')]
    host, _, port = ep.rpartition(':')
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise Fail('Неверный Endpoint')
    try:
        if ipaddress.ip_address(host.strip('[]')).version != 4:
            raise Fail('Endpoint должен быть IPv4 (IPv6 на роутере выключен)')
    except ValueError:
        if not HOSTNAME_RE.match(host):
            raise Fail('Неверный Endpoint')
    mtu = 1280
    m = vals.get(('[interface]', 'mtu'), '')
    if m.isdigit() and 576 <= int(m) <= 1500:
        mtu = int(m)
    info = {'address': str(addr), 'endpoint': ep, 'public_key': vals[('[peer]', 'publickey')], 'mtu': mtu}
    return '\n'.join(out) + '\n', info


def load_profile(name):
    check_profile_name(name)
    fd = os.open(str(PROFILES / name), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        raw = f.read(2000001)
    return parse_native(amnezia_config(raw))


def profile_id(name):
    p = profiles()
    if name not in p:
        raise Fail('Профиль не найден: ' + name)
    return p[name]['id']


def import_profile(name, raw):
    check_profile_name(name)
    if len(raw) > 2000000:
        raise Fail('Профиль слишком большой')
    parse_native(amnezia_config(raw))
    p = profiles()
    if name in p or (PROFILES / name).exists():
        raise Fail('Профиль с таким именем уже есть')
    used = {v['id'] for v in p.values()}
    free = [i for i in range(1, MAX_TUNNELS + 1) if i not in used]
    if not free:
        raise Fail('Слишком много профилей')
    PROFILES.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(PROFILES / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(raw.strip() + '\n')
    p[name] = {'id': free[0]}
    write_json(ETC / 'profiles.json', p)
    return 'Профиль загружен: %s (туннель awg%d)' % (name, free[0])


def delete_profile(name):
    check_profile_name(name)
    users = [h['name'] for h in hosts() if h.get('profile') == name]
    if users:
        raise Fail('Профиль используется хостами: ' + ', '.join(users))
    p = profiles()
    if name not in p:
        raise Fail('Профиль не найден')
    tunnel_down(p[name]['id'])
    path = PROFILES / name
    if path.is_file() and not path.is_symlink():
        path.unlink()
    del p[name]
    write_json(ETC / 'profiles.json', p)
    return 'Профиль удалён: ' + name


def profile_list():
    out = []
    for name, meta in sorted(profiles().items()):
        item = {'name': name, 'id': meta['id'], 'valid': False,
                'used_by': [h['name'] for h in hosts() if h.get('mode') == 'tunnel' and h.get('profile') == name]}
        try:
            _, info = load_profile(name)
            item.update(info, valid=True)
        except Exception as e:
            item['error'] = str(e) if isinstance(e, Fail) else 'Профиль не читается'
        out.append(item)
    return out


# ---------------------------------------------------------------- hosts

def norm_mac(mac):
    mac = (mac or '').strip().lower().replace('-', ':')
    if not MAC_RE.match(mac) or int(mac[:2], 16) & 1:
        raise Fail('Неверный MAC-адрес')
    return mac


def lan_net(c):
    return ipaddress.ip_network(c['lan_net'])


def static_range(c):
    net = lan_net(c)
    return [net[i] for i in range(10, 200)]


def host_add(name, mac, ip=None):
    c = cfg()
    if not HOST_RE.match(name or ''):
        raise Fail('Имя хоста: латиница в нижнем регистре, цифры и дефис, до 31 символа')
    mac = norm_mac(mac)
    hs = hosts()
    if len(hs) >= MAX_HOSTS:
        raise Fail('Слишком много хостов')
    if any(h['name'] == name for h in hs):
        raise Fail('Хост с таким именем уже есть')
    if any(h['mac'] == mac for h in hs):
        raise Fail('Этот MAC уже назначен')
    used = {h['ip'] for h in hs}
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise Fail('Неверный IP')
        if addr not in static_range(c):
            raise Fail('IP должен быть в диапазоне %s–%s' % (static_range(c)[0], static_range(c)[-1]))
        if str(addr) in used:
            raise Fail('IP уже занят')
        ip = str(addr)
    else:
        ip = next((str(a) for a in static_range(c) if str(a) not in used), None) or fail('Нет свободных адресов')
    hs.append({'name': name, 'mac': mac, 'ip': ip, 'mode': 'blocked', 'profile': None, 'local': False})
    write_json(ETC / 'hosts.json', hs)
    return 'Хост %s добавлен: %s → %s (без интернета, пока не выбран профиль)' % (name, mac, ip)


def find_host(hs, name):
    for h in hs:
        if h['name'] == name:
            return h
    raise Fail('Хост не найден: ' + str(name))


def host_set(name, mode=None, profile=None, local=None):
    hs = hosts()
    h = find_host(hs, name)
    if mode is not None:
        if mode not in MODES:
            raise Fail('Режим: blocked, direct или tunnel')
        if mode == 'tunnel':
            check_profile_name(profile)
            profile_id(profile)
            load_profile(profile)
            h['profile'] = profile
        else:
            h['profile'] = None
        h['mode'] = mode
    if local is not None:
        h['local'] = bool(local)
    write_json(ETC / 'hosts.json', hs)
    return 'Хост %s: %s' % (name, describe(h))


def describe(h):
    m = {'blocked': 'без интернета', 'direct': 'напрямую через WAN (без VPN!)',
         'tunnel': 'через туннель «%s»' % h.get('profile')}[h['mode']]
    return m + ('; домашняя сеть за WAN разрешена' if h.get('local') else '')


def host_del(name):
    hs = hosts()
    h = find_host(hs, name)
    hs.remove(h)
    write_json(ETC / 'hosts.json', hs)
    fw = [f for f in forwards() if f['host'] != name]
    write_json(ETC / 'forwards.json', fw)
    return 'Хост удалён: ' + name


def leases():
    out = []
    try:
        lines = LEASES.read_text().splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        p = line.split()
        if len(p) >= 4:
            out.append({'expires': int(p[0]) if p[0].isdigit() else 0, 'mac': p[1].lower(), 'ip': p[2],
                        'hostname': '' if p[3] == '*' else p[3][:63]})
    return out


def neighbours(c):
    state = {}
    for line in run(['ip', '-4', 'neigh', 'show', 'dev', c['lan_if']], False).splitlines():
        p = line.split()
        if p and len(p) >= 2:
            state[p[0]] = p[-1]
    return state


# ---------------------------------------------------------------- forwards

def fwd_add(proto, port, host, to_port, source='mgmt'):
    c = cfg()
    if proto not in ('tcp', 'udp'):
        raise Fail('Протокол: tcp или udp')
    try:
        port, to_port = int(port), int(to_port)
    except (TypeError, ValueError):
        raise Fail('Порт должен быть числом')
    if not (1 <= port <= 65535 and 1 <= to_port <= 65535):
        raise Fail('Порт вне диапазона 1–65535')
    if proto == 'tcp' and port in (c['ssh_port'], c['panel_port']):
        raise Fail('Порт %d занят самим роутером' % port)
    if proto == 'udp' and port in (67, 68):
        raise Fail('Порт занят DHCP')
    if source not in ('mgmt', 'local'):
        raise Fail('Источник: mgmt (только хост Windows) или local (ещё и локальные сети)')
    if source == 'local' and not c.get('local_nets'):
        raise Fail('Локальные сети не настроены (local_nets в config.json)')
    find_host(hosts(), host)
    fw = forwards()
    if any(f['proto'] == proto and f['port'] == port for f in fw):
        raise Fail('Этот внешний порт уже проброшен')
    fw.append({'proto': proto, 'port': port, 'host': host, 'to_port': to_port, 'source': source})
    fw.sort(key=lambda f: (f['proto'], f['port']))
    write_json(ETC / 'forwards.json', fw)
    return 'Проброс %s %d → %s:%d' % (proto, port, host, to_port)


def fwd_del(proto, port):
    fw = forwards()
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise Fail('Порт должен быть числом')
    new = [f for f in fw if not (f['proto'] == proto and f['port'] == port)]
    if len(new) == len(fw):
        raise Fail('Такого проброса нет')
    write_json(ETC / 'forwards.json', new)
    return 'Проброс удалён: %s %d' % (proto, port)


# ---------------------------------------------------------------- firewall

def nset(items):
    return '{ ' + ', '.join(items) + ' }'


def ruleset(c, hs, fw, ids):
    lan, wan, mgmt = '"%s"' % c['lan_if'], '"%s"' % c['wan_if'], '"%s"' % c['mgmt_if']
    admin = [c['mgmt_net']] + list(c.get('admin_nets', []))
    local = list(c.get('local_nets', []))
    block = list(c.get('mgmt_block', []))
    L = ['#!/usr/sbin/nft -f',
         '# Сгенерировано vmgw apply. Не править руками: изменения будут перезаписаны.',
         'flush ruleset', '',
         'table inet vmgw {',
         '\tset admin_nets { type ipv4_addr; flags interval; elements = %s; }' % nset(admin)]
    if local:
        L.append('\tset local_nets { type ipv4_addr; flags interval; elements = %s; }' % nset(local))
    L += ['',
          '\tchain input {',
          '\t\ttype filter hook input priority 0; policy drop;',
          '\t\tiif "lo" accept',
          '\t\tmeta nfproto ipv6 drop',
          '\t\tct state invalid drop',
          '\t\tct state established,related accept',
          '\t\tiifname %s udp sport 68 udp dport 67 accept' % lan,
          '\t\tiifname %s icmp type echo-request limit rate 20/second accept' % lan,
          '\t\tiifname %s udp sport 67 udp dport 68 accept' % wan,
          '\t\tiifname %s ip saddr %s icmp type echo-request accept' % (mgmt, c['mgmt_net']),
          '\t\tiifname { %s, %s } ip saddr @admin_nets tcp dport { %d, %d } accept' % (mgmt, wan, c['ssh_port'], c['panel_port']),
          '\t\tcounter',
          '\t}', '',
          '\t# Каждый пакет из LAN-сегмента (и новый, и уже установленного соединения)',
          '\t# проходит политику своего хоста. Поэтому при падении туннеля старые',
          '\t# соединения не уходят в WAN: established проверяется только после.',
          '\tchain forward {',
          '\t\ttype filter hook forward priority 0; policy drop;',
          '\t\tmeta nfproto ipv6 drop',
          '\t\t# MSS по MTU туннеля: иначе серверы шлют ВМ сегменты крупнее туннеля, за сервером',
          '\t\t# VPN они теряются, и сервер падает до 536 байт (Windows OOBE: «подключение потеряно»).',
          '\t\toifname "awg*" tcp flags syn tcp option maxseg size set rt mtu',
          '\t\tiifname %s jump from_lan' % lan,
          '\t\tct state invalid drop',
          '\t\tct state established,related accept',
          '\t\tct status dnat accept',
          '\t\t# Хост Windows -> ВМ сегмента: открыто (нужен маршрут к LAN через роутер).',
          '\t\tiifname %s ip saddr %s%s oifname %s ip daddr %s accept' % (
              mgmt, c['mgmt_net'], ' ip saddr != %s' % nset(block) if block else '', lan, c['lan_net']),
          '\t\tcounter',
          '\t}', '',
          '\tchain from_lan {',
          '\t\tct state invalid drop',
          '\t\tct direction reply ct status dnat accept',
          '\t\t# ВМ -> хост Windows: открыто для всех ВМ сегмента, кроме NAT-шлюза VMware',
          '\t\t# (через него был бы выход в интернет) и DNS (только по пути выхода ВМ).']
    to_host = '\t\toifname %s ip daddr %s' % (mgmt, c['mgmt_net'])
    if block:
        to_host += ' ip daddr != %s' % nset(block)
    L += [to_host + ' %s dport { 53, 853 } counter drop comment "DNS only via egress"' % p for p in ('tcp', 'udp')]
    L.append(to_host + ' accept')
    for i, h in enumerate(hs):
        L.append('\t\tip saddr %s ether saddr != %s counter drop comment "spoof %s"' % (h['ip'], h['mac'], h['name']))
        L.append('\t\tip saddr %s ether saddr %s jump host_%d' % (h['ip'], h['mac'], i))
    L += ['\t\tcounter drop comment "unknown host"', '\t}']
    for i, h in enumerate(hs):
        L += ['', '\tchain host_%d {' % i, '\t\t# %s: %s' % (h['name'], h['mode'] + (' ' + h['profile'] if h.get('profile') else ''))]
        if h['mode'] == 'tunnel' and h.get('profile') in ids:
            L.append('\t\toifname "awg%d" accept' % ids[h['profile']])
        elif h['mode'] == 'direct':
            L.append('\t\toifname %s accept' % wan)
        if h.get('local') and local:
            for p in ('tcp', 'udp'):
                L.append('\t\toifname %s ip daddr @local_nets %s dport { 53, 853 } '
                         'counter drop comment "DNS only via egress"' % (wan, p))
            L.append('\t\toifname %s ip daddr @local_nets accept' % wan)
        L += ['\t\tcounter drop', '\t}']
    L += ['}', '',
          'table ip vmgw_nat {',
          '\tchain prerouting {',
          '\t\ttype nat hook prerouting priority -100; policy accept;']
    byname = {h['name']: h for h in hs}
    for f in fw:
        h = byname.get(f['host'])
        if not h:
            continue
        tail = '%s dport %d dnat to %s:%d' % (f['proto'], f['port'], h['ip'], f['to_port'])
        L.append('\t\tiifname %s ip saddr %s ip daddr %s %s' % (mgmt, c['mgmt_net'], c['mgmt_addr'].split('/')[0], tail))
        if f['source'] == 'local' and local:
            L.append('\t\tiifname %s ip saddr %s fib daddr type local %s' % (wan, nset(local), tail))
    L += ['\t}', '',
          '\tchain postrouting {',
          '\t\ttype nat hook postrouting priority 100; policy accept;',
          '\t\toifname "awg*" ip saddr %s masquerade' % c['lan_net'],
          '\t\toifname %s ip saddr %s masquerade' % (wan, c['lan_net']),
          '\t\toifname %s ip saddr %s masquerade' % (mgmt, c['lan_net']),
          '\t\toifname %s ct status dnat masquerade' % lan,
          '\t}', '}', '']
    return '\n'.join(L)


def apply_firewall(c, hs, fw, ids):
    text = ruleset(c, hs, fw, ids)
    RUN.mkdir(mode=0o700, exist_ok=True)
    tmp = RUN / 'ruleset.check.nft'
    save(tmp, text)
    run(['nft', '-c', '-f', str(tmp)])
    run(['nft', '-f', str(tmp)])
    save(RULESET, text)
    tmp.unlink()


def write_dhcp(hs):
    text = ''.join('%s,%s,%s\n' % (h['mac'], h['ip'], h['name']) for h in hs)
    try:
        old = DHCP_HOSTS.read_text()
    except FileNotFoundError:
        old = None
    if old != text:
        save(DHCP_HOSTS, text, 0o644)
        run(['systemctl', 'kill', '-s', 'HUP', 'dnsmasq.service'], False)


# ---------------------------------------------------------------- routing
# Текстовый вывод ip, а не -j: iproute2 4.15 (Ubuntu 18.04) не умеет JSON для route и rule.

def word_after(line, key):
    t = line.split()
    return t[t.index(key) + 1] if key in t[:-1] else None


def ip4_addr(dev):
    """Первый IPv4-адрес интерфейса в виде 'a.b.c.d/len' или None."""
    for line in run(['ip', '-4', '-o', 'addr', 'show', 'dev', dev], False).splitlines():
        a = word_after(line, 'inet')
        if a:
            return a
    return None


def ip_rules():
    """[{'priority': int, 'src': .., 'iif': .., 'fwmark': .., 'table': ..}] из `ip -4 rule show`."""
    keys = {'from': 'src', 'iif': 'iif', 'fwmark': 'fwmark', 'lookup': 'table', 'table': 'table'}
    out = []
    for line in run(['ip', '-4', 'rule', 'show']).splitlines():
        pref, _, rest = line.partition(':')
        if not pref.strip().isdigit():
            continue
        r, t, i = {'priority': int(pref)}, rest.split(), 0
        while i < len(t):
            if t[i] in keys and i + 1 < len(t):
                r[keys[t[i]]] = t[i + 1]
                i += 2
            else:
                i += 1
        out.append(r)
    return out


def wan_info(c):
    gw, ip, net = None, None, None
    try:
        for line in run(['ip', '-4', 'route', 'show', 'default', 'dev', c['wan_if']], False).splitlines():
            gw = word_after(line, 'via')
            if gw:
                break
        ip = ip4_addr(c['wan_if'])
        if ip:
            net = str(ipaddress.ip_interface(ip).network)
    except ValueError:
        ip = None
    return {'gateway': gw, 'address': ip, 'network': net}


def subnet_of(a, b):
    # network.subnet_of() появился только в Python 3.7 (в Ubuntu 18.04 — 3.6).
    a, b = ipaddress.ip_network(a), ipaddress.ip_network(b)
    return a.version == b.version and a.prefixlen >= b.prefixlen and a.network_address in b


def base_routes(c, table, w):
    t = str(table)
    run(['ip', 'route', 'replace', 'blackhole', 'default', 'table', t, 'metric', '32760'])
    run(['ip', 'route', 'replace', c['lan_net'], 'dev', c['lan_if'], 'table', t])
    run(['ip', 'route', 'replace', c['mgmt_net'], 'dev', c['mgmt_if'], 'table', t])
    for n in c.get('local_nets', []):
        if w['network'] and subnet_of(n, w['network']):
            run(['ip', 'route', 'replace', n, 'dev', c['wan_if'], 'table', t], False)
        elif w['gateway']:
            run(['ip', 'route', 'replace', n, 'via', w['gateway'], 'dev', c['wan_if'], 'table', t], False)


def table_of(h, ids):
    if h['mode'] == 'tunnel' and h.get('profile') in ids:
        return TABLE_TUNNEL + ids[h['profile']]
    if h['mode'] == 'direct':
        return TABLE_DIRECT
    return TABLE_BLOCK


def apply_rules(c, hs, ids):
    """Per-host source rules. The catch-all blackhole rule is installed first and never removed."""
    rules = ip_rules()
    have = {}
    for r in rules:
        have.setdefault(r.get('priority'), []).append(r)
    want = {PREF_CATCHALL: (None, TABLE_BLOCK)}
    for i, h in enumerate(hs):
        want[PREF_HOST + i] = (h['ip'], table_of(h, ids))
    if not any(r.get('iif') == c['lan_if'] and str(r.get('table')) == str(TABLE_BLOCK) for r in have.get(PREF_CATCHALL, [])):
        run(['ip', 'rule', 'add', 'pref', str(PREF_CATCHALL), 'iif', c['lan_if'], 'lookup', str(TABLE_BLOCK)])
    for pref, rs in have.items():
        if not isinstance(pref, int) or not PREF_HOST <= pref < PREF_HOST + 1000:
            continue
        ok = pref in want and len(rs) == 1 and rs[0].get('src') == want[pref][0] \
            and str(rs[0].get('table')) == str(want[pref][1]) and rs[0].get('iif') == c['lan_if']
        if not ok:
            for _ in rs:
                run(['ip', 'rule', 'del', 'pref', str(pref)], False)
        else:
            want.pop(pref)
    for pref, (src, table) in sorted(want.items()):
        if pref == PREF_CATCHALL:
            continue
        run(['ip', 'rule', 'add', 'pref', str(pref), 'from', src, 'iif', c['lan_if'], 'lookup', str(table)])


# ---------------------------------------------------------------- corporate OpenVPN (shared transport)
#
# The corporate VPN is never an exit for hosts. When enabled, the encrypted UDP
# of every AmneziaWG tunnel goes to its server through corp0 instead of WAN.
# If corp0 is down the underlay route is a blackhole: no fallback to direct.

CORP_PERMITTED = {
    'client', 'dev-type', 'proto', 'nobind', 'persist-key', 'persist-tun', 'remote-cert-tls', 'reneg-sec', 'cipher',
    'auth', 'ncp-ciphers', 'data-ciphers', 'data-ciphers-fallback', 'tls-version-min', 'tls-cipher',
    'tls-ciphersuites', 'tls-cert-profile', 'verb', 'mute', 'connect-timeout', 'connect-retry', 'resolv-retry',
    'explicit-exit-notify', 'key-direction', 'auth-nocache', 'comp-lzo', 'compress', 'allow-compression', 'sndbuf',
    'rcvbuf', 'tun-mtu', 'mssfix', 'fragment', 'keepalive', 'ping', 'ping-restart', 'verify-x509-name', 'ns-cert-type',
    'remote-random', 'server-poll-timeout', 'float', 'mute-replay-warnings', 'setenv', 'remote', 'auth-user-pass'}
CORP_DROPPED = {'dev', 'redirect-gateway', 'route', 'route-gateway', 'dhcp-option', 'block-outside-dns',
                'register-dns', 'route-method', 'route-delay', 'script-security', 'up', 'down', 'pull'}
CORP_TAGS = {'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'extra-certs'}


def openvpn_old():
    """OpenVPN 2.4 (Ubuntu 18.04) не знает data-ciphers и allow-compression из профилей 2.5+."""
    try:
        m = re.search(r'OpenVPN (\d+)\.(\d+)', run(['openvpn', '--version'], False))
    except OSError:
        return False
    return bool(m) and (int(m.group(1)), int(m.group(2))) < (2, 5)


def corp_build(text):
    """Sanitize a client .ovpn into a config that cannot run scripts or change routes."""
    lines, inline, remotes, auth = [], None, 0, False
    old = openvpn_old()
    for raw in text.splitlines():
        l = raw.strip()
        if inline:
            lines.append(l)
            if l == '</%s>' % inline:
                inline = None
            continue
        if not l or l[0] in '#;':
            continue
        m = re.match(r'^<([a-z0-9-]+)>$', l)
        if m:
            if m.group(1) not in CORP_TAGS:
                raise Fail('Блок <%s> в корпоративном профиле не поддерживается' % m.group(1))
            inline = m.group(1)
            lines.append(l)
            continue
        parts = l.split()
        k = parts[0]
        if k in CORP_DROPPED or (k == 'setenv' and len(parts) > 1 and parts[1].upper() != 'CLIENT_CERT'):
            continue
        if k not in CORP_PERMITTED:
            raise Fail('Параметр «%s» в корпоративном профиле не поддерживается' % k[:40])
        if k == 'remote':
            remotes += 1
        if k == 'auth-user-pass':
            auth = True
            continue
        if old and k in ('allow-compression', 'tls-cert-profile', 'tls-ciphersuites'):
            continue
        if old and k == 'data-ciphers':
            gcm = [x for x in (parts[1] if len(parts) > 1 else '').split(':') if x.upper().endswith('-GCM')]
            if gcm:
                lines.append('ncp-ciphers ' + ':'.join(gcm))
            continue
        if old and k == 'data-ciphers-fallback':
            l = 'cipher ' + ' '.join(parts[1:])
        if any(ord(ch) < 32 for ch in l):
            raise Fail('Недопустимые символы в корпоративном профиле')
        lines.append(l)
    if inline:
        raise Fail('Незакрытый блок <%s>' % inline)
    if not remotes:
        raise Fail('В корпоративном профиле нет remote')
    lines += ['dev ' + CORP_DEV, 'dev-type tun', 'route-nopull', 'pull-filter ignore "redirect-gateway"',
              'pull-filter ignore "route"', 'pull-filter ignore "dhcp-option"', 'pull-filter ignore "block-outside-dns"',
              'script-security 1', 'auth-nocache']
    if auth:
        lines.append('auth-user-pass ' + str(CORP_AUTH))
    return '\n'.join(lines) + '\n', auth


def corp_import(raw):
    if len(raw) > 1000000:
        raise Fail('Профиль слишком большой')
    conf, auth = corp_build(raw)
    CORP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    save(CORP_SRC, raw)
    save(CORP_CONF, conf)
    return 'Корпоративный профиль сохранён' + ('; нужен логин/пароль: vmgw corp credentials' if auth and not CORP_AUTH.exists() else '')


def corp_credentials(login, password):
    if not login or '\n' in login or '\n' in (password or '') or not password:
        raise Fail('Неверный логин или пароль')
    CORP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    save(CORP_AUTH, login + '\n' + password + '\n')
    return 'Учётные данные сохранены (только root)'


def corp_status():
    st = state()
    out = {'enabled': bool(st.get('corporate')), 'profile': CORP_SRC.is_file(), 'auth': CORP_AUTH.is_file(),
           'service': run(['systemctl', 'is-active', CORP_UNIT], False), 'address': None}
    if CORP_SRC.is_file():
        try:
            out['needs_auth'] = corp_build(CORP_SRC.read_text())[1]
        except Fail as e:
            out['error'] = str(e)
    a = ip4_addr(CORP_DEV)
    out['address'] = a.split('/')[0] if a else None
    return out


def corp_ready():
    return bool(corp_status()['address'])


def corp_set(enabled):
    st = state()
    if enabled:
        if not CORP_SRC.is_file():
            raise Fail('Сначала загрузите корпоративный профиль .ovpn')
        conf, auth = corp_build(CORP_SRC.read_text())
        if auth and not CORP_AUTH.is_file():
            raise Fail('Нужны логин и пароль корпоративного VPN')
        save(CORP_CONF, conf)
    st['corporate'] = bool(enabled)
    write_json(ETC / 'state.json', st)
    if enabled:
        run(['systemctl', 'restart', CORP_UNIT])
        for _ in range(45):
            if corp_ready() or run(['systemctl', 'is-active', CORP_UNIT], False) == 'failed':
                break
            time.sleep(1)
    else:
        run(['systemctl', 'stop', CORP_UNIT], False)
    msg = apply(restart='all')
    if enabled and not corp_ready():
        raise Fail('Корпоративный VPN не подключился; туннели хостов без выхода (прямого обхода нет). '
                   'Журнал: journalctl -u ' + CORP_UNIT)
    return ('Корпоративный транспорт включён. ' if enabled else 'Корпоративный транспорт выключен. ') + msg


# ---------------------------------------------------------------- tunnels

def link_exists(dev):
    return subprocess.run(['ip', 'link', 'show', dev], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def resolve_endpoint(ep):
    host, _, port = ep.rpartition(':')
    host = host.strip('[]')
    try:
        ipaddress.IPv4Address(host)
        return host, port
    except ValueError:
        pass
    try:
        addrs = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror:
        raise Fail('Не удалось разрешить ' + host)
    return addrs[0][4][0], port


def underlay(c, w):
    """Routes for the encrypted packets of all running tunnels (fwmark -> TABLE_UNDERLAY)."""
    t = str(TABLE_UNDERLAY)
    run(['ip', 'route', 'flush', 'table', t], False)
    run(['ip', 'route', 'replace', 'blackhole', 'default', 'table', t, 'metric', '32760'])
    rules = ip_rules()
    if not any(r.get('priority') == PREF_UNDERLAY for r in rules):
        run(['ip', 'rule', 'add', 'pref', str(PREF_UNDERLAY), 'fwmark', str(FWMARK), 'lookup', t])
    corp = state().get('corporate')
    for f in sorted(RUN.glob('awg*.endpoint')) if RUN.exists() else []:
        ip = f.read_text().strip()
        if corp:
            if corp_ready():
                run(['ip', 'route', 'replace', ip + '/32', 'dev', CORP_DEV, 'table', t], False)
        elif w['gateway']:
            run(['ip', 'route', 'replace', ip + '/32', 'via', w['gateway'], 'dev', c['wan_if'], 'table', t], False)


def tunnel_down(k):
    run(['systemctl', 'stop', 'vmgw-awg@%d.service' % k], False)
    run(['systemctl', 'reset-failed', 'vmgw-awg@%d.service' % k], False)
    run(['ip', 'link', 'del', 'awg%d' % k], False)
    run(['ip', 'route', 'del', 'default', 'dev', 'awg%d' % k, 'table', str(TABLE_TUNNEL + k)], False)
    for ext in ('conf', 'started', 'endpoint'):
        f = RUN / ('awg%d.%s' % (k, ext))
        if f.exists():
            f.unlink()


def tunnel_up(c, name, k, w):
    conf, info = load_profile(name)
    tunnel_down(k)
    ip, port = resolve_endpoint(info['endpoint'])
    # Pin the resolved address so the underlay route and awg use the same server,
    # and set FwMark in the config itself: the very first handshake must already
    # be marked, otherwise it would leave through the main table.
    lines = []
    for l in conf.splitlines():
        if l.lower().startswith('fwmark '):
            continue
        lines.append('Endpoint = %s:%s' % (ip, port) if l.startswith('Endpoint = ') else l)
        if l == '[Interface]':
            lines.append('FwMark = %d' % FWMARK)
    conf = '\n'.join(lines) + '\n'
    table = TABLE_TUNNEL + k
    base_routes(c, table, w)
    dev = 'awg%d' % k
    RUN.mkdir(mode=0o700, exist_ok=True)
    save(RUN / (dev + '.conf'), conf)
    save(RUN / (dev + '.endpoint'), ip)
    underlay(c, w)
    run(['systemctl', 'start', 'vmgw-awg@%d.service' % k])
    for _ in range(50):
        if link_exists(dev):
            break
        time.sleep(0.1)
    else:
        raise Fail('amneziawg-go не создал %s: journalctl -u vmgw-awg@%d' % (dev, k))
    run([AWG, 'setconf', dev, str(RUN / (dev + '.conf'))])
    run(['ip', 'addr', 'add', info['address'], 'dev', dev])
    run(['ip', 'link', 'set', dev, 'mtu', str(info['mtu']), 'up'])
    run(['ip', 'route', 'replace', 'default', 'dev', dev, 'table', str(table), 'metric', '10'])
    save(RUN / (dev + '.started'), str(int(time.time())))


def tunnel_stats(k):
    dev = 'awg%d' % k
    out = {'dev': dev, 'up': link_exists(dev), 'handshake_age': None, 'endpoint': None, 'rx': 0, 'tx': 0}
    if not out['up']:
        return out
    stamps = [int(x.split()[1]) for x in run([AWG, 'show', dev, 'latest-handshakes'], False).splitlines() if len(x.split()) == 2]
    if stamps and max(stamps) > 0:
        out['handshake_age'] = int(time.time()) - max(stamps)
    for x in run([AWG, 'show', dev, 'endpoints'], False).splitlines():
        if len(x.split()) == 2:
            out['endpoint'] = x.split()[1]
    for x in run([AWG, 'show', dev, 'transfer'], False).splitlines():
        p = x.split()
        if len(p) == 3:
            out['rx'] += int(p[1])
            out['tx'] += int(p[2])
    return out


def wanted_tunnels(hs, ids):
    return sorted({h['profile'] for h in hs if h['mode'] == 'tunnel' and h.get('profile') in ids})


def running_tunnels():
    out = set()
    for line in run(['ip', '-o', 'link', 'show'], False).splitlines():
        m = re.match(r'^\d+: awg(\d+)[:@]', line)
        if m:
            out.add(int(m.group(1)))
    return out


# ---------------------------------------------------------------- apply / check

def apply(restart=None):
    """Bring everything to the stored state. restart: profile name or 'all'."""
    c = cfg()
    hs, fw = hosts(), forwards()
    ids = {n: m['id'] for n, m in profiles().items()}
    w = wan_info(c)
    write_dhcp(hs)
    apply_firewall(c, hs, fw, ids)
    for t in [TABLE_BLOCK, TABLE_DIRECT] + [TABLE_TUNNEL + k for k in ids.values()]:
        base_routes(c, t, w)
    if w['gateway']:
        run(['ip', 'route', 'replace', 'default', 'via', w['gateway'], 'dev', c['wan_if'], 'table', str(TABLE_DIRECT), 'metric', '10'])
    else:
        run(['ip', 'route', 'del', 'default', 'table', str(TABLE_DIRECT), 'metric', '10'], False)
    apply_rules(c, hs, ids)
    underlay(c, w)
    want = wanted_tunnels(hs, ids)
    for k in running_tunnels() - {ids[n] for n in want}:
        tunnel_down(k)
    msgs, errors = [], []
    for name in want:
        k = ids[name]
        if restart in ('all', name) or not link_exists('awg%d' % k) or not (RUN / ('awg%d.started' % k)).exists():
            if not w['gateway']:
                errors.append('%s: WAN ещё не получил шлюз, туннель поднимется позже' % name)
                continue
            try:
                tunnel_up(c, name, k, w)
                msgs.append('туннель awg%d поднят: %s' % (k, name))
            except Exception as e:
                tunnel_down(k)
                errors.append('%s: %s' % (name, e if isinstance(e, Fail) else type(e).__name__))
    if errors:
        raise Fail('; '.join(msgs + errors))
    return 'Применено' + (': ' + '; '.join(msgs) if msgs else '')


def check():
    """Watchdog (timer): restart missing tunnels and tunnels without a fresh handshake."""
    c = cfg()
    hs = hosts()
    ids = {n: m['id'] for n, m in profiles().items()}
    if state().get('corporate'):
        if run(['systemctl', 'is-active', CORP_UNIT], False) not in ('active', 'activating'):
            run(['systemctl', 'restart', CORP_UNIT], False)
        # corp0 may have come back with the same or a new address: refresh routes.
        underlay(c, wan_info(c))
    restart = []
    for name in wanted_tunnels(hs, ids):
        k = ids[name]
        st = tunnel_stats(k)
        try:
            started = int((RUN / ('awg%d.started' % k)).read_text())
        except (FileNotFoundError, ValueError):
            started = 0
        if not st['up']:
            restart.append(name)
        elif time.time() - started > 180 and (st['handshake_age'] is None or st['handshake_age'] > 300):
            restart.append(name)
    if not restart and set(running_tunnels()) >= {ids[n] for n in wanted_tunnels(hs, ids)}:
        return 'OK'
    w = wan_info(c)
    out = []
    for name in restart:
        if not w['gateway']:
            break
        try:
            tunnel_up(c, name, ids[name], w)
            out.append('перезапущен ' + name)
        except Exception as e:
            tunnel_down(ids[name])
            out.append('%s: %s' % (name, e if isinstance(e, Fail) else type(e).__name__))
    return '; '.join(out) or 'OK'


def stop_all():
    for k in running_tunnels():
        tunnel_down(k)
    return 'Все туннели остановлены; хосты в режиме tunnel без выхода'


# ---------------------------------------------------------------- status

def status():
    c = cfg()
    hs = hosts()
    ids = {n: m['id'] for n, m in profiles().items()}
    neigh = neighbours(c)
    ls = leases()
    lease_by_mac = {l['mac']: l for l in ls}
    known = {h['mac'] for h in hs}
    tunnels = []
    for name in sorted(ids):
        st = tunnel_stats(ids[name])
        st.update(profile=name, id=ids[name],
                  hosts=[h['name'] for h in hs if h['mode'] == 'tunnel' and h.get('profile') == name])
        if st['up'] or st['hosts']:
            tunnels.append(st)
    host_list = []
    for h in hs:
        item = dict(h)
        item['neigh'] = neigh.get(h['ip'], '')
        item['online'] = item['neigh'] in ('REACHABLE', 'STALE', 'DELAY', 'PROBE')
        item['hostname'] = lease_by_mac.get(h['mac'], {}).get('hostname', '')
        item['forwards'] = [f for f in forwards() if f['host'] == h['name']]
        host_list.append(item)
    return {
        'router': {'mgmt_addr': c['mgmt_addr'].split('/')[0], 'ssh_port': c['ssh_port'], 'panel_port': c['panel_port'],
                   'lan_net': c['lan_net'], 'local_nets': c.get('local_nets', []), 'wan': wan_info(c)},
        'tunnels': tunnels,
        'hosts': host_list,
        'unknown': [l for l in ls if l['mac'] not in known],
        'forwards': forwards(),
        'profiles': profile_list(),
        'corporate': corp_status(),
    }


def print_status():
    s = status()
    r = s['router']
    print('Роутер: mgmt %s (ssh %d, панель http://%s:%d), WAN %s шлюз %s' % (
        r['mgmt_addr'], r['ssh_port'], r['mgmt_addr'], r['panel_port'], r['wan']['address'], r['wan']['gateway']))
    cs = s['corporate']
    print('Транспорт туннелей: ' + ('корпоративный VPN (%s, адрес %s)' % (cs['service'], cs['address']) if cs['enabled'] else 'напрямую через WAN'))
    print('\nТуннели:')
    for t in s['tunnels']:
        age = '%d с назад' % t['handshake_age'] if t['handshake_age'] is not None else 'не было'
        print('  %-6s %-30s %-5s рукопожатие: %-12s хосты: %s' % (t['dev'], t['profile'], 'up' if t['up'] else 'DOWN', age, ', '.join(t['hosts'])))
    print('\nХосты:')
    for h in s['hosts']:
        print('  %-16s %-15s %s  %-8s %s' % (h['name'], h['ip'], h['mac'], 'online' if h['online'] else '-', describe(h)))
    for u in s['unknown']:
        print('  ? без профиля %s %s %s (без интернета; добавьте: vmgw host add ИМЯ %s)' % (u['ip'], u['mac'], u['hostname'], u['mac']))
    print('\nПроброс портов:')
    for f in s['forwards']:
        print('  %s %d → %s:%d (%s)' % (f['proto'], f['port'], f['host'], f['to_port'], f['source']))
    print('\nПрофили:')
    for p in s['profiles']:
        print('  awg%-3d %-30s %s' % (p['id'], p['name'], p.get('endpoint') if p['valid'] else 'ОШИБКА: ' + p.get('error', '')))


# ---------------------------------------------------------------- panel password

def hash_password(pw):
    salt = secrets.token_bytes(16)
    it = 300000
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, it)
    return 'pbkdf2_sha256$%d$%s$%s' % (it, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def panel_password():
    pw = getpass.getpass('Новый пароль панели: ')
    if len(pw) < 8:
        raise Fail('Минимум 8 символов')
    if getpass.getpass('Повторите: ') != pw:
        raise Fail('Пароли не совпадают')
    save(PANEL_PASS, hash_password(pw) + '\n', 0o640)
    run(['chgrp', 'vmgw-web', str(PANEL_PASS)], False)
    run(['systemctl', 'try-restart', 'vmgw-web.service'], False)
    return 'Пароль панели сохранён'


# ---------------------------------------------------------------- API for the web panel

def api():
    """Single sudo entry point for the panel: JSON request on stdin, JSON reply on stdout."""
    try:
        req = json.loads(sys.stdin.read(3 * 1024 * 1024))
    except Exception:
        raise Fail('Неверный запрос')
    if not isinstance(req, dict):
        raise Fail('Неверный запрос')
    a = req.get('action')
    s = lambda k: req.get(k) if isinstance(req.get(k), str) else None
    if a == 'status':
        return status()
    if a == 'apply':
        return apply()
    if a == 'restart':
        name = s('profile') or 'all'
        if name != 'all':
            profile_id(name)
        return apply(restart=name)
    if a == 'import':
        msg = import_profile(s('name'), s('data') or '')
        return msg
    if a == 'profile-delete':
        msg = delete_profile(s('name'))
        apply()
        return msg
    if a == 'host-add':
        msg = host_add(s('name'), s('mac'), s('ip') or None)
        apply()
        return msg
    if a == 'host-set':
        local = req.get('local')
        msg = host_set(s('name'), s('mode'), s('profile'), local if isinstance(local, bool) else None)
        apply()
        return msg
    if a == 'host-del':
        msg = host_del(s('name'))
        apply()
        return msg
    if a == 'fwd-add':
        msg = fwd_add(s('proto'), req.get('port'), s('host'), req.get('to_port'), s('source') or 'mgmt')
        apply()
        return msg
    if a == 'fwd-del':
        msg = fwd_del(s('proto'), req.get('port'))
        apply()
        return msg
    if a == 'corp-set':
        return corp_set(req.get('enabled') is True)
    if a == 'corp-import':
        return corp_import(s('data') or '')
    if a == 'corp-credentials':
        return corp_credentials(s('login'), s('password'))
    raise Fail('Неизвестное действие')


USAGE = '''vmgw — управление шлюзом
  vmgw status                          состояние туннелей, хостов, пробросов
  vmgw apply                           применить сохранённую конфигурацию
  vmgw restart [ПРОФИЛЬ]               перезапустить туннели (все или один)
  vmgw stop                            остановить все туннели (хосты остаются без выхода)
  vmgw profile list
  vmgw profile import ФАЙЛ [ИМЯ.vpn]   ФАЙЛ "-" = stdin
  vmgw profile delete ИМЯ
  vmgw host list
  vmgw host add ИМЯ MAC [IP]
  vmgw host set ИМЯ tunnel ПРОФИЛЬ | direct | blocked
  vmgw host local ИМЯ on|off           доступ к домашней сети за WAN (local_nets)
  vmgw host del ИМЯ
  vmgw fwd list
  vmgw fwd add tcp|udp ВНЕШНИЙ_ПОРТ ХОСТ ПОРТ [mgmt|local]
  vmgw fwd del tcp|udp ВНЕШНИЙ_ПОРТ
  vmgw leases                          DHCP-аренды (в т.ч. ВМ без профиля)
  vmgw corp import ФАЙЛ.ovpn           корпоративный OpenVPN (общий транспорт)
  vmgw corp credentials                логин/пароль корпоративного VPN
  vmgw corp on|off                     все туннели через корпоративный VPN / напрямую
  vmgw panel-password'''


def main(argv):
    if sys.getfilesystemencoding().lower() != 'utf-8' and os.environ.get('LC_ALL') != 'C.UTF-8':
        # Python 3.6 (Ubuntu 18.04) без локали работает в ASCII: имена профилей не по-латински не открыть.
        os.execve(sys.executable, [sys.executable, '-I', os.path.abspath(sys.argv[0])] + argv,
                  dict(os.environ, LC_ALL='C.UTF-8'))
    if os.geteuid() != 0:
        raise Fail('Запускайте через sudo')
    ETC.mkdir(mode=0o700, exist_ok=True)
    global apply
    if argv and argv[0] == '--no-apply':
        # Used by router-install.sh before the first reboot: the interfaces get
        # their final names (mgmt0/lan0/wan0) only after it.
        argv = argv[1:]
        apply = lambda restart=None: 'Применится после перезагрузки'
    cmd = argv[0] if argv else 'status'
    sub = argv[1] if len(argv) > 1 else None
    args = argv[2:]
    if cmd in ('help', '-h', '--help'):
        print(USAGE)
        return
    lock = open(str(ETC / 'lock'), 'w')
    fcntl.flock(lock, fcntl.LOCK_EX)
    if cmd == 'api':
        try:
            out = api()
            print(json.dumps({'ok': True, 'output': out if isinstance(out, str) else '', 'data': out if not isinstance(out, str) else None}, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({'ok': False, 'output': str(e) if isinstance(e, Fail) else 'Внутренняя ошибка: ' + type(e).__name__}, ensure_ascii=False))
        return
    if cmd == 'status':
        print_status()
    elif cmd == 'apply':
        print(apply())
    elif cmd == 'restart':
        if sub:
            profile_id(sub)
        print(apply(restart=sub or 'all'))
    elif cmd == 'check':
        r = check()
        if r != 'OK':
            print(r)
    elif cmd == 'stop':
        print(stop_all())
    elif cmd == 'profile' and sub == 'list':
        for p in profile_list():
            print('awg%-3d %-30s %s  хосты: %s' % (p['id'], p['name'], p.get('endpoint') if p['valid'] else 'ОШИБКА: ' + p.get('error', ''), ', '.join(p['used_by']) or '-'))
    elif cmd == 'profile' and sub == 'import' and len(args) in (1, 2):
        src = args[0]
        name = args[1] if len(args) == 2 else (None if src == '-' else Path(src).name)
        if not name:
            raise Fail('Укажите имя профиля')
        raw = sys.stdin.read(2000001) if src == '-' else Path(src).read_text(errors='replace')
        print(import_profile(name, raw))
    elif cmd == 'profile' and sub == 'delete' and len(args) == 1:
        print(delete_profile(args[0]))
        print(apply())
    elif cmd == 'host' and sub == 'list':
        for h in hosts():
            print('%-16s %-15s %s  %s' % (h['name'], h['ip'], h['mac'], describe(h)))
    elif cmd == 'host' and sub == 'add' and len(args) in (2, 3):
        print(host_add(args[0], args[1], args[2] if len(args) == 3 else None))
        print(apply())
    elif cmd == 'host' and sub == 'set' and len(args) >= 2:
        if args[1] == 'tunnel' and len(args) == 3:
            print(host_set(args[0], 'tunnel', args[2]))
        elif args[1] in ('direct', 'blocked') and len(args) == 2:
            print(host_set(args[0], args[1]))
        else:
            raise Fail(USAGE)
        print(apply())
    elif cmd == 'host' and sub == 'local' and len(args) == 2 and args[1] in ('on', 'off'):
        print(host_set(args[0], local=args[1] == 'on'))
        print(apply())
    elif cmd == 'host' and sub == 'del' and len(args) == 1:
        print(host_del(args[0]))
        print(apply())
    elif cmd == 'fwd' and sub == 'list':
        for f in forwards():
            print('%s %d → %s:%d (%s)' % (f['proto'], f['port'], f['host'], f['to_port'], f['source']))
    elif cmd == 'fwd' and sub == 'add' and len(args) in (4, 5):
        print(fwd_add(args[0], args[1], args[2], args[3], args[4] if len(args) == 5 else 'mgmt'))
        print(apply())
    elif cmd == 'fwd' and sub == 'del' and len(args) == 2:
        print(fwd_del(args[0], args[1]))
        print(apply())
    elif cmd == 'leases':
        known = {h['mac']: h['name'] for h in hosts()}
        for l in leases():
            print('%-15s %s  %-20s %s' % (l['ip'], l['mac'], l['hostname'], known.get(l['mac'], 'не зарегистрирован (без интернета)')))
    elif cmd == 'corp' and sub == 'import' and len(args) == 1:
        print(corp_import(Path(args[0]).read_text(errors='replace')))
    elif cmd == 'corp' and sub == 'credentials' and not args:
        login = input('Логин корпоративного VPN: ').strip()
        print(corp_credentials(login, getpass.getpass('Пароль: ')))
    elif cmd == 'corp' and sub in ('on', 'off') and not args:
        print(corp_set(sub == 'on'))
    elif cmd == 'panel-password':
        print(panel_password())
    elif cmd == 'render':
        # Write (but do not load) the ruleset and the DHCP reservations; nftables.service loads it at boot.
        text = ruleset(cfg(), hosts(), forwards(), {n: m['id'] for n, m in profiles().items()})
        save(RULESET, text)
        run(['nft', '-c', '-f', str(RULESET)])
        write_dhcp(hosts())
        print('Правила записаны: %s' % RULESET)
    else:
        raise Fail(USAGE)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as e:
        # Never print profile contents or raw tracebacks: they may contain keys.
        print('ОШИБКА: ' + (str(e) if isinstance(e, Fail) else type(e).__name__), file=sys.stderr)
        sys.exit(1)
