# Разбор VPN-профилей: AmneziaWG/WireGuard (.conf), OpenVPN (.ovpn), экспорт Amnezia (vpn://)

function ConvertFrom-AmneziaExport {
    # vpn://<base64url( qCompress(json) )>, qCompress = 4 байта длины (BE) + zlib-поток
    param([Parameter(Mandatory)][string]$Text)
    $s = $Text.Trim() -replace '^vpn://', '' -replace '-', '+' -replace '_', '/'
    while ($s.Length % 4) { $s += '=' }
    [byte[]]$b = [Convert]::FromBase64String($s)
    # 4 байта длины + 2 байта заголовка zlib, дальше raw deflate
    $ms = New-Object System.IO.MemoryStream -ArgumentList @(, $b[6..($b.Length - 1)])
    $z = New-Object System.IO.Compression.DeflateStream -ArgumentList $ms, ([System.IO.Compression.CompressionMode]::Decompress)
    $json = (New-Object System.IO.StreamReader -ArgumentList $z, ([Text.Encoding]::UTF8)).ReadToEnd()
    $json | ConvertFrom-Json
}

function Get-VpnProfile {
    # Возвращает @{ Kind = 'awg'|'openvpn'; Name; Text } — готовый к запуску конфиг
    param([Parameter(Mandatory)][string]$Path)
    $Path = (Resolve-Path -LiteralPath $Path).Path
    $raw = [IO.File]::ReadAllText($Path)
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    # Имя туннеля = имя адаптера/службы: только латиница, цифры, -_ ; до 32 символов
    $safe = ($name -replace '[^A-Za-z0-9_-]', '')
    if (-not $safe) { $safe = 'vpn' }
    $safe = $safe.Substring(0, [Math]::Min(32, $safe.Length))

    if ($raw.TrimStart().StartsWith('vpn://')) {
        $j = ConvertFrom-AmneziaExport $raw
        $order = @($j.defaultContainer) + @($j.containers | ForEach-Object { $_.container })
        foreach ($cname in $order | Select-Object -Unique) {
            $c = $j.containers | Where-Object { $_.container -eq $cname } | Select-Object -First 1
            if (-not $c) { continue }
            foreach ($p in $c.PSObject.Properties | Where-Object Name -ne 'container') {
                $lc = $p.Value.last_config
                if (-not $lc) { continue }
                $cfg = ($lc | ConvertFrom-Json).config
                if (-not $cfg) { continue }
                # В экспорте Amnezia хост/DNS иногда оставлены плейсхолдерами
                $cfg = $cfg -replace '\$PRIMARY_DNS', $j.dns1 -replace '\$SECONDARY_DNS', $j.dns2
                switch -Regex ($p.Name) {
                    '^(awg|wireguard)$' { return @{ Kind = 'awg'; Name = $safe; Text = $cfg; Source = "amnezia:$cname" } }
                    '^openvpn$'         { return @{ Kind = 'openvpn'; Name = $safe; Text = $cfg; Source = "amnezia:$cname" } }
                }
            }
        }
        $kinds = ($j.containers | ForEach-Object { $_.container }) -join ', '
        throw "В экспорте Amnezia нет поддерживаемого протокола (есть: $kinds). Поддерживаются AWG/WireGuard и OpenVPN."
    }
    if ($raw -match '(?m)^\s*\[Interface\]') { return @{ Kind = 'awg'; Name = $safe; Text = $raw; Source = 'conf' } }
    if ($raw -match '(?m)^\s*(client|remote|dev)\b') { return @{ Kind = 'openvpn'; Name = $safe; Text = $raw; Source = 'ovpn' } }
    throw "Не удалось определить формат профиля: $Path"
}

function Get-VpnEndpoint {
    # Список @{ Host; Port; Proto } серверов профиля
    param([Parameter(Mandatory)]$VpnProfile)
    if ($VpnProfile.Kind -eq 'awg') {
        foreach ($m in [regex]::Matches($VpnProfile.Text, '(?m)^\s*Endpoint\s*=\s*\[?([^\]\s]+?)\]?:(\d+)\s*$')) {
            @{ Host = $m.Groups[1].Value; Port = [int]$m.Groups[2].Value; Proto = 'UDP' }
        }
    } else {
        $defProto = 'UDP'; $defPort = 1194
        if ($VpnProfile.Text -match '(?m)^\s*proto\s+(\w+)') { $defProto = if ($Matches[1] -like 'tcp*') { 'TCP' } else { 'UDP' } }
        if ($VpnProfile.Text -match '(?m)^\s*port\s+(\d+)') { $defPort = [int]$Matches[1] }
        foreach ($m in [regex]::Matches($VpnProfile.Text, '(?m)^\s*remote\s+(\S+)(?:\s+(\d+))?(?:\s+(\w+))?')) {
            $port = if ($m.Groups[2].Success) { [int]$m.Groups[2].Value } else { $defPort }
            $proto = if ($m.Groups[3].Success) { if ($m.Groups[3].Value -like 'tcp*') { 'TCP' } else { 'UDP' } } else { $defProto }
            @{ Host = $m.Groups[1].Value; Port = $port; Proto = $proto }
        }
    }
}
