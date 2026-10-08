# Выполняется ВНУТРИ Windows Sandbox (LogonCommand).
# Порядок важен: сначала kill switch, потом туннель, потом приложение.
$ErrorActionPreference = 'Stop'
$Root = 'C:\VpnSandbox'
$RunDir = "$Root\run"
$Work = 'C:\ProgramData\VpnSandbox'
New-Item -ItemType Directory -Force $Work | Out-Null
Start-Transcript -Path "$RunDir\bootstrap.log" -Force | Out-Null
$Host.UI.RawUI.WindowTitle = 'VPN Sandbox'

function Say($msg, $color = 'Gray') { Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $msg) -ForegroundColor $color }
function Fail($msg) {
    Say $msg 'Red'
    Say 'Приложение НЕ запущено. Сеть в песочнице заблокирована. Окно можно закрыть.' 'Red'
    Stop-Transcript | Out-Null
    Read-Host 'Enter — закрыть'
    exit 1
}

try {
    $cfg = Get-Content -Raw "$RunDir\run.json" | ConvertFrom-Json

    # ---------- 1. Kill switch ----------
    Say 'Включаю kill switch (весь исходящий трафик заблокирован)...' 'Yellow'
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -AllowLocalFirewallRules True
    # Штатные разрешающие правила (DNS-клиент, Teredo, приложения и т.п.) обходят DefaultOutbound=Block — выключаем все
    Get-NetFirewallRule -Direction Outbound -Action Allow | Where-Object Enabled -eq 'True' | Disable-NetFirewallRule
    Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object Enabled -eq 'True' | Disable-NetFirewallRule

    $g = 'VpnSandbox'
    foreach ($ep in $cfg.Endpoints) {
        New-NetFirewallRule -Group $g -DisplayName "VPN endpoint $($ep.Ip):$($ep.Port)" -Direction Outbound -Action Allow `
            -RemoteAddress $ep.Ip -Protocol $ep.Proto -RemotePort $ep.Port | Out-Null
    }
    # Продление DHCP-аренды внутренней NAT-сети песочницы
    New-NetFirewallRule -Group $g -DisplayName 'DHCP' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
    Say "Разрешено только: $(($cfg.Endpoints | ForEach-Object { "$($_.Proto) $($_.Ip):$($_.Port)" }) -join ', ')" 'Green'

    # Секреты забираем из общей папки и удаляем оттуда
    $confPath = Join-Path $Work $cfg.TunnelFile
    Copy-Item "$RunDir\$($cfg.TunnelFile)" $confPath -Force
    Remove-Item "$RunDir\$($cfg.TunnelFile)" -Force

    # ---------- 2. Клиент и туннель ----------
    function Install-Msi($pattern) {
        $msi = Get-ChildItem "$Root\tools\$pattern" | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $msi) { Fail "Нет установщика $pattern в папке tools. Запустите Setup.cmd на хосте." }
        Say "Устанавливаю $($msi.Name) (только внутри песочницы)..."
        $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$($msi.FullName)`"", '/qn', '/norestart' -Wait -PassThru
        if ($p.ExitCode -notin 0, 3010) { Fail "msiexec вернул код $($p.ExitCode)" }
    }

    if ($cfg.Kind -eq 'awg') {
        Install-Msi 'amneziawg-amd64-*.msi'
        Get-Process amneziawg -ErrorAction SilentlyContinue | Stop-Process -Force  # GUI, если стартовал после установки
        $awg = @("$env:ProgramFiles\AmneziaWG\amneziawg.exe") + (Get-ChildItem "$env:ProgramFiles\*\amneziawg.exe" -ErrorAction SilentlyContinue).FullName |
            Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if (-not $awg) { Fail 'Не найден amneziawg.exe после установки' }
        Say 'Поднимаю туннель AmneziaWG...'
        & $awg /installtunnelservice $confPath
        $alias = $cfg.TunnelName
        $timeout = 60
    } else {
        Install-Msi 'OpenVPN-*.msi'
        $ovpn = "$env:ProgramFiles\OpenVPN\bin\openvpn.exe"
        if (-not (Test-Path $ovpn)) { Fail 'Не найден openvpn.exe после установки' }
        $before = @(Get-NetAdapter -IncludeHidden | ForEach-Object ifIndex)
        Say 'Запускаю OpenVPN в отдельном окне. Если профиль просит логин/пароль — введите их там.' 'Cyan'
        Start-Process $ovpn -ArgumentList '--config', "`"$confPath`"", '--redirect-gateway', 'def1', '--block-outside-dns' -WorkingDirectory $Work
        $alias = $null
        $timeout = 300
    }

    # ---------- 3. Ждём туннель ----------
    $deadline = (Get-Date).AddSeconds($timeout)
    $ip = $null
    while ((Get-Date) -lt $deadline) {
        if (-not $alias) {
            $a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.ifIndex -notin $before -or $_.InterfaceDescription -match 'OpenVPN|TAP-Windows|Wintun') } | Select-Object -First 1
            if ($a) { $alias = $a.Name }
        }
        if ($alias) {
            $ip = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -notlike '169.254.*'
            if ($ip) { break }
        }
        Start-Sleep 1
    }
    if (-not $ip) { Fail "Туннель не поднялся за $timeout с." }
    New-NetFirewallRule -Group $g -DisplayName "Tunnel $alias" -Direction Outbound -Action Allow -InterfaceAlias $alias | Out-Null
    Say "Туннель '$alias' поднят, адрес $($ip.IPAddress -join ', ')" 'Green'

    # ---------- 4. Проверка ----------
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $pub = $null
    for ($i = 0; $i -lt 15 -and -not $pub; $i++) {
        try { $pub = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5).ToString().Trim() } catch { Start-Sleep 2 }
    }
    if (-not $pub) { Fail 'Через туннель нет доступа в интернет (проверьте профиль/сервер).' }
    Say "Внешний IP песочницы: $pub" 'Green'
    if ($cfg.HostPublicIp) {
        if ($pub -eq $cfg.HostPublicIp) { Say "ВНИМАНИЕ: совпадает с IP хоста ($($cfg.HostPublicIp)). Возможно, хост сам сидит на этом же VPN." 'Yellow' }
        else { Say "IP хоста: $($cfg.HostPublicIp) — отличается, трафик идёт через VPN." 'Green' }
    }

    # ---------- 5. Приложение ----------
    if ($cfg.Exe) {
        $wd = Split-Path $cfg.Exe
        if ($cfg.DropAdmin) {
            # Basic User: токен без прав администратора — приложение не сможет выключить firewall
            $inner = '"' + $cfg.Exe + '"' + $(if ($cfg.Args) { ' ' + $cfg.Args } else { '' })
            Say "Запускаю без прав администратора: $inner" 'Cyan'
            Start-Process runas.exe -ArgumentList '/trustlevel:0x20000', ('"' + $inner.Replace('"', '\"') + '"') -WorkingDirectory $wd
        } else {
            Say "Запускаю с правами администратора: $($cfg.Exe) $($cfg.Args)" 'Yellow'
            if ($cfg.Args) { Start-Process $cfg.Exe -ArgumentList $cfg.Args -WorkingDirectory $wd } else { Start-Process $cfg.Exe -WorkingDirectory $wd }
        }
    } else {
        Say 'exe не указан — открываю общую папку. Всё, что запустите в песочнице, ходит только через VPN.' 'Cyan'
        Start-Process explorer.exe "$env:USERPROFILE\Desktop\Shared"
    }
    Stop-Transcript | Out-Null
} catch {
    Fail "Ошибка: $($_.Exception.Message)"
}

# ---------- Мониторинг ----------
Say 'Мониторинг туннеля (окно можно свернуть). При падении туннеля сеть просто пропадёт — утечки не будет.'
$last = $null
while ($true) {
    Start-Sleep 15
    $up = (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue).Status -eq 'Up'
    $state = if ($up) { 'UP' } else { 'DOWN' }
    if ($state -ne $last) { Say "Туннель: $state" $(if ($up) { 'Green' } else { 'Red' }); $last = $state }
}
