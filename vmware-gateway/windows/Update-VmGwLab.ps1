<#
.SYNOPSIS
  Обновляет софт vmgw во всех запущенных ВМ лабораторий до версии этого комплекта.

.DESCRIPTION
  1. Находит запущенные ВМ (vmrun list) и лаборатории, к которым они относятся (lab.json).
  2. Обновляет папку комплекта лаборатории (общая папка «vmgw» в ВМ).
  3. Сравнивает версию комплекта с установленной в каждой ВМ (/usr/local/lib/vmgw/VERSION).
  4. Отличающиеся ВМ обновляет по SSH (вход по ключу): копирует комплект во временную папку
     и запускает update.sh через sudo — пароль sudo вводится в этом окне.
     Сначала роутер, затем ведомые ВМ (напрямую или через роутер).
  Хосты, профили, пробросы и пароль панели при обновлении не меняются.

.EXAMPLE
  .\Update-VmGwLab.ps1
.EXAMPLE
  .\Update-VmGwLab.ps1 -CheckOnly
  Только показать версии, ничего не менять.
.EXAMPLE
  .\Update-VmGwLab.ps1 -RebuildAwg
  Заодно пересобрать AmneziaWG на роутере (туннели переподнимутся).
#>
[CmdletBinding()]
param(
    [string[]]$LabDir,
    [string]$User,
    [string]$ClientUser,
    [switch]$CheckOnly,
    [switch]$Force,
    [switch]$RebuildAwg,
    [switch]$RouterOnly,
    [switch]$Json          # для окна vpnsbx-ui: без вопросов, итог строкой VMGW-JSON:{...}
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
. (Join-Path $PSScriptRoot 'VmGwCommon.ps1')

$StampRe = '^\S+\+[0-9a-f]{12}$'
$SshOpts = @('-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ServerAliveInterval=15')

function Invoke-Quiet([string]$exe, [string[]]$a) {
    # Вывод и stderr перехватываются; ошибки нативной команды не превращаются в исключения.
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = @(& $exe @a 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $old }
    [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
}

function Get-Prop($o, [string]$n) { $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }

function Save-Lab($lab) {
    [IO.File]::WriteAllText((Join-Path $lab.LabDir 'lab.json'), ($lab | ConvertTo-Json -Depth 5), $Utf8)
}

function Ask-User($lab, [string]$prop, [string]$given, [string]$question, [string]$default) {
    $u = $given
    if (-not $u) { $u = Get-Prop $lab $prop }
    if (-not $u -and $Json) { $u = $default }
    if (-not $u) {
        $u = Read-Host "$question [$default]"
        if (-not $u) { $u = $default }
    }
    if ($u -notmatch '^[a-z_][a-z0-9_.-]{0,31}$') { Fail "Неверное имя пользователя: $u" }
    if ((Get-Prop $lab $prop) -ne $u) { $lab | Add-Member -NotePropertyName $prop -NotePropertyValue $u -Force; Save-Lab $lab }
    $u
}

# Конечная точка SSH: адрес, порт и доп. параметры (ProxyJump).
function New-Endpoint([string]$user, [string]$addr, [int]$port, [string[]]$extra) {
    [pscustomobject]@{ Target = "$user@$addr"; Port = "$port"; Extra = @($extra) }
}

function Get-RemoteStamp($ep) {
    $r = Invoke-Quiet $Ssh (@('-n', '-p', $ep.Port, '-o', 'BatchMode=yes') + $SshOpts + $ep.Extra + @($ep.Target, 'cat /usr/local/lib/vmgw/VERSION 2>/dev/null || echo NONE'))
    $line = @($r.Out | Where-Object { $_ -match $StampRe -or $_ -eq 'NONE' }) | Select-Object -Last 1
    if ($r.Code -eq 0 -and $line) {
        return [pscustomobject]@{ Ok = $true; Stamp = $(if ($line -eq 'NONE') { 'не записана' } else { $line }); Error = '' }
    }
    $msg = ($r.Out | Where-Object { $_ -and $_ -notmatch '^Warning: Permanently added' }) -join ' '
    if ($msg -match 'IDENTIFICATION HAS CHANGED') {
        $msg = "сменился ключ хоста (ВМ переустановлена?). Если это ожидаемо: ssh-keygen -R `"[$($ep.Target.Split('@')[1])]:$($ep.Port)`""
    } elseif ($msg -match 'Permission denied') {
        $msg = 'нет входа по ключу SSH'
    } elseif (-not $msg) { $msg = "ssh завершился с кодом $($r.Code)" }
    [pscustomobject]@{ Ok = $false; Stamp = ''; Error = $msg }
}

function Invoke-GuestUpdate($lab, $ep, [string]$role) {
    $base = @('-n', '-p', $ep.Port, '-o', 'BatchMode=yes') + $SshOpts + $ep.Extra
    $r = Invoke-Quiet $Ssh ($base + @($ep.Target, 'mktemp -d /tmp/vmgw-update.XXXXXXXX'))
    $dir = @($r.Out | Where-Object { $_ -match '^/tmp/vmgw-update\.[A-Za-z0-9]+$' }) | Select-Object -First 1
    if (-not $dir) { return "не удалось создать временную папку: $($r.Out -join ' ')" }
    # Относительный путь: scp не путает «C:» в локальном пути с именем хоста.
    Push-Location -LiteralPath $lab.LabDir
    try { $r = Invoke-Quiet $Scp (@('-q', '-r', '-P', $ep.Port, '-o', 'BatchMode=yes') + $SshOpts + $ep.Extra + @('kit', "$($ep.Target):$dir/")) }
    finally { Pop-Location }
    if ($r.Code -ne 0) { return "не удалось скопировать комплект: $($r.Out -join ' ')" }
    $flags = $role
    if ($role -eq 'router' -and $RebuildAwg) { $flags += ' --rebuild-awg' }
    if ($Force) { $flags += ' --force' }
    Write-Host "Запуск update.sh $flags (может спросить пароль sudo пользователя $($ep.Target.Split('@')[0]))" -ForegroundColor DarkGray
    # Интерактивно (-t): пароль sudo вводится в этом окне и никуда не сохраняется.
    # Start-Process: ssh пишет прямо в консоль. Вызов через & внутри функции, чей результат
    # присваивается, PowerShell перехватывает — приглашение sudo не видно, вывод уходит в итог.
    $sshArgs = ((@('-t', '-p', $ep.Port) + $SshOpts + $ep.Extra + @($ep.Target)) -join ' ') +
        " `"sudo bash $dir/kit/update.sh $flags; rc=`$?; rm -rf $dir; exit `$rc`""
    $p = Start-Process -FilePath $Ssh -ArgumentList $sshArgs -NoNewWindow -PassThru
    $null = $p.Handle   # без этого ExitCode после завершения бывает пустым
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { return "update.sh завершился с кодом $($p.ExitCode)" }
    ''
}

function Get-ClientIp($vmx, $mac, $routerEp) {
    $r = Invoke-Quiet $Vmrun @('-T', 'ws', 'getGuestIPAddress', $vmx)
    $ip = @($r.Out | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) | Select-Object -First 1
    if ($r.Code -eq 0 -and $ip) { return $ip }
    if (-not $routerEp) { return $null }
    # Без VMware Tools в ВМ: адрес из DHCP-аренд роутера.
    $r = Invoke-Quiet $Ssh (@('-n', '-p', $routerEp.Port, '-o', 'BatchMode=yes') + $SshOpts + @($routerEp.Target, 'cat /var/lib/misc/dnsmasq.leases'))
    foreach ($l in $r.Out) {
        $f = $l -split '\s+'
        if ($f.Count -ge 3 -and $f[1] -eq $mac -and $f[2] -match '^\d+\.\d+\.\d+\.\d+$') { return $f[2] }
    }
    $null
}

# ================================================================ main
$vmwareDir = Find-VMware
$Vmrun = Join-Path $vmwareDir 'vmrun.exe'
if (-not (Test-Path $Vmrun)) { Fail "Нет $Vmrun" }
$Ssh = Find-SshTool 'ssh'
$Scp = Find-SshTool 'scp'
$KitStamp = Get-KitStamp $KitSrc

Say "Комплект: версия $KitStamp"
$r = Invoke-Quiet $Vmrun @('-T', 'ws', 'list')
if ($r.Code -ne 0) { Fail "vmrun list не сработал: $($r.Out -join ' ')" }
$running = @($r.Out | Where-Object { $_ -match '\.vmx\s*$' } | ForEach-Object { [IO.Path]::GetFullPath($_.Trim()) })
Write-Host "Запущено ВМ в VMware: $($running.Count)"

# Лаборатории: папка с lab.json, в которой лежат запущенные ВМ (ЛАБ\имя\имя.vmx), и заданные явно.
$labDirs = @()
foreach ($v in $running) {
    $d = Split-Path (Split-Path $v -Parent) -Parent
    if ($d -and (Test-Path (Join-Path $d 'lab.json'))) { $labDirs += $d }
}
# Папка по умолчанию: её ВМ могут лежать где угодно (контур, собранный вручную) — сверка по путям vmx.
$def = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Virtual Machines\VmGw'
if (Test-Path (Join-Path $def 'lab.json')) {
    $l = Get-Content -Raw -LiteralPath (Join-Path $def 'lab.json') | ConvertFrom-Json
    $vmxs = @($l.Router.Vmx) + @($l.Clients | ForEach-Object { $_.Vmx }) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_) }
    if (@($vmxs | Where-Object { $running -contains $_ }).Count) { $labDirs += $def }
}
if ($LabDir) {
    $want = @($LabDir | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
    foreach ($d in $want) { if (-not (Test-Path (Join-Path $d 'lab.json'))) { Fail "Нет лаборатории: $d\lab.json" } }
    $labDirs = $want
}
$labDirs = @($labDirs | Sort-Object -Unique)
if (-not $labDirs.Count) {
    Write-Host 'Запущенных ВМ лабораторий vmgw не найдено. Включите роутер (и нужные ВМ) и запустите снова.'
    if ($Json) { 'VMGW-JSON:' + (ConvertTo-Json -Compress @{ KitStamp = $KitStamp; Rows = @() }) }
    return
}

$report = @()
foreach ($d in $labDirs) {
    $lab = Get-Content -Raw -LiteralPath (Join-Path $d 'lab.json') | ConvertFrom-Json
    $lab.LabDir = $d
    $lab.Clients = @($lab.Clients)
    Say "Лаборатория $d"
    if (-not $CheckOnly) {
        Copy-Kit $lab
        $s = Get-KitStamp (Join-Path $d 'kit')
        if ($s -ne $KitStamp) { Fail "Комплект в $d\kit не совпал с исходным после копирования" }
        Write-Host 'Папка комплекта (общая папка vmgw) обновлена'
    }
    $routerUp = $running -contains [IO.Path]::GetFullPath($lab.Router.Vmx)
    $routerEp = $null
    $rowR = [pscustomobject]@{ ВМ = 'router'; Было = '-'; Стало = '-'; Итог = '' }
    if (-not $routerUp) {
        $rowR.Итог = 'выключена'
    } else {
        $ru = Ask-User $lab 'RouterUser' $User 'Пользователь на роутере (созданный при установке Ubuntu)' $env:USERNAME.ToLower()
        $routerEp = New-Endpoint $ru $lab.MgmtAddr $lab.SshPort @()
        $st = Get-RemoteStamp $routerEp
        if (-not $st.Ok) {
            $rowR.Итог = "нет доступа: $($st.Error)"
            $routerEp = $null
        } else {
            $rowR.Было = $st.Stamp
            if ($st.Stamp -eq $KitStamp -and -not $Force -and -not $RebuildAwg) { $rowR.Стало = $st.Stamp; $rowR.Итог = 'актуальна' }
            elseif ($CheckOnly) { $rowR.Итог = 'нужно обновить' }
            else {
                Say "Обновление роутера ($($routerEp.Target))"
                $err = Invoke-GuestUpdate $lab $routerEp 'router'
                $after = Get-RemoteStamp $routerEp
                $rowR.Стало = $after.Stamp
                $rowR.Итог = if ($err) { "ошибка: $err" } elseif ($after.Stamp -eq $KitStamp) { 'обновлена' } else { 'версия не совпала' }
            }
        }
    }
    $report += $rowR | Select-Object @{ n = 'Лаборатория'; e = { Split-Path $d -Leaf } }, *

    if ($RouterOnly) { continue }
    foreach ($c in $lab.Clients) {
        $row = [pscustomobject]@{ ВМ = $c.Name; Было = '-'; Стало = '-'; Итог = '' }
        $os = $c.PSObject.Properties['Os']
        if ($os -and $os.Value -eq 'windows') { $row.Итог = 'Windows: софт vmgw не нужен' }
        elseif (-not ($running -contains [IO.Path]::GetFullPath($c.Vmx))) { $row.Итог = 'выключена' }
        elseif (-not $routerEp) { $row.Итог = 'пропущена: роутер недоступен' }
        else {
            $cu = Ask-User $lab 'ClientUser' $ClientUser 'Пользователь на ведомых ВМ' $routerEp.Target.Split('@')[0]
            $ip = Get-ClientIp $c.Vmx $c.Mac $routerEp
            if (-not $ip) { $row.Итог = 'нет адреса (VMware Tools не запущены и аренды DHCP нет)' }
            else {
                # Напрямую (есть маршрут Windows → LAN), иначе через роутер.
                $jump = @('-o', "ProxyJump=$($routerEp.Target):$($routerEp.Port)")
                $ep = New-Endpoint $cu $ip 22 @()
                $st = Get-RemoteStamp $ep
                if (-not $st.Ok) { $ep = New-Endpoint $cu $ip 22 $jump; $st = Get-RemoteStamp $ep }
                if (-not $st.Ok) {
                    $row.Итог = "нет SSH ($($st.Error)); в ВМ: sudo bash /mnt/hgfs/vmgw/client-setup.sh --ssh или sudo bash /mnt/hgfs/vmgw/update.sh client"
                } else {
                    $row.Было = $st.Stamp
                    if ($st.Stamp -eq $KitStamp -and -not $Force) { $row.Стало = $st.Stamp; $row.Итог = 'актуальна' }
                    elseif ($CheckOnly) { $row.Итог = 'нужно обновить' }
                    else {
                        Say "Обновление $($c.Name) ($ip)"
                        $err = Invoke-GuestUpdate $lab $ep 'client'
                        $after = Get-RemoteStamp $ep
                        $row.Стало = $after.Stamp
                        $row.Итог = if ($err) { "ошибка: $err" } elseif ($after.Stamp -eq $KitStamp) { 'обновлена' } else { 'версия не совпала' }
                    }
                }
            }
        }
        $report += $row | Select-Object @{ n = 'Лаборатория'; e = { Split-Path $d -Leaf } }, *
    }
}

Say 'Итог'
$report | Format-Table -AutoSize -Wrap | Out-Host
if ($Json) {
    $rows = @($report | ForEach-Object { [pscustomobject]@{ Lab = $_.Лаборатория; Vm = $_.ВМ; Before = $_.Было; After = $_.Стало; Result = $_.Итог } })
    'VMGW-JSON:' + (ConvertTo-Json -Compress -Depth 3 @{ KitStamp = $KitStamp; Rows = $rows })
}
if (@($report | Where-Object { $_.Итог -eq 'выключена' }).Count) {
    Write-Host 'Выключенные ВМ обновятся при следующем запуске Update.cmd, когда будут включены.'
}
if (@($report | Where-Object { $_.Итог -match '^(ошибка|нет|версия|пропущена)' }).Count) { exit 1 }
