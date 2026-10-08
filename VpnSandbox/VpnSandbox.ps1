# VPN Sandbox — запуск программы в Windows Sandbox, где сеть есть только через VPN.
#   Без параметров — окно выбора профиля и exe.
#   CLI: VpnSandbox.ps1 -Profile <файл> [-Exe <файл>] [-Arguments "..."] [-KeepAdmin] [-AppWritable]
param(
    [string]$Profile,
    [string]$Exe,
    [string]$Arguments,
    [switch]$KeepAdmin,
    [switch]$AppWritable,
    [switch]$DryRun   # только сгенерировать .wsb, не запускать
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
. "$Root\lib\Profiles.ps1"
$SettingsFile = "$Root\settings.json"

function Get-SandboxExe {
    foreach ($p in "$env:windir\System32\WindowsSandbox.exe", "$env:windir\Sysnative\WindowsSandbox.exe") { if (Test-Path $p) { return $p } }
    $c = Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
}

function Resolve-Endpoints($VpnProfile) {
    $list = @()
    foreach ($ep in @(Get-VpnEndpoint $VpnProfile)) {
        $ips = if ($ep.Host -as [ipaddress]) { @($ep.Host) } else {
            [Net.Dns]::GetHostAddresses($ep.Host) | Where-Object AddressFamily -eq 'InterNetwork' | ForEach-Object IPAddressToString
        }
        if (-not $ips) { throw "Не удалось разрешить адрес сервера $($ep.Host)" }
        foreach ($ip in $ips) { $list += [pscustomobject]@{ Host = $ep.Host; Ip = $ip; Port = $ep.Port; Proto = $ep.Proto } }
    }
    if (-not $list) { throw 'В профиле не найден адрес сервера (Endpoint/remote)' }
    $list
}

function Get-TunnelConfig($VpnProfile, $Endpoints) {
    # В песочнице DNS до поднятия туннеля закрыт — подставляем IP вместо имён
    $t = $VpnProfile.Text -replace "`r`n", "`n"
    if ($VpnProfile.Kind -eq 'awg') {
        $ep = $Endpoints | Select-Object -First 1
        $t = [regex]::Replace($t, '(?m)^(\s*Endpoint\s*=\s*).*$', "`${1}$($ep.Ip):$($ep.Port)")
        # 0.0.0.0/0 (а не 0.0.0.0/1+128.0.0.0/1) включает встроенный kill switch клиента — второй слой защиты
        $t = [regex]::Replace($t, '(?m)^(\s*AllowedIPs\s*=\s*).*$', '${1}0.0.0.0/0, ::/0')
    } else {
        $t = [regex]::Replace($t, '(?m)^\s*remote\s+.*$\n?', '')
        $remotes = ($Endpoints | ForEach-Object { "remote $($_.Ip) $($_.Port) $($_.Proto.ToLower())" }) -join "`n"
        $t = "$remotes`n$t"
    }
    $t -replace "`n", "`r`n"
}

function Get-HostPublicIp {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 4).ToString().Trim()
    } catch { $null }
}

function Escape-Xml([string]$s) { [Security.SecurityElement]::Escape($s) }

function Start-VpnSandbox {
    param([string]$ProfilePath, [string]$ExePath, [string]$ExeArgs, [bool]$DropAdmin = $true, [bool]$AppReadOnly = $true, [switch]$DryRun)

    $sbx = Get-SandboxExe
    if (-not $sbx -and -not $DryRun) {
        throw "Windows Sandbox не включён. Запустите от администратора:`n  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All`nи перезагрузитесь."
    }
    if (Get-Process WindowsSandbox, WindowsSandboxClient, WindowsSandboxRemoteSession -ErrorAction SilentlyContinue) {
        throw 'Windows Sandbox уже запущена — одновременно может работать только одна. Закройте её.'
    }

    $vp = Get-VpnProfile $ProfilePath
    $pattern = if ($vp.Kind -eq 'awg') { 'amneziawg-amd64-*.msi' } else { 'OpenVPN-*.msi' }
    if (-not (Get-ChildItem "$Root\tools\$pattern" -ErrorAction SilentlyContinue)) { throw "Нет клиента ($pattern) в папке tools — запустите Setup.cmd" }

    $eps = Resolve-Endpoints $vp

    # Старые запуски (секреты из них bootstrap уже удалил, но чистим целиком)
    Get-ChildItem "$Root\runs" -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $run = New-Item -ItemType Directory -Force "$Root\runs\$(Get-Date -Format yyyyMMdd-HHmmss)"
    New-Item -ItemType Directory -Force "$Root\shared" | Out-Null

    $tunnelFile = "$($vp.Name).$(if ($vp.Kind -eq 'awg') { 'conf' } else { 'ovpn' })"
    [IO.File]::WriteAllText("$($run.FullName)\$tunnelFile", (Get-TunnelConfig $vp $eps), (New-Object Text.UTF8Encoding $false))

    $maps = @(
        @{ Host = "$Root\tools";   Box = 'C:\VpnSandbox\tools';   RO = $true }
        @{ Host = "$Root\sandbox"; Box = 'C:\VpnSandbox\sandbox'; RO = $true }
        @{ Host = $run.FullName;   Box = 'C:\VpnSandbox\run';     RO = $false }
        @{ Host = "$Root\shared";  Box = 'C:\Users\WDAGUtilityAccount\Desktop\Shared'; RO = $false }
    )
    $boxExe = $null
    if ($ExePath) {
        $ExePath = (Resolve-Path -LiteralPath $ExePath).Path
        $appDir = Split-Path $ExePath
        $maps += @{ Host = $appDir; Box = 'C:\App'; RO = $AppReadOnly }
        $boxExe = 'C:\App\' + (Split-Path $ExePath -Leaf)
    }

    $hostIp = Get-HostPublicIp
    [ordered]@{
        Kind = $vp.Kind; TunnelName = $vp.Name; TunnelFile = $tunnelFile
        Endpoints = @($eps | ForEach-Object { @{ Ip = $_.Ip; Port = $_.Port; Proto = $_.Proto } })
        Exe = $boxExe; Args = $ExeArgs; DropAdmin = $DropAdmin; HostPublicIp = $hostIp
    } | ConvertTo-Json -Depth 4 | Set-Content "$($run.FullName)\run.json" -Encoding UTF8

    $mapXml = ($maps | ForEach-Object {
        "    <MappedFolder><HostFolder>$(Escape-Xml $_.Host)</HostFolder><SandboxFolder>$(Escape-Xml $_.Box)</SandboxFolder><ReadOnly>$($_.RO.ToString().ToLower())</ReadOnly></MappedFolder>"
    }) -join "`r`n"
    $wsb = @"
<Configuration>
  <Networking>Enable</Networking>
  <MappedFolders>
$mapXml
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File C:\VpnSandbox\sandbox\Bootstrap.ps1</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbPath = "$($run.FullName)\VpnSandbox.wsb"
    Set-Content $wsbPath $wsb -Encoding UTF8

    $info = "Профиль: $(Split-Path $ProfilePath -Leaf) [$($vp.Kind), $($vp.Source)]; сервер: $(($eps | ForEach-Object { "$($_.Proto) $($_.Ip):$($_.Port)" }) -join ', ')"
    if (-not $DryRun) { Start-Process $sbx -ArgumentList "`"$wsbPath`"" }
    [pscustomobject]@{ Info = $info; Wsb = $wsbPath; RunDir = $run.FullName }
}

function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $s = if (Test-Path $SettingsFile) { Get-Content -Raw $SettingsFile | ConvertFrom-Json } else { [pscustomobject]@{} }

    $f = New-Object Windows.Forms.Form -Property @{ Text = 'VPN Sandbox'; Width = 640; Height = 330; StartPosition = 'CenterScreen'; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false; Font = New-Object Drawing.Font('Segoe UI', 9) }
    function Add-Row($y, $label, $value, $filter) {
        $l = New-Object Windows.Forms.Label -Property @{ Text = $label; Left = 12; Top = $y + 3; Width = 110 }
        $t = New-Object Windows.Forms.TextBox -Property @{ Left = 125; Top = $y; Width = 400; Text = $value }
        $b = New-Object Windows.Forms.Button -Property @{ Text = 'Обзор…'; Left = 532; Top = $y - 1; Width = 80 }
        $b.Add_Click({ $d = New-Object Windows.Forms.OpenFileDialog -Property @{ Filter = $filter }; if ($t.Text) { $d.InitialDirectory = Split-Path $t.Text -ErrorAction SilentlyContinue }; if ($d.ShowDialog() -eq 'OK') { $t.Text = $d.FileName } }.GetNewClosure())
        $f.Controls.AddRange(@($l, $t, $b)); $t
    }
    $tProfile = Add-Row 15 'VPN-профиль:' $s.Profile 'VPN-профили (*.conf;*.vpn;*.ovpn)|*.conf;*.vpn;*.ovpn|Все файлы|*.*'
    $tExe = Add-Row 49 'Программа (exe):' $s.Exe 'Программы (*.exe)|*.exe|Все файлы|*.*'
    $y = 83
    $l = New-Object Windows.Forms.Label -Property @{ Text = 'Аргументы:'; Left = 12; Top = $y + 3; Width = 110 }
    $tArgs = New-Object Windows.Forms.TextBox -Property @{ Left = 125; Top = $y; Width = 400; Text = $s.Args }
    $f.Controls.AddRange(@($l, $tArgs)); $y += 34
    $cDrop = New-Object Windows.Forms.CheckBox -Property @{ Text = 'Запускать без прав администратора (не сможет отключить kill switch)'; Left = 125; Top = $y; Width = 480; Checked = ($s.DropAdmin -ne $false) }; $y += 26
    $cRO = New-Object Windows.Forms.CheckBox -Property @{ Text = 'Папка программы только для чтения'; Left = 125; Top = $y; Width = 480; Checked = ($s.AppReadOnly -ne $false) }; $y += 30
    $status = New-Object Windows.Forms.Label -Property @{ Left = 12; Top = $y; Width = 600; Height = 40; Text = 'Пустое поле exe — песочница с VPN и проводником. Общая папка: ' + "$Root\shared" }; $y += 44
    $go = New-Object Windows.Forms.Button -Property @{ Text = 'Запустить в песочнице'; Left = 420; Top = $y; Width = 192; Height = 30 }
    $f.Controls.AddRange(@($cDrop, $cRO, $status, $go)); $f.AcceptButton = $go

    $go.Add_Click({
        try {
            if (-not $tProfile.Text) { throw 'Выберите VPN-профиль' }
            $f.Cursor = 'WaitCursor'; $status.Text = 'Готовлю песочницу...'; $f.Refresh()
            $r = Start-VpnSandbox -ProfilePath $tProfile.Text -ExePath $tExe.Text -ExeArgs $tArgs.Text -DropAdmin $cDrop.Checked -AppReadOnly $cRO.Checked
            [pscustomobject]@{ Profile = $tProfile.Text; Exe = $tExe.Text; Args = $tArgs.Text; DropAdmin = $cDrop.Checked; AppReadOnly = $cRO.Checked } | ConvertTo-Json | Set-Content $SettingsFile -Encoding UTF8
            $status.ForeColor = 'DarkGreen'; $status.Text = "Песочница запускается. $($r.Info)"
        } catch {
            $status.ForeColor = 'DarkRed'; $status.Text = $_.Exception.Message
        } finally { $f.Cursor = 'Default' }
    })
    [void]$f.ShowDialog()
}

if ($Profile) {
    $r = Start-VpnSandbox -ProfilePath $Profile -ExePath $Exe -ExeArgs $Arguments -DropAdmin (-not $KeepAdmin) -AppReadOnly (-not $AppWritable) -DryRun:$DryRun
    $r.Info; "wsb: $($r.Wsb)"
} else {
    Show-Gui
}
