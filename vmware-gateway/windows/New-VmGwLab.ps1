<#
.SYNOPSIS
  Создаёт в VMware Workstation лабораторию vmgw: роутер + N ведомых ВМ.

.DESCRIPTION
  Роутер (Ubuntu Server) получает три сетевые карты:
    управление  - host-only VMnet1 (или NAT VMnet8): связь с этим компьютером;
    LAN         - внутренний сегмент (LAN segment) для ведомых ВМ;
    WAN         - мост (bridged) в физическую сеть: отсюда выход в интернет.
  Ведомые ВМ (Ubuntu Desktop) получают одну карту - в LAN-сегменте.
  Дистрибутивы скачиваются вручную с официального сайта Ubuntu.

.EXAMPLE
  .\New-VmGwLab.ps1
  Спросит ISO через окно выбора файла и создаст роутер и одну ВМ ws1.

.EXAMPLE
  .\New-VmGwLab.ps1 -ServerIso D:\iso\ubuntu-24.04.3-live-server-amd64.iso -DesktopIso D:\iso\ubuntu-24.04.3-desktop-amd64.iso -Clients ws1,ws2

.EXAMPLE
  .\New-VmGwLab.ps1 -AddClient ws3
  Добавляет ещё одну ВМ в существующую лабораторию.

.EXAMPLE
  .\New-VmGwLab.ps1 -AddClient win1 -ClientOs windows -WindowsIso D:\iso\Win11_24H2_Russian_x64.iso
  Ведомая ВМ с Windows 10/11: в ней ничего ставить не нужно, сеть целиком даёт роутер.
#>
[CmdletBinding()]
param(
    [string]$LabDir = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Virtual Machines\VmGw'),
    [string]$ServerIso,
    [string]$DesktopIso,
    [string[]]$Clients = @('ws1'),
    [string]$AddClient,
    [ValidateSet('ubuntu', 'windows')][string]$ClientOs = 'ubuntu',
    [string]$WindowsIso,
    [ValidateSet('VMnet1', 'VMnet8')][string]$MgmtVnet = 'VMnet1',
    [string]$LanNet = '192.168.150.0/24',
    [int]$SshPort = 22,
    [int]$PanelPort = 8088,
    [string]$AdminNets = '',
    [string]$LocalNets = 'auto',
    [int]$RouterMemoryMB = 1024,
    [int]$RouterCpus = 1,
    [int]$RouterDiskGB = 16,
    [int]$ClientMemoryMB = 4096,
    [int]$ClientCpus = 2,
    [int]$ClientDiskGB = 40,
    [string]$SshPublicKey,
    [switch]$NoSshKey,
    [switch]$SkipIsoCheck,
    [switch]$NoRoute,
    [switch]$NoOpen,
    [int]$HwVersion = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
. (Join-Path $PSScriptRoot 'VmGwCommon.ps1')
$NameRe = '^[a-z0-9][a-z0-9-]{0,30}$'

# ---------------------------------------------------------------- VMware
function Get-HwVersion([string]$dir) {
    # Версию берём из свойств файла, не запуская vmware.exe.
    $v = (Get-Item (Join-Path $dir 'vmware.exe')).VersionInfo.ProductVersion
    if ($v -notmatch '^(\d+)\.(\d+)') { return 19 }
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]
    if ($maj -ge 25) { return 22 }
    if ($maj -eq 17 -and $min -ge 5) { return 21 }
    if ($maj -eq 17) { return 20 }
    return 19
}

# ---------------------------------------------------------------- адреса
function IpToUInt([string]$ip) {
    $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0)
}
function UIntToIp([uint32]$n) {
    $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); (New-Object Net.IPAddress (, $b)).ToString()
}
function MaskOf([int]$prefix) { [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix)) }
function Parse-Net([string]$cidr) {
    if ($cidr -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { Fail "Неверная сеть: $cidr" }
    $p = [int]$Matches[2]
    if ($p -lt 16 -or $p -gt 24) { Fail "Сеть $cidr`: нужна маска от /16 до /24" }
    $m = MaskOf $p
    $n = (IpToUInt $Matches[1]) -band $m
    [pscustomobject]@{ Net = (UIntToIp $n); Prefix = $p; Mask = (UIntToIp $m); Base = [uint32]$n; Cidr = "$(UIntToIp $n)/$p" }
}

function Get-MgmtNet([string]$vnet) {
    $alias = "VMware Network Adapter $vnet"
    $a = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $a) {
        Fail "Нет адаптера «$alias». Включите его: VMware → Edit → Virtual Network Editor → $vnet → «Connect a host virtual adapter»."
    }
    $n = Parse-Net ("{0}/{1}" -f $a.IPAddress, $a.PrefixLength)
    [pscustomobject]@{ Cidr = $n.Cidr; HostIp = $a.IPAddress; Addr = (UIntToIp ($n.Base + 10)) }
}

# ---------------------------------------------------------------- случайные идентификаторы
$Rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
function RandomBytes([int]$n) { $b = New-Object byte[] $n; $Rng.GetBytes($b); , $b }
function New-Mac {
    # Ручной диапазон VMware: 00:50:56:00:00:00 - 00:50:56:3F:FF:FF
    $b = RandomBytes 3
    '00:50:56:{0:x2}:{1:x2}:{2:x2}' -f ($b[0] -band 0x3f), $b[1], $b[2]
}
function New-PvnId {
    $b = RandomBytes 16
    $h = @($b | ForEach-Object { '{0:x2}' -f $_ })
    ($h[0..7] -join ' ') + '-' + ($h[8..15] -join ' ')
}

# ---------------------------------------------------------------- ISO
function Select-Iso([string]$title, [string]$hint) {
    Write-Host $hint
    Add-Type -AssemblyName System.Windows.Forms
    $d = New-Object Windows.Forms.OpenFileDialog
    $d.Title = $title
    $d.Filter = 'ISO (*.iso)|*.iso'
    if ($d.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { Fail 'ISO не выбран' }
    $d.FileName
}

function Test-UbuntuIso([string]$path) {
    if ($SkipIsoCheck) { return }
    $name = Split-Path $path -Leaf
    if ($name -notmatch '^ubuntu-(\d+\.\d+)(\.\d+)?-') {
        Write-Warning "$name`: не похоже на официальное имя образа Ubuntu, проверка SHA256 пропущена"
        return
    }
    $urls = @("https://releases.ubuntu.com/$($Matches[1])$($Matches[2])/SHA256SUMS", "https://releases.ubuntu.com/$($Matches[1])/SHA256SUMS") | Select-Object -Unique
    $want = $null
    foreach ($u in $urls) {
        try { $sums = (Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 30).Content } catch { continue }
        if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
        foreach ($line in ($sums -split "`n")) {
            if ($line -match '^([0-9a-f]{64}) \*?(.+?)\s*$' -and $Matches[2] -eq $name) { $want = $Matches[1]; break }
        }
        if ($want) { break }
    }
    if (-not $want) {
        Write-Warning "$name нет в SHA256SUMS на releases.ubuntu.com (старый выпуск?) — проверка пропущена"
        return
    }
    Write-Host "Проверка SHA256 $name ..."
    $have = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower()
    if ($have -ne $want) { Fail "SHA256 образа $name не совпадает с releases.ubuntu.com — скачайте заново" }
    Write-Host 'SHA256 совпадает с официальным' -ForegroundColor Green
}

# ---------------------------------------------------------------- файлы ВМ
function New-Disk([string]$vdm, [string]$path, [int]$gb) {
    if (Test-Path $path) { Fail "Диск уже существует: $path" }
    & $vdm -c -s "${gb}GB" -a lsilogic -t 0 $path | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail "vmware-vdiskmanager не создал $path" }
}

function Write-Vmx([string]$path, [System.Collections.Specialized.OrderedDictionary]$v) {
    $lines = foreach ($k in $v.Keys) { '{0} = "{1}"' -f $k, $v[$k] }
    [IO.File]::WriteAllText($path, (($lines -join "`r`n") + "`r`n"), $Utf8)
}

function Base-Vmx([string]$name, [int]$mem, [int]$cpus, [string]$disk, [string]$iso, [int]$hw, [string]$share, [string]$guestOs = 'ubuntu-64') {
    $v = [ordered]@{
        '.encoding' = 'UTF-8'; 'config.version' = '8'; 'virtualHW.version' = "$hw"
        'displayName' = $name; 'guestOS' = $guestOs; 'firmware' = 'efi'
        'memsize' = "$mem"; 'numvcpus' = "$cpus"; 'cpuid.coresPerSocket' = "$cpus"
        'pciBridge0.present' = 'TRUE'
    }
    foreach ($i in 4..7) {
        $v["pciBridge$i.present"] = 'TRUE'; $v["pciBridge$i.virtualDev"] = 'pcieRootPort'; $v["pciBridge$i.functions"] = '8'
    }
    $v['vmci0.present'] = 'TRUE'; $v['hpet0.present'] = 'TRUE'; $v['floppy0.present'] = 'FALSE'
    if ($guestOs -like 'windows*') {
        # Установщик Windows видит NVMe без дополнительных драйверов (pvscsi — нет).
        $v['nvme0.present'] = 'TRUE'
        $v['nvme0:0.present'] = 'TRUE'; $v['nvme0:0.fileName'] = $disk
    } else {
        $v['scsi0.present'] = 'TRUE'; $v['scsi0.virtualDev'] = 'pvscsi'
        $v['scsi0:0.present'] = 'TRUE'; $v['scsi0:0.fileName'] = $disk
    }
    $v['sata0.present'] = 'TRUE'; $v['sata0:1.present'] = 'TRUE'; $v['sata0:1.deviceType'] = 'cdrom-image'
    $v['sata0:1.fileName'] = $iso; $v['sata0:1.startConnected'] = 'TRUE'
    $v['tools.syncTime'] = 'TRUE'
    if (-not $share) { return $v }
    $v['isolation.tools.hgfs.disable'] = 'FALSE'
    $v['sharedFolder.maxNum'] = '1'
    $v['sharedFolder0.present'] = 'TRUE'; $v['sharedFolder0.enabled'] = 'TRUE'
    $v['sharedFolder0.readAccess'] = 'TRUE'; $v['sharedFolder0.writeAccess'] = 'FALSE'
    $v['sharedFolder0.hostPath'] = $share; $v['sharedFolder0.guestName'] = 'vmgw'; $v['sharedFolder0.expiration'] = 'never'
    $v['hgfs.mapRootShare'] = 'TRUE'; $v['hgfs.linkRootShare'] = 'TRUE'
    $v
}

function Add-Nic($v, [int]$i, [string]$type, [string]$mac, [string]$pvn, [string]$dev = 'vmxnet3') {
    $v["ethernet$i.present"] = 'TRUE'
    $v["ethernet$i.virtualDev"] = $dev
    $v["ethernet$i.connectionType"] = $type
    if ($pvn) { $v["ethernet$i.pvnID"] = $pvn }
    $v["ethernet$i.addressType"] = 'static'
    $v["ethernet$i.address"] = $mac
    $v["ethernet$i.startConnected"] = 'TRUE'
}

# Windows 11 не ставится без TPM 2.0, а виртуальный TPM VMware даёт только зашифрованной ВМ.
# Вместо этого рядом с ВМ кладётся маленький ISO с autounattend.xml: установщик Windows сам
# находит его на любом CD и до проверки совместимости выставляет ключи LabConfig (как Rufus).
# Других ответов в файле нет — язык, диск и учётную запись установщик спрашивает как обычно.
$WinSetupXml = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>2</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>3</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
'@

function New-WinSetupIso([string]$path) {
    $src = Join-Path ([IO.Path]::GetTempPath()) ('vmgw-unattend-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $src | Out-Null
    try {
        [IO.File]::WriteAllText((Join-Path $src 'autounattend.xml'), $WinSetupXml.Replace("`r`n", "`n").Replace("`n", "`r`n"), $Utf8)
        if (-not ('VmGwIso' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class VmGwIso {
    public static void Save(object image, string path) {
        IStream s = (IStream)image;
        byte[] buf = new byte[65536];
        IntPtr n = Marshal.AllocHGlobal(4);
        try {
            using (FileStream f = File.Create(path)) {
                while (true) {
                    s.Read(buf, buf.Length, n);
                    int got = Marshal.ReadInt32(n);
                    if (got <= 0) break;
                    f.Write(buf, 0, got);
                }
            }
        } finally { Marshal.FreeHGlobal(n); }
    }
}
'@
        }
        # IMAPI2 есть в любой Windows 10/11: ISO 9660 + Joliet без сторонних программ.
        $fs = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
        $fs.FileSystemsToCreate = 3
        $fs.VolumeName = 'VMGW_SETUP'
        $fs.Root.AddTree($src, $false)
        [VmGwIso]::Save($fs.CreateResultImage().ImageStream, $path)
    } finally {
        Remove-Item -LiteralPath $src -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function New-ClientVm($lab, [string]$name, [string]$vdm, [string]$iso, [string]$os = 'ubuntu') {
    if ($name -notmatch $NameRe) { Fail "Имя ВМ «$name»: латиница в нижнем регистре, цифры, дефис (до 31 символа)" }
    if (@($lab.Clients | Where-Object { $_.Name -eq $name }).Count) { Fail "ВМ $name уже есть в лаборатории" }
    $dir = Join-Path $lab.LabDir $name
    if (Test-Path $dir) { Fail "Папка уже существует: $dir" }
    New-Item -ItemType Directory -Path $dir | Out-Null
    $used = @($lab.Router.MgmtMac, $lab.Router.LanMac, $lab.Router.WanMac) + @($lab.Clients | ForEach-Object { $_.Mac })
    do { $mac = New-Mac } while ($used -contains $mac)
    if ($os -eq 'windows') {
        # Минимум Windows 11: 4 ГБ памяти, 2 ядра, 64 ГБ диска. Комплект vmgw внутри не нужен — без общей папки.
        $guest = if ((Split-Path $iso -Leaf) -match '(?i)win(dows)?[ _-]?10') { 'windows9-64' } else { 'windows11-64' }
        New-Disk $vdm (Join-Path $dir "$name.vmdk") ([Math]::Max($lab.ClientDiskGB, 64))
        $v = Base-Vmx "vmgw-$name" ([Math]::Max($lab.ClientMemoryMB, 4096)) ([Math]::Max($lab.ClientCpus, 2)) "$name.vmdk" $iso $lab.HwVersion '' $guest
        $v['uefi.secureBoot.enabled'] = 'TRUE'
        if ($guest -eq 'windows11-64') {
            $setup = Join-Path $dir 'win11-setup.iso'
            try {
                New-WinSetupIso $setup
                $v['sata0:2.present'] = 'TRUE'; $v['sata0:2.deviceType'] = 'cdrom-image'
                $v['sata0:2.fileName'] = $setup; $v['sata0:2.startConnected'] = 'TRUE'
            } catch {
                Write-Warning "Не удалось создать win11-setup.iso ($($_.Exception.Message)): проверку TPM придётся обойти вручную (см. README)"
            }
        }
        $nic = 'e1000e'   # драйвер есть в самой Windows; vmxnet3 — только после VMware Tools
    } else {
        New-Disk $vdm (Join-Path $dir "$name.vmdk") $lab.ClientDiskGB
        $v = Base-Vmx "vmgw-$name" $lab.ClientMemoryMB $lab.ClientCpus "$name.vmdk" $iso $lab.HwVersion (Join-Path $lab.LabDir 'kit')
        $nic = 'vmxnet3'
    }
    $v['mks.enable3d'] = 'TRUE'
    $v['sound.present'] = 'TRUE'; $v['sound.virtualDev'] = 'hdaudio'; $v['sound.autoDetect'] = 'TRUE'
    $v['usb.present'] = 'TRUE'; $v['usb_xhci.present'] = 'TRUE'
    # Единственная сетевая карта - во внутреннем LAN-сегменте.
    Add-Nic $v 0 'pvn' $mac $lab.PvnId $nic
    $vmx = Join-Path $dir "$name.vmx"
    Write-Vmx $vmx $v
    $c = [pscustomobject]@{ Name = $name; Mac = $mac; Vmx = $vmx }
    if ($os -eq 'windows') { $c | Add-Member Os 'windows' }
    $lab.Clients += $c
    $vmx
}

function Get-Prop($o, [string]$name) {
    # lab.json прежних версий может не содержать поля; Set-StrictMode не даёт читать отсутствующее.
    $p = $o.PSObject.Properties[$name]
    if ($p) { $p.Value } else { $null }
}

# ---------------------------------------------------------------- kit и lab.conf
function Write-LabConf($lab) {
    $hosts = ($lab.Clients | ForEach-Object { "$($_.Name)=$($_.Mac)" }) -join ','
    $lines = @(
        "# lab.conf - параметры лаборатории vmgw. Создан New-VmGwLab.ps1 $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        '# Читается router-install.sh (не исполняется как скрипт).'
        "MGMT_MAC=$($lab.Router.MgmtMac)"
        "LAN_MAC=$($lab.Router.LanMac)"
        "WAN_MAC=$($lab.Router.WanMac)"
        "MGMT_NET=$($lab.MgmtNet)"
        "MGMT_ADDR=$($lab.MgmtAddr)"
        "LAN_NET=$($lab.LanNet)"
        "SSH_PORT=$($lab.SshPort)"
        "PANEL_PORT=$($lab.PanelPort)"
        "ADMIN_NETS=$($lab.AdminNets)"
        "LOCAL_NETS=$($lab.LocalNets)"
        "HOSTS=`"$hosts`""
    )
    if ($lab.SshPubKey) { $lines += "SSH_PUBKEY=`"$($lab.SshPubKey)`"" }
    [IO.File]::WriteAllText((Join-Path $lab.LabDir 'kit\lab.conf'), (($lines -join "`n") + "`n"), $Utf8)
}

function Save-Lab($lab) {
    [IO.File]::WriteAllText((Join-Path $lab.LabDir 'lab.json'), ($lab | ConvertTo-Json -Depth 5), $Utf8)
}

function Add-WindowsRoute($lab) {
    if ($NoRoute) { return }
    $lan = Parse-Net $lab.LanNet
    if (Get-NetRoute -DestinationPrefix $lan.Cidr -ErrorAction SilentlyContinue) {
        Write-Host "Маршрут к $($lan.Cidr) в Windows уже есть"
        return
    }
    $routeArgs = "-p add $($lan.Net) mask $($lan.Mask) $($lab.MgmtAddr)"
    Say "Маршрут Windows → LAN-сегмент"
    Write-Host "Чтобы этот компьютер видел ВМ сегмента напрямую, нужен постоянный маршрут:"
    Write-Host "  route $routeArgs"
    $a = Read-Host 'Добавить сейчас (потребуются права администратора)? [Y/n]'
    if ($a -match '^(n|н)') { Write-Host 'Пропущено. Команду можно выполнить позже в консоли администратора.'; return }
    try {
        $p = Start-Process -FilePath route.exe -ArgumentList $routeArgs -Verb RunAs -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) { Write-Host 'Маршрут добавлен' -ForegroundColor Green } else { Write-Warning "route.exe завершился с кодом $($p.ExitCode)" }
    } catch { Write-Warning 'Маршрут не добавлен (отказ в повышении прав). Команда выше.' }
}

function Get-PubKey {
    if ($NoSshKey) { return $null }
    $path = $SshPublicKey
    if (-not $path) {
        foreach ($n in 'id_ed25519.pub', 'id_ecdsa.pub', 'id_rsa.pub') {
            $p = Join-Path $env:USERPROFILE ".ssh\$n"
            if (Test-Path $p) { $path = $p; break }
        }
    }
    if (-not $path) { return $null }
    $k = (Get-Content -Raw -Path $path).Trim()
    if ($k -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]+( [^"\r\n]*)?$') {
        Write-Warning "$path не похож на публичный ключ SSH — не используется"
        return $null
    }
    Write-Host "Публичный ключ SSH для входа на ВМ: $path"
    $k
}

function Open-Vm([string]$vmwareDir, [string]$vmx) {
    if (-not $NoOpen) { Start-Process -FilePath (Join-Path $vmwareDir 'vmware.exe') -ArgumentList "`"$vmx`"" }
}

# ================================================================ main
$vmwareDir = Find-VMware
$vdm = Join-Path $vmwareDir 'vmware-vdiskmanager.exe'
$labJson = Join-Path $LabDir 'lab.json'

if ($AddClient) {
    if (-not (Test-Path $labJson)) { Fail "Лаборатория не найдена: $labJson (укажите -LabDir)" }
    $lab = Get-Content -Raw -Path $labJson | ConvertFrom-Json
    $lab.Clients = @($lab.Clients)
    $lab.LabDir = (Resolve-Path -LiteralPath $LabDir).Path   # папку могли перенести
    if ($ClientOs -eq 'windows') {
        if (-not $WindowsIso) { $WindowsIso = Get-Prop $lab 'WindowsIso' }
        if (-not $WindowsIso -or -not (Test-Path $WindowsIso)) {
            $WindowsIso = Select-Iso 'Образ Windows 10/11' 'Выберите ISO Windows 10/11 (https://www.microsoft.com/software-download/windows11)'
        }
        $WindowsIso = (Resolve-Path $WindowsIso).Path
        $vmx = New-ClientVm $lab $AddClient $vdm $WindowsIso 'windows'
        $lab | Add-Member -Force WindowsIso $WindowsIso
    } else {
        if (-not $DesktopIso) { $DesktopIso = $lab.DesktopIso }
        if (-not $DesktopIso -or -not (Test-Path $DesktopIso)) {
            $DesktopIso = Select-Iso 'Образ Ubuntu Desktop' 'Выберите ISO Ubuntu Desktop (https://ubuntu.com/download/desktop)'
        }
        $vmx = New-ClientVm $lab $AddClient $vdm $DesktopIso
        $lab.DesktopIso = $DesktopIso
    }
    Copy-Kit $lab
    Write-LabConf $lab
    Save-Lab $lab
    $c = $lab.Clients[-1]
    Say "ВМ $($c.Name) создана: $vmx"
    Write-Host "MAC: $($c.Mac). Зарегистрируйте ВМ на роутере и назначьте ей профиль:"
    Write-Host "  панель http://$($lab.MgmtAddr):$($lab.PanelPort) → «ВМ без профиля» → «Добавить как хост»"
    Write-Host "  или: sudo vmgw host add $($c.Name) $($c.Mac)"
    if ($ClientOs -eq 'windows') {
        Write-Host 'Windows: в ВМ ничего от vmgw ставить не нужно — адрес, DNS и выход через туннель даёт роутер.'
        Write-Host '  Установщик Windows 11 хочет интернет: назначьте ВМ профиль до установки — тогда он будет, через туннель.'
        if (Test-Path (Join-Path (Split-Path $vmx) 'win11-setup.iso')) {
            Write-Host '  Проверку TPM 2.0 и Secure Boot установщик Windows 11 пропустит сам: к ВМ подключён win11-setup.iso'
            Write-Host '  (autounattend.xml только с ключами LabConfig). Настоящий vTPM не нужен; если нужен (BitLocker) —'
            Write-Host '  VMware → настройки ВМ → Options → Access Control → Encrypt, затем Hardware → Add → Trusted Platform Module.'
        }
        Write-Host '  После установки: VM → Install VMware Tools (драйвер экрана и буфер обмена).'
    } else {
        Write-Host 'Установите Ubuntu Desktop; для обновлялки один раз в ВМ: sudo bash /mnt/hgfs/vmgw/client-setup.sh --ssh'
    }
    Open-Vm $vmwareDir $vmx
    return
}
if ($ClientOs -ne 'ubuntu') { Fail 'Ведомые ВМ с Windows добавляются в готовую лабораторию: -AddClient ИМЯ -ClientOs windows' }

if (Test-Path $labJson) { Fail "В $LabDir уже есть лаборатория. Новая ВМ: -AddClient ИМЯ; другая лаборатория: -LabDir ПАПКА" }
$Clients = @($Clients | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($n in $Clients) { if ($n -notmatch $NameRe) { Fail "Имя ВМ «$n»: латиница в нижнем регистре, цифры, дефис" } }
if (@($Clients | Select-Object -Unique).Count -ne $Clients.Count) { Fail 'Имена ВМ повторяются' }
if (-not (Test-Path (Join-Path $KitSrc 'router-install.sh'))) { Fail "Не найден комплект: $KitSrc" }

Say 'Образы Ubuntu (только с официального сайта)'
Write-Host '  Ubuntu Server (роутер):  https://ubuntu.com/download/server'
Write-Host '  Ubuntu Desktop (ВМ):     https://ubuntu.com/download/desktop'
Write-Host '  Все выпуски и SHA256SUMS: https://releases.ubuntu.com/'
if (-not $ServerIso) { $ServerIso = Select-Iso 'Образ Ubuntu Server для роутера' 'Выберите ISO Ubuntu Server (live-server)' }
if (-not (Test-Path $ServerIso)) { Fail "Нет файла $ServerIso" }
$ServerIso = (Resolve-Path $ServerIso).Path
if ((Split-Path $ServerIso -Leaf) -notmatch 'server') { Write-Warning 'Похоже, это не образ Ubuntu Server' }
Test-UbuntuIso $ServerIso
if ($Clients.Count) {
    if (-not $DesktopIso) { $DesktopIso = Select-Iso 'Образ Ubuntu Desktop для ведомых ВМ' 'Выберите ISO Ubuntu Desktop' }
    if (-not (Test-Path $DesktopIso)) { Fail "Нет файла $DesktopIso" }
    $DesktopIso = (Resolve-Path $DesktopIso).Path
    if ((Split-Path $DesktopIso -Leaf) -notmatch 'desktop') { Write-Warning 'Похоже, это не образ Ubuntu Desktop' }
    Test-UbuntuIso $DesktopIso
}

Say 'Параметры сети'
$mgmt = Get-MgmtNet $MgmtVnet
$lan = Parse-Net $LanNet
$mb = Parse-Net $mgmt.Cidr
$overlap = (($lan.Base -band (MaskOf $mb.Prefix)) -eq $mb.Base) -or (($mb.Base -band (MaskOf $lan.Prefix)) -eq $lan.Base)
if ($overlap) { Fail "LAN-сегмент $($lan.Cidr) пересекается с сетью $MgmtVnet $($mgmt.Cidr): задайте -LanNet" }
if (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { ((IpToUInt $_.IPAddress) -band (MaskOf $lan.Prefix)) -eq $lan.Base }) {
    Fail "Сеть $($lan.Cidr) уже используется на этом компьютере: задайте другую -LanNet"
}
$hw = if ($HwVersion) { $HwVersion } else { Get-HwVersion $vmwareDir }
Write-Host "Управление: $MgmtVnet $($mgmt.Cidr), этот компьютер $($mgmt.HostIp), роутер $($mgmt.Addr)"
Write-Host "LAN-сегмент: $($lan.Cidr), шлюз $(UIntToIp ($lan.Base + 1))"
Write-Host "VMware: $vmwareDir (virtualHW $hw)"

$macs = @()
while ($macs.Count -lt 3) { $m = New-Mac; if ($macs -notcontains $m) { $macs += $m } }
$lab = [pscustomobject]@{
    LabDir = $LabDir; Created = (Get-Date -Format s); HwVersion = $hw
    MgmtVnet = $MgmtVnet; MgmtNet = $mgmt.Cidr; MgmtAddr = $mgmt.Addr; LanNet = $lan.Cidr; PvnId = (New-PvnId)
    SshPort = $SshPort; PanelPort = $PanelPort; AdminNets = $AdminNets; LocalNets = $LocalNets
    SshPubKey = (Get-PubKey)
    ClientMemoryMB = $ClientMemoryMB; ClientCpus = $ClientCpus; ClientDiskGB = $ClientDiskGB
    ServerIso = $ServerIso; DesktopIso = $DesktopIso
    Router = [pscustomobject]@{ MgmtMac = $macs[0]; LanMac = $macs[1]; WanMac = $macs[2]; Vmx = '' }
    Clients = @()
}

Say "Создание ВМ в $LabDir"
$routerDir = Join-Path $LabDir 'router'
New-Item -ItemType Directory -Force -Path $routerDir | Out-Null
Copy-Kit $lab
New-Disk $vdm (Join-Path $routerDir 'router.vmdk') $RouterDiskGB
$v = Base-Vmx 'vmgw-router' $RouterMemoryMB $RouterCpus 'router.vmdk' $ServerIso $hw (Join-Path $LabDir 'kit')
Add-Nic $v 0 $(if ($MgmtVnet -eq 'VMnet8') { 'nat' } else { 'hostonly' }) $lab.Router.MgmtMac $null
Add-Nic $v 1 'pvn' $lab.Router.LanMac $lab.PvnId
Add-Nic $v 2 'bridged' $lab.Router.WanMac $null
$lab.Router.Vmx = Join-Path $routerDir 'router.vmx'
Write-Vmx $lab.Router.Vmx $v
Write-Host "Роутер: $($lab.Router.Vmx)"
foreach ($n in $Clients) {
    $vmx = New-ClientVm $lab $n $vdm $DesktopIso
    Write-Host "ВМ $n`: $vmx"
}
Write-LabConf $lab
Save-Lab $lab
Add-WindowsRoute $lab

Say 'Дальше'
Write-Host "1. Роутер vmgw-router: установите Ubuntu Server (можно вариант «minimized»), включите OpenSSH."
Write-Host "   Сеть в установщике не трогайте. После установки на роутере:"
Write-Host "     sudo mkdir -p /mnt/hgfs && sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other"
Write-Host "     sudo bash /mnt/hgfs/vmgw/router-install.sh"
Write-Host "2. Панель: http://$($mgmt.Addr):$PanelPort   SSH: ssh -p $SshPort ПОЛЬЗОВАТЕЛЬ@$($mgmt.Addr)"
Write-Host "3. Загрузите профили AmneziaWG в панели и назначьте их ВМ."
Write-Host "4. Установите Ubuntu Desktop на ВМ: $($Clients -join ', '). Интернет там появится, когда"
Write-Host "   ВМ назначен профиль. Подробно: $(Join-Path $LabDir 'kit\README.md')"
Open-Vm $vmwareDir $lab.Router.Vmx
foreach ($c in $lab.Clients) { Open-Vm $vmwareDir $c.Vmx }
