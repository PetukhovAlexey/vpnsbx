# VmGwCommon.ps1 — общие функции New-VmGwLab.ps1 и Update-VmGwLab.ps1 (подключается через точку).

$Utf8 = New-Object Text.UTF8Encoding $false
$KitSrc = Join-Path (Split-Path $PSScriptRoot -Parent) 'guest'

function Say([string]$t) { Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }
function Fail([string]$t) { throw $t }

function Find-VMware {
    $dirs = @()
    foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation', 'HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation') {
        $p = Get-ItemProperty -Path $k -Name InstallPath -ErrorAction SilentlyContinue
        if ($p) { $dirs += $p.InstallPath }
    }
    $dirs += "${env:ProgramFiles(x86)}\VMware\VMware Workstation", "$env:ProgramFiles\VMware\VMware Workstation"
    foreach ($d in $dirs) {
        if ($d -and (Test-Path (Join-Path $d 'vmware.exe')) -and (Test-Path (Join-Path $d 'vmware-vdiskmanager.exe'))) { return $d }
    }
    Fail 'VMware Workstation не найден'
}

# Комплект в папке лаборатории (общая папка «vmgw» в ВМ) — точная копия guest\ + README и lab.conf.
function Copy-Kit($lab) {
    $kit = Join-Path $lab.LabDir 'kit'
    New-Item -ItemType Directory -Force -Path $kit | Out-Null
    Get-ChildItem -LiteralPath $kit -Force | Where-Object { $_.Name -ne 'lab.conf' } | Remove-Item -Recurse -Force
    Copy-Item -Path (Join-Path $KitSrc '*') -Destination $kit -Recurse -Force
    Get-ChildItem -Path $kit -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
    $readme = Join-Path (Split-Path $PSScriptRoot -Parent) 'README.md'
    if (Test-Path $readme) { Copy-Item $readme $kit -Force }
}

# Версия комплекта: VERSION + отпечаток файлов. Тот же алгоритм — kit_stamp в guest/lib.sh.
function Get-KitStamp([string]$dir) {
    $root = (Resolve-Path -LiteralPath $dir).Path.TrimEnd('\')
    $rel = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force |
        Where-Object { $_.Name -ne 'lab.conf' -and $_.Name -ne 'README.md' -and $_.FullName -notmatch '\\__pycache__\\' } |
        ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') })
    [Array]::Sort($rel, [StringComparer]::Ordinal)
    $sb = New-Object Text.StringBuilder
    foreach ($r in $rel) {
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root $r)).Hash.ToLower()
        [void]$sb.Append("$h  $r`n")
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    $sum = -join ($sha.ComputeHash($Utf8.GetBytes($sb.ToString())) | ForEach-Object { '{0:x2}' -f $_ })
    $ver = (Get-Content -Raw -LiteralPath (Join-Path $root 'VERSION')) -replace '[\s]', ''
    "$ver+$($sum.Substring(0, 12))"
}

function Find-SshTool([string]$name) {
    # Сначала OpenSSH для Windows: ssh из Git/MSYS хуже работает с консолью (ввод пароля sudo через -t).
    foreach ($d in "$env:SystemRoot\System32\OpenSSH", "$env:ProgramFiles\OpenSSH") {
        $p = Join-Path $d "$name.exe"
        if (Test-Path $p) { return $p }
    }
    $c = Get-Command "$name.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    Fail "Не найден $name.exe: установите «Клиент OpenSSH» (Параметры → Система → Дополнительные компоненты)"
}
