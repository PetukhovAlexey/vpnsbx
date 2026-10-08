# Одноразовая подготовка: скачивает установщики VPN-клиентов в tools\ (на хост они НЕ ставятся —
# только внутрь песочницы при каждом запуске) и проверяет, включён ли Windows Sandbox.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tools = New-Item -ItemType Directory -Force "$PSScriptRoot\tools"

$clients = @(
    @{ Name = 'amneziawg-amd64-3.1.0.msi'; Url = 'https://github.com/amnezia-vpn/amneziawg-windows-client/releases/download/3.1.0/amneziawg-amd64-3.1.0.msi' }
    @{ Name = 'OpenVPN-2.7.8-I001-amd64.msi'; Url = 'https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.8-I001-amd64.msi' }
)
foreach ($c in $clients) {
    $dst = Join-Path $tools $c.Name
    if (-not (Test-Path $dst)) {
        Write-Host "Скачиваю $($c.Name)..."
        Invoke-WebRequest -Uri $c.Url -OutFile $dst -UseBasicParsing
    }
    $sig = Get-AuthenticodeSignature $dst
    Write-Host ("{0}: подпись {1} ({2})" -f $c.Name, $sig.Status, $sig.SignerCertificate.Subject)
    if ($sig.Status -ne 'Valid') { Remove-Item $dst; throw "Подпись $($c.Name) недействительна — файл удалён" }
}

if (Test-Path "$env:windir\System32\WindowsSandbox.exe") {
    Write-Host 'Windows Sandbox: включён' -ForegroundColor Green
} else {
    Write-Host 'Windows Sandbox: НЕ включён. Выполните в PowerShell от администратора и перезагрузитесь:' -ForegroundColor Yellow
    Write-Host '  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All'
}
