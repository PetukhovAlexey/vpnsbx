@echo off
rem Сборка vpnsbx-<версия>.msi и vpnsbx-setup-<версия>.exe (драйвер + msi).
rem Нужны Go и WiX 6:
rem   dotnet tool install --global wix --version "6.*"
rem   wix extension add -g WixToolset.Util.wixext/6.0.2
rem   wix extension add -g WixToolset.BootstrapperApplications.wixext/6.0.2
setlocal
set VERSION=0.1.0
set DRIVER=Windows.Packet.Filter.3.6.2.1.x64.msi
set DRIVER_URL=https://github.com/wiresock/ndisapi/releases/download/v3.6.2/%DRIVER%
set DRIVER_SHA256=9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c
set ROOT=%~dp0..
set OUT=%ROOT%\dist
set REDIST=%ROOT%\installer\redist
cd /d "%ROOT%" || exit /b 1
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%REDIST%" mkdir "%REDIST%"

go run github.com/tc-hib/go-winres@v0.3.3 make --in winres\svc.json --out cmd\vpnsbx\rsrc --arch amd64 --product-version %VERSION% --file-version %VERSION% || exit /b 1
go run github.com/tc-hib/go-winres@v0.3.3 make --in winres\ui.json --out cmd\vpnsbx-ui\rsrc --arch amd64 --product-version %VERSION% --file-version %VERSION% || exit /b 1
go build -trimpath -ldflags "-s -w" -o "%OUT%\vpnsbx.exe" .\cmd\vpnsbx || exit /b 1
go build -trimpath -ldflags "-s -w -H windowsgui" -o "%OUT%\vpnsbx-ui.exe" .\cmd\vpnsbx-ui || exit /b 1

wix build -arch x64 -ext WixToolset.Util.wixext -d Version=%VERSION% -d BinDir="%OUT%" -o "%OUT%\vpnsbx-%VERSION%.msi" installer\Package.wxs || exit /b 1

rem MSI драйвера: официальный релиз wiresock, сверяется по SHA-256.
if not exist "%REDIST%\%DRIVER%" curl.exe -sSfL -o "%REDIST%\%DRIVER%" "%DRIVER_URL%" || exit /b 1
powershell -NoProfile -Command "if ((Get-FileHash -Algorithm SHA256 '%REDIST%\%DRIVER%').Hash -ne '%DRIVER_SHA256%') { Write-Error 'driver SHA-256 mismatch'; exit 1 }" || exit /b 1

wix build -arch x64 -ext WixToolset.BootstrapperApplications.wixext -d Version=%VERSION% -d BinDir="%OUT%" -d DriverMsi="%REDIST%\%DRIVER%" -o "%OUT%\vpnsbx-setup-%VERSION%.exe" installer\Bundle.wxs || exit /b 1
echo %OUT%\vpnsbx-%VERSION%.msi
echo %OUT%\vpnsbx-setup-%VERSION%.exe
