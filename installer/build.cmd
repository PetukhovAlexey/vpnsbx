@echo off
rem Сборка vpnsbx.msi: exe (с ресурсами из winres) и пакет WiX 6.
rem Нужны Go и WiX: dotnet tool install --global wix --version "6.*"
setlocal
set VERSION=0.1.0
set ROOT=%~dp0..
set OUT=%ROOT%\dist
cd /d "%ROOT%" || exit /b 1
if not exist "%OUT%" mkdir "%OUT%"

go run github.com/tc-hib/go-winres@v0.3.3 make --in winres\svc.json --out cmd\vpnsbx\rsrc --arch amd64 --product-version %VERSION% --file-version %VERSION% || exit /b 1
go run github.com/tc-hib/go-winres@v0.3.3 make --in winres\ui.json --out cmd\vpnsbx-ui\rsrc --arch amd64 --product-version %VERSION% --file-version %VERSION% || exit /b 1
go build -trimpath -ldflags "-s -w" -o "%OUT%\vpnsbx.exe" .\cmd\vpnsbx || exit /b 1
go build -trimpath -ldflags "-s -w -H windowsgui" -o "%OUT%\vpnsbx-ui.exe" .\cmd\vpnsbx-ui || exit /b 1

wix build -arch x64 -ext WixToolset.Util.wixext -d Version=%VERSION% -d BinDir="%OUT%" -o "%OUT%\vpnsbx-%VERSION%.msi" installer\Package.wxs || exit /b 1
echo %OUT%\vpnsbx-%VERSION%.msi
