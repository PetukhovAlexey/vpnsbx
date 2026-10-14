@echo off
rem Creates the vmgw lab in VMware Workstation. Parameters are passed to New-VmGwLab.ps1,
rem e.g.  Setup.cmd -Clients ws1,ws2   or   Setup.cmd -AddClient ws3
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\New-VmGwLab.ps1" %*
pause
