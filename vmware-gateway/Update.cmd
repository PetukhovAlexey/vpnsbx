@echo off
rem Updates vmgw software in all running VMs of the labs to this kit version.
rem e.g.  Update.cmd   or   Update.cmd -CheckOnly   or   Update.cmd -RebuildAwg
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\Update-VmGwLab.ps1" %*
pause
