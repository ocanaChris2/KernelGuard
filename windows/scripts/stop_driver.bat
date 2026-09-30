@echo off
sc stop KernelGuard
sc delete KernelGuard
echo Driver stopped and removed.
pause
