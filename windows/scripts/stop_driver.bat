@echo off
sc stop ScpdDriver
sc delete ScpdDriver
echo Driver stopped and removed.
pause
