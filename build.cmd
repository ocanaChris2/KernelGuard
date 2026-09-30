@echo off
rem Launcher for build.py: finds a Python 3 interpreter, then runs it with the same arguments.
rem   build.cmd [options]        see build.cmd --help
rem On Linux use build.sh.  Run it from a terminal: it asks questions and the window would close at the end.
setlocal

rem "py" is the launcher that python.org installs.  "python" may be the Microsoft Store stub, which
rem fails the version test, so it is only tried second.  The probes use "call" because a .bat shim
rem (pyenv-win installs them) started without it never returns; the final launch does not need to
rem return, so its exit code, from an .exe or a shim, becomes this script's.
call py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if errorlevel 1 goto try_python
py -3 "%~dp0build.py" %*
exit /b %errorlevel%

:try_python
call python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if errorlevel 1 goto no_python
python "%~dp0build.py" %*
exit /b %errorlevel%

:no_python
>&2 echo [FAIL] Python 3.8 or newer is required to run build.py
>&2 echo        Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
>&2 echo        or run: winget install Python.Python.3.12
exit /b 3
