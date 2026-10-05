@echo off
setlocal
where cl >nul 2>nul
if errorlevel 1 (
  echo Install Visual Studio Build Tools with the C++ workload, then run this from a Developer Command Prompt.
  exit /b 1
)
if "%INCLUDE%"=="" (
  echo Run this from a Visual Studio Developer Command Prompt so cl.exe finds the SDK headers.
  exit /b 1
)
echo Building authv4.dll, needs libcurl and OpenSSL dev files on LIB/INCLUDE.
cl /LD /O2 authv4.c /Fe:authv4.dll /link /DEF:authv4.def libcurl.lib libcrypto.lib
if errorlevel 1 exit /b 1
if not exist ..\dist mkdir ..\dist
copy /y authv4.dll ..\dist\authv4.dll
echo Wrote sdk\dist\authv4.dll
