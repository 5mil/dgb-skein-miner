@echo off
REM dgb-skein-miner launcher (Windows)
REM Edit config.json or pass flags directly

set BIN=miner.exe

if not exist "%BIN%" (
  echo [dgb-skein-miner] Binary not found. Build with: ucm compile .main miner.exe
  exit /b 1
)

%BIN% --config-file config.json %*
