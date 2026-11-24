@echo off
setlocal EnableExtensions
title Epiphyllum Sentinel
cd /d "%~dp0"

set "PROJECT=epiphyllum-sentinel"
set "URL=http://localhost:8080"
set "READY=%URL%/api/v1/health/ready"
set "MODE=live"
set "GENERATION_PAUSED=0"
set "MODE_SET=0"
set "NO_PAUSE="
set "RC=0"

:parse
if "%~1"=="" goto args_done
if /I "%~1"=="--live" goto arg_live
if /I "%~1"=="--paused" goto arg_paused
if /I "%~1"=="--no-pause" (
  set "NO_PAUSE=1"
  shift
  goto parse
)
if /I "%~1"=="--help" goto usage
goto bad_args

:arg_live
if "%MODE_SET%"=="1" goto bad_args
set "MODE=live"
set "GENERATION_PAUSED=0"
set "MODE_SET=1"
shift
goto parse

:arg_paused
if "%MODE_SET%"=="1" goto bad_args
set "MODE=paused"
set "GENERATION_PAUSED=1"
set "MODE_SET=1"
shift
goto parse

:args_done
where docker >nul 2>nul
if errorlevel 1 (
  echo [ERROR] No se encontro el comando docker.
  echo Inicia Docker Desktop en modo contenedores Linux y vuelve a intentar.
  set "RC=1"
  goto done
)
docker info >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Docker Desktop no responde.
  echo Inicia Docker Desktop y espera a que termine de arrancar.
  set "RC=1"
  goto done
)
set "OSTYPE="
for /f "delims=" %%T in ('docker info --format "{{.OSType}}" 2^>nul') do set "OSTYPE=%%T"
if /I not "%OSTYPE%"=="linux" (
  echo [ERROR] Docker Desktop debe estar en modo contenedores Linux.
  set "RC=1"
  goto done
)

echo Compilando backend y frontend...
docker compose -p "%PROJECT%" -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml build backend frontend
if errorlevel 1 (
  echo [ERROR] El build fallo. La instalacion actual queda sin cambios.
  set "RC=1"
  goto logs
)

set "HAS_BACKEND="
set "HAS_FRONTEND="
for /f "delims=" %%S in ('docker compose -p "%PROJECT%" -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml ps --status running --services 2^>nul') do (
  if /I "%%S"=="backend" set "HAS_BACKEND=1"
  if /I "%%S"=="frontend" set "HAS_FRONTEND=1"
)
set "BOTH_RUNNING="
if defined HAS_BACKEND if defined HAS_FRONTEND set "BOTH_RUNNING=1"
if defined BOTH_RUNNING (
  echo Instalacion en ejecucion: recreando solo backend y frontend...
  docker compose -p "%PROJECT%" -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml up -d --no-deps backend frontend
) else (
  echo Instalacion detenida: arrancando con sus dependencias...
  docker compose -p "%PROJECT%" -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml up -d
)
if errorlevel 1 (
  echo [ERROR] No se pudo arrancar Sentinel.
  set "RC=1"
  goto logs
)

echo Esperando a que Sentinel responda...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$deadline=(Get-Date).AddSeconds(180); while((Get-Date) -lt $deadline){ try { $r=Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri '%READY%'; if($r.StatusCode -eq 200){ exit 0 } } catch {}; Start-Sleep -Seconds 2 }; exit 1"
if errorlevel 1 (
  echo [ERROR] Sentinel no respondio en el endpoint de readiness dentro de 180 segundos.
  echo Modo efectivo: %MODE%.
  set "RC=1"
  goto logs
)

echo.
echo Modo efectivo: %MODE%.
echo Sentinel disponible en %URL%
goto done

:logs
echo.
echo Para ver los logs:
echo   docker compose -p "%PROJECT%" -f compose.yaml -f compose.organized.yaml -f compose.lab.example.yaml logs --tail 100 backend frontend
goto done

:usage
echo Uso: iniciar-laboratorio.bat [--live] [--paused] [--no-pause]
echo   Sin argumentos o --live: GENERATION_PAUSED=0, arranque normal.
echo   --paused: ensayo de MCP y CVE sin generacion de IA.
echo   --no-pause: no esperar una tecla al terminar.
set "RC=0"
goto done

:bad_args
echo [ERROR] Argumento no reconocido.
echo Usa --paused, --live, --no-pause o --help.
set "RC=2"
goto done

:done
set "EXIT_CODE=%RC%"
if not defined NO_PAUSE pause
endlocal & exit /b %EXIT_CODE%
