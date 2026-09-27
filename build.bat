@echo off
chcp 65001 > nul
setlocal
set PATH=C:\msys64\ucrt64\bin;%PATH%

taskkill /F /IM loader_debug.exe >nul 2>&1
taskkill /F /IM loader.exe >nul 2>&1
taskkill /F /IM payload_test.exe >nul 2>&1
timeout /t 1 /nobreak >nul

if not exist build mkdir build

echo.
echo [0/2] Сборка payload_test.exe...
gcc ^
    -O2 -s -mwindows ^
    -nostdlib -nostdinc ^
    -ffreestanding -fno-builtin ^
    -fno-stack-protector -fno-ident ^
    -Wl,--entry=payload_entry ^
    -Wl,--subsystem,windows ^
    -o build\payload_test.exe ^
    src\payload_test\payload_test.c ^
    src\loader\api_resolver.c ^
    src\loader\pe_parser.c ^
    src\common\memory.c

if errorlevel 1 ( echo [!] Ошибка & exit /b 1 )

echo.
echo [1/2] Сборка loader_debug.exe (отладочный, консольный)...
gcc ^
    -O2 -s -mconsole ^
    -o build\loader_debug.exe ^
    src\loader_debug\main_debug.c ^
    src\loader\pe_parser.c ^
    src\loader\api_resolver.c ^
    src\loader\reflective.c ^
    src\common\memory.c

if errorlevel 1 ( echo [!] Ошибка & exit /b 1 )

echo.
echo [+] Готово.
endlocal