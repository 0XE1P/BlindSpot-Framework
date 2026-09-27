@echo off
chcp 65001 > nul
setlocal

echo ============================================================
echo  BlindSpot GUI - EXE Builder
echo ============================================================
echo.

REM Проверка Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python не найден в PATH
    pause
    exit /b 1
)

REM Установка зависимостей
echo [*] Проверка зависимостей Python...
python -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo [*] Устанавливаю customtkinter...
    pip install customtkinter
)

python -c "import requests" >nul 2>&1
if errorlevel 1 (
    echo [*] Устанавливаю requests...
    pip install requests
)

python -c "import pefile" >nul 2>&1
if errorlevel 1 (
    echo [*] Устанавливаю pefile...
    pip install pefile
)

python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [*] Устанавливаю PyInstaller...
    pip install pyinstaller
)

echo.
echo [*] Очистка старых сборок...
if exist build_exe rmdir /S /Q build_exe
if exist dist\BlindSpotGUI.exe del /Q dist\BlindSpotGUI.exe
if exist BlindSpotGUI.spec del /Q BlindSpotGUI.spec

echo [*] Сборка BlindSpotGUI.exe (это займёт 1-2 минуты)...
pyinstaller --onefile --noconsole --name BlindSpotGUI ^
    --hidden-import customtkinter ^
    --hidden-import requests ^
    --hidden-import urllib3 ^
    --hidden-import certifi ^
    --hidden-import pefile ^
    --hidden-import PIL ^
    --hidden-import PIL._tkinter_finder ^
    --hidden-import darkdetect ^
    --hidden-import packaging ^
    --hidden-import idna ^
    --hidden-import charset_normalizer ^
    --collect-all customtkinter ^
    --collect-all pefile ^
    blindspot_gui.py

if errorlevel 1 (
    echo.
    echo [!] ОШИБКА сборки
    pause
    exit /b 1
)

echo.
echo [*] Копирование файлов рядом с exe...
if not exist dist\BlindSpot_v1.0 mkdir dist\BlindSpot_v1.0
move /Y dist\BlindSpotGUI.exe dist\BlindSpot_v1.0\BlindSpotGUI.exe

xcopy /E /I /Y core dist\BlindSpot_v1.0\core\ >nul
xcopy /E /I /Y src dist\BlindSpot_v1.0\src\ >nul
if exist payloads xcopy /E /I /Y payloads dist\BlindSpot_v1.0\payloads\ >nul
if exist config xcopy /E /I /Y config dist\BlindSpot_v1.0\config\ >nul

if not exist dist\BlindSpot_v1.0\build mkdir dist\BlindSpot_v1.0\build
if not exist dist\BlindSpot_v1.0\payloads\input mkdir dist\BlindSpot_v1.0\payloads\input
if not exist dist\BlindSpot_v1.0\config mkdir dist\BlindSpot_v1.0\config

if exist build.bat copy /Y build.bat dist\BlindSpot_v1.0\build.bat >nul

echo.
echo ============================================================
echo  ГОТОВО
echo ============================================================
echo.
echo  Папка: dist\BlindSpot_v1.0\
echo  Запуск: dist\BlindSpot_v1.0\BlindSpotGUI.exe
echo.
echo  ВАЖНО: не переносить exe отдельно от папки!
echo         core/ и src/ должны лежать рядом с exe.
echo.
pause