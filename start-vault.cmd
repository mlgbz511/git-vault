@echo off
chcp 65001 >nul
title Git-Vault Enterprise Gateway Launcher

echo ========================================================
echo   Git-Vault 本地宿主桌面启动器 (Host Native Launcher)
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/3] 正在检查端口 8765 监听状态...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8765" ^| findstr "LISTENING"') do (
    echo [*] 正在释放旧实例 PID: %%a...
    taskkill /f /pid %%a >nul 2>&1
)

echo [2/3] 正在宿主物理桌面会话中拉起 Git-Vault 服务...
start "" python server.py

echo [3/3] 正在唤起默认浏览器打开控制台...
timeout /t 1 /nobreak >nul
start http://127.0.0.1:8765

echo.
echo [OK] 服务已就绪！此控制台窗口可随时关闭。
echo.
pause
