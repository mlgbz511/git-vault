# -*- coding: utf-8 -*-
"""
Git-Vault Enterprise Service Manager
提供一站式服务持久化生命周期管理：
- start / stop / restart
- status (端口监听、PID、自启项、日志)
- install / uninstall (免管理员权限的 Windows 登录自启托管)
"""
import os
import sys
import subprocess
import shutil

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "server.log")
VBS_PATH = os.path.join(BASE_DIR, "core", "daemon.vbs")
TASK_NAME = "GitVaultEnterpriseServer"
PORT = 8765

STARTUP_DIR = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
STARTUP_LINK_NAME = "GitVault-AutoStart.vbs"
STARTUP_LINK_PATH = os.path.join(STARTUP_DIR, STARTUP_LINK_NAME)


def get_listening_pids(port=PORT):
    """查找指定端口的 LISTENING 进程 PID 列表"""
    pids = []
    try:
        out = subprocess.check_output("netstat -ano", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) not in pids:
                        pids.append(int(pid))
    except Exception:
        pass
    return pids


def start_service():
    """静默脱壳启动服务"""
    pids = get_listening_pids()
    if pids:
        print(f"[WARN] 服务已在运行中 (PID: {pids[0]})! Web 控制台: http://127.0.0.1:{PORT}")
        return True

    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(VBS_PATH):
        print(f"[FAIL] 守护脚本不存在: {VBS_PATH}")
        return False

    print("[INFO] 正在通过静默守护器 (daemon.vbs) 脱壳启动服务...")
    subprocess.Popen(["wscript.exe", VBS_PATH], shell=True)

    import time
    for _ in range(6):
        time.sleep(0.5)
        pids = get_listening_pids()
        if pids:
            print(f"[OK] 服务脱壳启动成功 (PID: {pids[0]})!")
            print(f"[OK] Web 控制台已就绪: http://127.0.0.1:{PORT}")
            return True

    print(f"[WARN] 启动命令已触发，但尚未检测到端口 {PORT} 监听，请稍候执行 status 查看。")
    return False


def stop_service():
    """优雅停止服务"""
    pids = get_listening_pids()
    if not pids:
        print(f"[INFO] 端口 {PORT} 空闲，当前未在运行。")
        return True

    for pid in pids:
        print(f"[INFO] 正在终止进程 PID: {pid} ...")
        try:
            subprocess.run(f"taskkill /F /PID {pid}", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[OK] 进程 {pid} 已终止。")
        except Exception as e:
            print(f"[WARN] 终止进程 {pid} 异常: {e}")

    return True


def restart_service():
    """重启服务"""
    print("[INFO] 正在重启 Git-Vault 服务...")
    stop_service()
    import time
    time.sleep(1)
    start_service()


def check_autostart_status():
    """检测当前自启配置"""
    modes = []
    if os.path.exists(STARTUP_LINK_PATH):
        modes.append("用户自启目录 (shell:startup)")
    try:
        res = subprocess.run(f'schtasks /query /tn "{TASK_NAME}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            modes.append(f"计划任务 ({TASK_NAME})")
    except Exception:
        pass
    return modes


def install_task():
    """配置免权限登录自启与计划任务"""
    print("[INFO] 正在配置 Windows 登录开机自启...")
    installed_any = False

    # 1. 优先使用 Windows Startup 目录（免管理员权限，100% 成功）
    try:
        os.makedirs(STARTUP_DIR, exist_ok=True)
        vbs_content = (
            'Set WshShell = CreateObject("WScript.Shell")\r\n'
            f'WshShell.Run "wscript.exe ""{VBS_PATH}""", 0, False\r\n'
        )
        with open(STARTUP_LINK_PATH, "w", encoding="utf-8") as f:
            f.write(vbs_content)
        print(f"[OK] 已在用户启动目录注册自启托管: {STARTUP_LINK_NAME}")
        installed_any = True
    except Exception as e:
        print(f"[WARN] 写入用户自启目录失败: {e}")

    # 2. 尝试追加注册计划任务（如果已有管理员权限则更稳健）
    try:
        tr_cmd = f'wscript.exe "{VBS_PATH}"'
        cmd = f'schtasks /create /tn "{TASK_NAME}" /tr "{tr_cmd}" /sc ONLOGON /f'
        res = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            print(f"[OK] 已同步注册 Windows 计划任务: {TASK_NAME}")
            installed_any = True
    except Exception:
        pass

    if installed_any:
        print("[OK] 自启托管配置完毕！开机登录桌面后将自动完全静默拉起 Git-Vault 服务。")
        start_service()
        return True
    else:
        print("[FAIL] 自启配置失败。")
        return False


def uninstall_task():
    """卸载开机自启"""
    print("[INFO] 正在移除开机自启托管配置...")
    removed = False
    if os.path.exists(STARTUP_LINK_PATH):
        try:
            os.remove(STARTUP_LINK_PATH)
            print("[OK] 已移除用户启动项目录项。")
            removed = True
        except Exception as e:
            print(f"[WARN] 移除启动项失败: {e}")

    try:
        res = subprocess.run(f'schtasks /delete /tn "{TASK_NAME}" /f', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            print("[OK] 已移除计划任务项。")
            removed = True
    except Exception:
        pass

    if removed:
        print("[OK] 开机自启托管已完全卸载。")
    else:
        print("[INFO] 当前未发现任何开机自启配置。")
    return True


def status_service():
    """查看运行状态"""
    print("=" * 60)
    print("  Git-Vault Enterprise 服务运行与持久化状态检查")
    print("=" * 60)
    pids = get_listening_pids()
    if pids:
        print(f"  运行状态: [OK] 正在运行 (ONLINE)")
        print(f"  进程 PID: {', '.join(map(str, pids))}")
        print(f"  监听地址: 127.0.0.1:{PORT}")
        print(f"  Web 入口: http://127.0.0.1:{PORT}")
    else:
        print(f"  运行状态: [STOPPED] 未运行 (OFFLINE)")
        print(f"  监听端口: {PORT} 空闲")

    print()
    modes = check_autostart_status()
    if modes:
        print(f"  自启托管: [OK] 已开启 -> {' + '.join(modes)}")
    else:
        print(f"  自启托管: [NONE] 未配置 (执行 'service.cmd install' 开启)")

    print()
    if os.path.exists(LOG_FILE):
        print("  最新运行日志 (最后 5 行):")
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for line in lines[-5:]:
                    print("   ", line.rstrip())
        except Exception as e:
            print(f"    (读取日志失败: {e})")
    else:
        print("  日志文件: 暂无日志文件 (logs/server.log)")
    print("=" * 60)


def print_help():
    print("=" * 60)
    print("  Git-Vault Enterprise 服务持久化管理工具")
    print("=" * 60)
    print("  用法: service.cmd [命令]")
    print()
    print("  可用命令:")
    print("    start       - 静默启动后台服务 (完全脱壳无黑框)")
    print("    stop        - 停止后台服务 (释放 8765 端口)")
    print("    restart     - 重启后台服务")
    print("    status      - 查看当前运行状态、PID 及开机自启配置")
    print("    install     - 一键开启开机自启 (免管理员权限，静默托管)")
    print("    uninstall   - 卸载开机自启托管")
    print("=" * 60)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return

    cmd = args[0].lower()
    if cmd == "start":
        start_service()
    elif cmd == "stop":
        stop_service()
    elif cmd == "restart":
        restart_service()
    elif cmd == "status":
        status_service()
    elif cmd == "install":
        install_task()
    elif cmd == "uninstall":
        uninstall_task()
    else:
        print(f"[ERROR] 未知命令: {cmd}")
        print_help()


if __name__ == "__main__":
    main()
