' Git-Vault 无控制台黑框后台启动脚本 (Silent Host Desktop Launcher)
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

' 1. 释放旧端口
WshShell.Run "cmd /c for /f ""tokens=5"" %a in ('netstat -aon ^| findstr "":8765"" ^| findstr ""LISTENING""') do taskkill /f /pid %a", 0, True

' 2. 静默拉起服务在 WinSta0\Default 物理桌面
WshShell.Run "python server.py", 0, False

' 3. 唤起浏览器
WScript.Sleep 1000
WshShell.Run "http://127.0.0.1:8765"
