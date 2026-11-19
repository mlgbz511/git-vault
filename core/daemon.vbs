Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
baseDir = fso.GetParentFolderName(scriptDir)

logDir = baseDir & "\logs"
If Not fso.FolderExists(logDir) Then
    fso.CreateFolder(logDir)
End If

' SECURITY/STABILITY: never inherit DSH sandbox shims or injected Python/Git vars.
cleanPath = "<path>\Program Files\Git\cmd;<path>\Program Files\Git\bin;" & _
    WshShell.ExpandEnvironmentStrings("%SystemRoot%") & "\system32;" & _
    WshShell.ExpandEnvironmentStrings("%SystemRoot%") & ";" & _
    WshShell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\Wbem;" & _
    WshShell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0;" & _
    WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Microsoft\WindowsApps"
WshShell.Environment("PROCESS")("PATH") = cleanPath
WshShell.Environment("PROCESS")("PYTHONPATH") = ""
WshShell.Environment("PROCESS")("GIT_SSH_COMMAND") = ""
WshShell.Environment("PROCESS")("GIT_ASKPASS") = ""
WshShell.Environment("PROCESS")("SSH_ASKPASS") = ""

cmd = "cmd.exe /c cd /d """ & baseDir & """ && python server.py >> """ & logDir & "\server.log"" 2>&1"
WshShell.Run cmd, 0, False
