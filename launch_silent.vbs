Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd /c .venv312\Scripts\python.exe guardianctl.py start", 0, False
