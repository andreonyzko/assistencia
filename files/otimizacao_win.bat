@echo off
chcp 65001
color 0B

cls

echo.
echo *************************************
echo *       Otimização do Windows...    *
echo *************************************
echo Essa otimização realiza os seguintes passos:
echo 1- Verifica a integridade do sistema.
echo 2- Limpa e restaura a imagem do sistema.
echo 3- Desativa indexação de arquivos.
echo 4- Desativa a Cortana e Bing Search.
echo 5- Desativa atividades de usuário.
echo 6- Ajusta configurações de energia para máximo desempenho.
echo 7- Desabilita o Game DVR e outras configs relacionadas.
echo 8- Limpa Lixeira.
echo 9- Recicla a pasta Temp (arquivos temporarios).
echo 10- Exclui arquivos de logs do Windows.
echo 11- Deleta temp files dos 12 primeiros perfis de navegadores.
echo 12- Arquivos temporários do OneDrive, Adobe, VMWare, TeamViewer e Spotify.
echo .
echo Deseja continuar? (S/N)
set /p resposta=Digite S para sim ou N para não: 

if /i "%resposta%"=="N" (
    exit
)

cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Checando a integridade do sistema
echo Verificando a integridade do sistema (sfc /scannow)...
sfc /scannow

cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Limpando e restaurando a imagem do sistema
echo Restaurando a imagem do sistema (dism)...
dism /online /cleanup-image /restorehealth

cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Desativar indexação de arquivos
echo Desativando indexação de arquivos...
sc config "wuauserv" start= disabled
net stop "wuauserv"

cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Desativar Cortana e Bing Search
echo Desativando Cortana e Bing Search...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Desativar atividades de usuário
echo Desativando atividades de usuário...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f

cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Ajustar configurações de energia para desempenho máximo
echo Ajustando configurações de energia para desempenho máximo...
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -change -standby-timeout-ac 0
powercfg -change -monitor-timeout-ac 0
powercfg -change -disk-timeout-ac 0


cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Desabilitar Game DVR e outras configurações de jogos
echo Desativando Game DVR e captura de jogos...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f


cls

echo.
echo *************************************
echo *       Otimizando o Windows...     *
echo *************************************
echo.

:: Limpeza
del c:\$recycle.bin\* /s /q
PowerShell.exe -NoProfile -Command Clear-RecycleBin -Confirm:$false >$null
del $null
for /d %%F in (C:\Users\*) do type nul >"%%F\Appdata\Local\Temp\vazio.txt"
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Temp\ %%F\AppData\Local\Temp\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Temp\vazio.txt
del c:\Windows\Temp\* /s /q
type nul > c:\Windows\Temp\vazio.txt
robocopy c:\Windows\Temp c:\Windows\Temp /s /move /NFL /NDL /NJH /NJS /nc /ns /np
del c:\Windows\Temp\vazio.txt
del C:\Windows\Logs\cbs\*.log
del C:\Windows\setupact.log
attrib -s c:\windows\logs\measuredboot\*.*
del c:\windows\logs\measuredboot\*.log
attrib -h -s C:\Windows\ServiceProfiles\NetworkService\
attrib -h -s C:\Windows\ServiceProfiles\LocalService\
del C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\MpCmdRun.log
del C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log
attrib +h +s C:\Windows\ServiceProfiles\NetworkService\
attrib +h +s C:\Windows\ServiceProfiles\LocalService\
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\*.log /s /q
del C:\Windows\Logs\MeasuredBoot\*.log 
del C:\Windows\Logs\MoSetup\*.log
del C:\Windows\Panther\*.log /s /q
del C:\Windows\Performance\WinSAT\winsat.log /s /q
del C:\Windows\inf\*.log /s /q
del C:\Windows\logs\*.log /s /q
del C:\Windows\SoftwareDistribution\*.log /s /q
del C:\Windows\Microsoft.NET\*.log /s /q
taskkill /F /IM "OneDrive.exe"
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\OneDrive\setup\logs\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\OneDrive\*.odl /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\OneDrive\*.aodl /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\OneDrive\*.otc /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\OneDrive\*.qmlc /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\CrashDumps\*.dmp /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\Explorer\*.db /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\WebCache\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\SettingSync\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\Explorer\ThumbCacheToDelete\*.tmp /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\"Terminal Server Client"\Cache\*.bin /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\INetCache\IE\* /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\INetCache\Low\*.dat /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\INetCache\Low\*.js /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\INetCache\Low\*.htm /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\INetCache\Low\*.txt /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Windows\INetCache\Low\*.jpg /s /q
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Microsoft\Windows\INetCache\IE\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
taskkill /F /IM "msedge.exe"
for /d %%F in (C:\Users\*) do attrib -h -s %%F\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\*.*
for /d %%F in (C:\Users\*) do attrib -h -s %%F\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*.*
for /d %%F in (C:\Users\*) do del %%F\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\*.* /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*.* /s /q
for /d %%F in (C:\Users\*) do attrib +h +s %%F\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content
for /d %%F in (C:\Users\*) do attrib +h +s %%F\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\Cache\Cache_Data\data*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\Cache\Cache_Data\data*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\Cache\Cache_Data\data*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\Cache\Cache_Data\f*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\Cache\Cache_Data\f*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\Cache\Cache_Data\f*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\Cache\Cache_Data\index. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\Cache\Cache_Data\index. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\Cache\Cache_Data\index. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\GPUCache\d*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\GPUCache\d*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\GPUCache\d*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\GPUCache\i*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\GPUCache\i*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\GPUCache\i*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\IndexedDB\https_ntp.msn.com_0.indexeddb.leveldb\*.* /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\IndexedDB\https_ntp.msn.com_0.indexeddb.leveldb\*.* /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\IndexedDB\https_ntp.msn.com_0.indexeddb.leveldb\*.* /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Code Cache"\js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Code Cache"\js\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Code Cache"\js\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Code Cache"\wasm\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Code Cache"\wasm\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Code Cache"\wasm\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Platform Notifications"\*.* /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Platform Notifications"\*.* /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Platform Notifications"\*.* /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\EdgePushStorageWithWinRt\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\EdgePushStorageWithWinRt\*.log /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\EdgePushStorageWithWinRt\*.log /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"File System"\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"File System"\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"File System"\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\CacheStorage\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\*. /s /q)
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\CacheStorage\ %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\ %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\ %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\Database\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Service Worker"\Database\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Service Worker"\Database\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\ScriptCache\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\"Service Worker"\ScriptCache\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\"Service Worker"\ScriptCache\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\EdgeCoupons\coupons_data.db\*.ldb /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\EdgeCoupons\coupons_data.db\*.ldb /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\EdgeCoupons\coupons_data.db\*.ldb /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\EdgeCoupons\coupons_data.db\index. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\EdgeCoupons\coupons_data.db\index. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\EdgeCoupons\coupons_data.db\index. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\Default\EdgeCoupons\coupons_data.db\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Guest Profile"\EdgeCoupons\coupons_data.db\*.log /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\"Profile %%i"\EdgeCoupons\coupons_data.db\*.log /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Microsoft\Edge\"User Data"\BrowserMetrics\*.pma /s /q
taskkill /F /IM "firefox.exe"
for /d %%F in (C:\Users\*) do del %%F\AppData\local\Mozilla\Firefox\Profiles\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\local\Mozilla\Firefox\Profiles\script*.bin /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\local\Mozilla\Firefox\Profiles\startup*.* /s /q
taskkill /F /IM "chrome.exe"
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\Cache\Cache_Data\data*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\Cache\Cache_Data\data*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\Cache\Cache_Data\data*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\Cache\Cache_Data\f*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\Cache\Cache_Data\f*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\Cache\Cache_Data\f*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\Cache\Cache_Data\index. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\Cache\Cache_Data\index. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\Cache\Cache_Data\index. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\GPUCache\d*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\GPUCache\d*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\GPUCache\d*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\GPUCache\i*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\GPUCache\i*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\GPUCache\i*. /s /q)
del C:\Program Files\Google\Chrome\Application\SetupMetrics\*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Code Cache"\js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Code Cache"\js\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Code Cache"\js\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Code Cache"\wasm\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Code Cache"\wasm\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Code Cache"\wasm\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\Storage\data_*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\Storage\data_*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\Storage\data_*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\JumpListIconsRecentClosed\*.tmp /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\JumpListIconsRecentClosed\*.tmp /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\JumpListIconsRecentClosed\*.tmp /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\Storage\index*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\Storage\index*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\Storage\index*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\History-journal*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\History-journal*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\History-journal*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Code Cache"\webui_js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Code Cache"\webui_js\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Code Cache"\webui_js\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\CacheStorage\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\Database\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Service Worker"\Database\*.log /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Service Worker"\Database\*.log /s /q)
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\CacheStorage\ %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\ %%F\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\ %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\Database\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Service Worker"\Database\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Service Worker"\Database\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\ScriptCache\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Guest Profile"\"Service Worker"\ScriptCache\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\"Profile %%i"\"Service Worker"\ScriptCache\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\BrowserMetrics*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Google\Chrome\"User Data"\crash*.pma /s /q
taskkill /F /IM "brave.exe"
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Cache\Cache_Data\data*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\Cache\Cache_Data\data*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Cache\Cache_Data\f*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\Cache\Cache_Data\f*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Cache\Cache_Data\index. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\Cache\Cache_Data\index. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\GPUCache\d*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\GPUCache\d*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\GPUCache\i*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\GPUCache\i*. /s /q
del C:\Program Files\BraveSoftware\Brave-Browser\Application\SetupMetrics\*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Code Cache"\js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Code Cache"\js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Code Cache"\wasm\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Code Cache"\wasm\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Storage\data_*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\Storage\data_*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\JumpListIconsRecentClosed\*.tmp /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\JumpListIconsRecentClosed\*.tmp /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Storage\index*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\Storage\index*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\History-journal*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\History-journal*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Code Cache"\webui_js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Code Cache"\webui_js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\CacheStorage\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\Database\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Service Worker"\Database\*.log /s /q
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\CacheStorage\ %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\ %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\Database\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Service Worker"\Database\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\ScriptCache\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Guest Profile"\"Service Worker"\ScriptCache\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\BrowserMetrics*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\crash*.pma /s /q
taskkill /F /IM "vivaldi.exe"
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\Cache\Cache_Data\data*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\Cache\Cache_Data\data*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\Cache\Cache_Data\data*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\Cache\Cache_Data\f*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\Cache\Cache_Data\f*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\Cache\Cache_Data\f*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\Cache\Cache_Data\index. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\Cache\Cache_Data\index. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\Cache\Cache_Data\index. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\GPUCache\d*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\GPUCache\d*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\GPUCache\d*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\GPUCache\i*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\GPUCache\i*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\GPUCache\i*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Code Cache"\js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Code Cache"\js\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Code Cache"\js\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Code Cache"\wasm\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Code Cache"\wasm\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Code Cache"\wasm\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\Storage\data_*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\Storage\data_*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\Storage\data_*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\JumpListIconsRecentClosed\*.tmp /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\JumpListIconsRecentClosed\*.tmp /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\JumpListIconsRecentClosed\*.tmp /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\Storage\index*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\Storage\index*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\Storage\index*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\History-journal*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\History-journal*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\History-journal*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Code Cache"\webui_js\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Code Cache"\webui_js\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Code Cache"\webui_js\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\CacheStorage\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\Database\*.log /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Service Worker"\Database\*.log /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Service Worker"\Database\*.log /s /q)
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\CacheStorage\ %%F\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Service Worker"\CacheStorage\ %%F\AppData\Local\Vivaldi\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do robocopy %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\ %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Service Worker"\CacheStorage\ /s /move /NFL /NDL /NJH /NJS /nc /ns /np)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\Database\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Service Worker"\Database\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Service Worker"\Database\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\ScriptCache\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Guest Profile"\"Service Worker"\ScriptCache\*. /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\"Profile %%i"\"Service Worker"\ScriptCache\*. /s /q)
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\BrowserMetrics*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Vivaldi\"User Data"\crash*.pma /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Spotify\Data\*.file /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Spotify\Browser\Cache\"Cache_Data"\f*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Local\Spotify\Browser\GPUCache\*. /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Roaming\Adobe\Common\"Media Cache files"\*.* /s /q
for /d %%F in (C:\Users\*) do del %%F\AppData\Roaming\Adobe\*.log /s /q
del C:\ProgramData\VMware\logs\*.log /s /q
for /l %%i in (1,1,12) do (for /d %%F in (C:\Users\*) do del %%F\AppData\Local\TeamViewer\EdgeBrowserControl\Persistent\data_*.  /s /q)
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /S /M *_0 /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /S /M *_1 /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /S /M *_2 /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /S /M *_3 /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /S /M *_4 /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /S /M *_5 /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /M "f_*." /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /M "data.*" /C "cmd /c del @path"))
for /d %%u in (C:\Users\*) do (if exist "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" (forfiles /P "%%u\AppData\Local\TeamViewer\EdgeBrowserControl" /M "index.*" /C "cmd /c del @path"))


cls

echo.
echo *************************************
echo *       Otimização Concluída!      *
echo *************************************
echo.
pause
