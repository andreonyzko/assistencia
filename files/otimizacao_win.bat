@echo off
color 0a

echo.
echo *************************************
echo *       Otimizando o Windows...    *
echo *************************************
echo.

:: Checando a integridade do sistema
echo Verificando a integridade do sistema (sfc /scannow)...
sfc /scannow

:: Limpando e restaurando a imagem do sistema
echo Restaurando a imagem do sistema (dism)...
dism /online /cleanup-image /restorehealth

:: Desativar indexação de arquivos
echo Desativando indexação de arquivos...
sc config "wuauserv" start= disabled
net stop "wuauserv"

:: Desativar Cortana e Bing Search
echo Desativando Cortana e Bing Search...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

:: Desativar atividades de usuário
echo Desativando atividades de usuário...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f

:: Ajustar configurações de energia para desempenho máximo
echo Ajustando configurações de energia para desempenho máximo...
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -change -standby-timeout-ac 0
powercfg -change -monitor-timeout-ac 0
powercfg -change -disk-timeout-ac 0

:: Desabilitar Game DVR e outras configurações de jogos
echo Desativando Game DVR e captura de jogos...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f

:: Limpeza de arquivos de navegadores
echo Limpando cache do Google Chrome...
del /q /f /s "%localappdata%\Google\Chrome\User Data\Default\Cache\*"
echo Limpando cache do Microsoft Edge...
del /q /f /s "%localappdata%\Microsoft\Edge\User Data\Default\Cache\*"
echo Limpando cache do Mozilla Firefox...
del /q /f /s "%appdata%\Mozilla\Firefox\Profiles\*.default-release\cache2\entries\*"
echo Limpando cache do Opera...
del /q /f /s "%appdata%\Opera Software\Opera Stable\Cache\*"
echo Limpando cache do Brave Browser...
del /q /f /s "%localappdata%\BraveSoftware\Brave-Browser\User Data\Default\Cache\*"

:: Limpando arquivos temporários do sistema
echo Limpando arquivos temporários do sistema...
del /q /f %emptyFile%
del /q /f %tempFile%


:: Parando e reiniciando serviços
echo Parando serviço SysMain (Superfetch)...
net stop sysmain

:: Limpando arquivos de Prefetch, Temp e outros
echo Limpando Prefetch...
del /f /s /q %systemroot%\Prefetch\*
echo Limpando arquivos temporários do sistema...
del /f /s /q %systemroot%\Temp\*
echo Limpando histórico de navegação...
del /s /f /q "%userprofile%\Local Settings\History"
echo Limpando cookies...
del /s /f /q "%userprofile%\Cookies"
echo Limpando arquivos recentes...
del /s /f /q "%userprofile%\Recent"
echo Limpando impressoras...
del /q /f /s "%windir%\System32\spool\PRINTERS\*" >nul 2>&1

:: Limpando caches e logs do Windows
echo Limpando o histórico de escaneamentos do Windows Defender...
del /q /f /s "%ProgramData%\Microsoft\Windows Defender\Scans\History\*" >nul 2>&1
echo Limpando logs do Windows Update...
del /q /f /s "%windir%\SoftwareDistribution\DataStore\Logs\*" >nul 2>&1
echo Limpando logs do CBS...
del /q /f /s "%windir%\Logs\CBS\*" >nul 2>&1

:: Limpeza de disco
echo Iniciando limpeza de disco...
cleanmgr /sagerun:1

:: Otimização de memória
echo Otimizando memória com EmptyStandbyList...
set "emptyStandbyList=%scriptDir%EmptyStandbyList.exe"
if not exist "%emptyStandbyList%" (
    echo [ERRO] O arquivo EmptyStandbyList.exe nao foi encontrado.
    echo Certifique-se de que ele esta na mesma pasta deste script.
    exit /b
)
"%emptyStandbyList%" workingsets
"%emptyStandbyList%" modifiedpagelist
"%emptyStandbyList%" standbylist

:: Ajustes de registro para otimização do Explorador de Arquivos
echo Ajustando configurações do Explorador de Arquivos...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f



echo.
echo *************************************
echo *       Otimização Concluída!      *
echo *************************************
echo.
pause
