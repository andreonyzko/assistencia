@echo off
color 0a

echo.
echo *************************************
echo *       Limpando e Otimizando      *
echo *        o Windows...              *
echo *************************************
echo.


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
echo *       Limpeza e Otimização       *
echo *        Concluída com sucesso!    *
echo *************************************
echo.
pause
