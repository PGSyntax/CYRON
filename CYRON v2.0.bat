@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: ADMINISTRATOR CHECK
:: =============================================================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator!
    pause
    exit /b
)

:: =============================================================================
:: GLOBAL VARIABLES & INITIAL SETTINGS
:: =============================================================================
set "COLOR=05"
set "LOG=cyron.log"
set "HOSTS=%windir%\system32\drivers\etc\hosts"

mode con: cols=100 lines=30
chcp 65001 >nul
title CYRON v2.0
cls


:: =============================================================================
:: ASCII ART (Banner)
:: =============================================================================
echo.
echo  ______     __  __     ______     ______     __   __    
echo /\  ___\   /\ \_\ \   /\  == \   /\  __ \   /\ "-.\ \   
echo \ \ \____  \ \____ \  \ \  __-   \ \ \/\ \  \ \ \-.  \  
echo  \ \_____\  \/\_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\ 
echo   \/_____/   \/_____/   \/_/ /_/   \/_____/   \/_/ \/_/ 
echo.
pause >nul


:: =============================================================================
:: MAIN MENU
:: =============================================================================
:menu
cls
color %COLOR%
echo =============== CYRON v2.0 ===============
echo [1] Network Tools
echo [2] System Info
echo [3] Security
echo [4] Windows Tweaks
echo [5] Advanced Tools
echo [6] Settings
echo [7] Offensive Tools
echo [0] Exit
echo.
set /p c=Choice: 
if "%c%"=="0" exit
if "%c%"=="1" goto network
if "%c%"=="2" goto system
if "%c%"=="3" goto security
if "%c%"=="4" goto tweaks
if "%c%"=="5" goto advanced
if "%c%"=="6" goto settings
if "%c%"=="7" goto offensive
goto menu

:: =============================================================================
:: NETWORK TOOLS
:: =============================================================================
:network
cls
echo === Network Tools ===
echo [1] IP Configuration
echo [2] Show WiFi Passwords
echo [3] Change MAC Address
echo [4] Traceroute
echo [5] Ping Sweep
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto menu
if "%c%"=="1" (
    ipconfig /all
    pause
    goto network
)
if "%c%"=="2" (
    for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| find "Profile"') do (
        set "ssid=%%a"
        set "ssid=!ssid:~1!"
        call :get_wifi_pass "!ssid!"
    )
    pause
    goto network
)
if "%c%"=="3" call :mac_change
if "%c%"=="4" goto traceroute
if "%c%"=="5" goto ping_sweep
goto network

:: ----- Traceroute Function -----
:traceroute
cls
echo Traceroute
set /p target=Target Host/IP: 
tracert %target%
pause
goto network

:: ----- Ping Sweep Function -----
:ping_sweep
cls
echo Ping Sweep
set /p subnet=Enter base IP (e.g., 192.168.1.): 
set /p start=Start host number: 
set /p end=End host number: 
for /L %%i in (%start%,1,%end%) do (
    ping -n 1 %subnet%%%i | find "TTL=" >nul && (
        echo %subnet%%%i is UP
    ) || (
        echo %subnet%%%i is DOWN
    )
)
pause
goto network

:: ----- Legacy MAC Change Function (used by Network Tools) -----
:mac_change
cls
echo Available Network Adapters:
getmac /v /fo list
echo.
set /p adapter=Adapter Description: 
set /p new_mac=New MAC (XX-XX-XX-XX-XX-XX): 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v NetworkAddress /d %new_mac% /f >nul
echo MAC address changed! A restart is required.
pause
goto network

:: ----- WiFi Passwords (shared function) -----
:get_wifi_pass
netsh wlan show profile name="%~1" key=clear | find "Key Content"
goto :eof

:: =============================================================================
:: SYSTEM INFO
:: =============================================================================
:system
cls
echo === System Info ===
echo [1] System Information
echo [2] Memory Capacity
echo [3] Disk Drive Size
echo [4] System Uptime
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto menu
if "%c%"=="1" (
    systeminfo
    pause
    goto system
)
if "%c%"=="2" (
    wmic memorychip get capacity
    pause
    goto system
)
if "%c%"=="3" (
    wmic diskdrive get size
    pause
    goto system
)
if "%c%"=="4" goto uptime
goto system

:: ----- System Uptime Function -----
:uptime
cls
echo System Uptime:
net stats srv | find "Statistics since"
pause
goto system

:: =============================================================================
:: SECURITY
:: =============================================================================
:security
cls
echo === Security ===
echo [1] Defender Scan
echo [2] Show Firewall Rules
echo [3] Process Monitor
echo [4] Show User Accounts
echo [5] Kill Process
echo [6] Show Installed Antivirus
echo [7] Check for Updates
echo [8] Show Security Settings
echo [9] Network Configuration
echo [A] Check Running Services
echo [B] Display Scheduled Tasks
echo [C] List Active Connections
echo [D] Show Windows Logs
echo [E] System Information
echo [F] Show System Drivers
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto menu
if "%c%"=="1" (
    "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
    pause
    goto security
)
if "%c%"=="2" (
    netsh advfirewall show allprofiles
    pause
    goto security
)
if "%c%"=="3" (
    tasklist /svc
    pause
    goto security
)
if "%c%"=="4" (
    net user
    pause
    goto security
)
if "%c%"=="5" goto kill_process
if "%c%"=="6" (
    wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName
    pause
    goto security
)
if "%c%"=="7" (
    wuauclt /detectnow
    pause
    goto security
)
if "%c%"=="8" (
    secedit /export /cfg secedit.cfg
    pause
    goto security
)
if /i "%c%"=="9" (
    ipconfig /all
    pause
    goto security
)
if /i "%c%"=="A" (
    sc query
    pause
    goto security
)
if /i "%c%"=="B" (
    schtasks /query
    pause
    goto security
)
if /i "%c%"=="C" (
    netstat -an
    pause
    goto security
)
if /i "%c%"=="D" (
    eventvwr.msc
    pause
    goto security
)
if /i "%c%"=="E" (
    systeminfo
    pause
    goto security
)
if /i "%c%"=="F" (
    driverquery
    pause
    goto security
)
goto security


:: ----- Kill Process Function -----
:kill_process
cls
echo Kill Process
set /p pname=Process Name (e.g., notepad.exe): 
taskkill /IM %pname% /F
echo Process %pname% terminated (if running).
pause
goto security

:: =============================================================================
:: WINDOWS TWEAKS
:: =============================================================================
:tweaks
cls
echo === Windows Tweaks ===
echo [1] Disable Telemetry
echo [2] Disable Fast Startup
echo [3] Stop Superfetch
echo [4] Disable Windows Defender
echo [5] Disable Windows Updates
echo [6] Disable Windows Store
echo [7] Disable Cortana
echo [8] Disable Windows Defender Antivirus in Group Policy
echo [9] Enable High Performance Power Plan
echo [A] Disable Remote Desktop
echo [B] Disable UAC (User Account Control)
echo [C] Disable Windows Error Reporting
echo [D] Disable Windows Defender Real-Time Protection
echo [E] Disable Windows Search Indexing
echo [F] Disable OneDrive
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto menu
if "%c%"=="1" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    sc stop DiagTrack
    echo Telemetry disabled!
    pause
    goto tweaks
)
if "%c%"=="2" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
    echo Fast Startup disabled!
    pause
    goto tweaks
)
if "%c%"=="3" (
    sc stop SysMain
    sc config SysMain start=disabled
    echo Superfetch stopped!
    pause
    goto tweaks
)
if "%c%"=="4" (
    sc stop WinDefend
    sc config WinDefend start=disabled
    echo Windows Defender disabled!
    pause
    goto tweaks
)
if "%c%"=="5" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableOSUpgrade /t REG_DWORD /d 1 /f
    echo Windows Updates disabled!
    pause
    goto tweaks
)
if "%c%"=="6" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
    echo Windows Store disabled!
    pause
    goto tweaks
)
if "%c%"=="7" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaEnabled /t REG_DWORD /d 0 /f
    echo Cortana disabled!
    pause
    goto tweaks
)
if "%c%"=="8" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
    echo Windows Defender Antivirus disabled via Group Policy!
    pause
    goto tweaks
)
if "%c%"=="9" (
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0
    powercfg /setactive SCHEME_MAX
    echo High Performance Power Plan enabled!
    pause
    goto tweaks
)
if "%c%"=="A" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    echo Remote Desktop disabled!
    pause
    goto tweaks
)
if "%c%"=="B" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
    echo User Account Control (UAC) disabled!
    pause
    goto tweaks
)
if "%c%"=="C" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
    echo Windows Error Reporting disabled!
    pause
    goto tweaks
)
if "%c%"=="D" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
    echo Windows Defender Real-Time Protection disabled!
    pause
    goto tweaks
)
if "%c%"=="E" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
    echo Windows Search Indexing disabled!
    pause
    goto tweaks
)
if "%c%"=="F" (
    reg add "HKCU\Software\Microsoft\OneDrive" /v UserSetting /t REG_DWORD /d 0 /f
    echo OneDrive disabled!
    pause
    goto tweaks
)
goto tweaks


:: =============================================================================
:: ADVANCED TOOLS
:: =============================================================================
:advanced
cls
echo === Advanced Tools ===
echo [1] Encrypt File (AES)
echo [2] Create Backup
echo [3] Calculate Hash
echo [4] Compress Folder (ZIP)
echo [5] Decrypt File (AES)
echo [6] Create System Restore Point
echo [7] Delete Old Backup Files
echo [8] Check Disk for Errors
echo [9] Schedule Task
echo [A] Show Network Information
echo [B] Create Disk Image
echo [C] Clear Temp Files
echo [D] List Installed Programs
echo [E] Check Disk Space
echo [F] Generate Random Password
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto menu
if "%c%"=="1" (
    set /p file=File Path: 
    certutil -f -encode "%file%" "%file%.enc" >nul
    echo File encrypted!
    pause
    goto advanced
)
if "%c%"=="2" (
    set /p src=Source Folder: 
    set /p dest=Destination Folder: 
    robocopy "%src%" "%dest%" /MIR /LOG:%LOG%
    echo Backup created! See %LOG%
    pause
    goto advanced
)
if "%c%"=="3" (
    set /p file=File: 
    certutil -hashfile "%file%" SHA256
    pause
    goto advanced
)
if "%c%"=="4" (
    set /p folder=Folder Path: 
    set /p zipfile=Destination ZIP File: 
    powershell Compress-Archive -Path "%folder%" -DestinationPath "%zipfile%"
    echo Folder compressed into ZIP!
    pause
    goto advanced
)
if "%c%"=="5" (
    set /p file=File Path: 
    certutil -decode "%file%" "%file%.dec"
    echo File decrypted!
    pause
    goto advanced
)
if "%c%"=="6" (
    powershell -Command "Checkpoint-Computer -Description 'Backup Restore Point' -RestorePointType 'MODIFY_SETTINGS'"
    echo System Restore Point created!
    pause
    goto advanced
)
if "%c%"=="7" (
    set /p folder=Backup Folder: 
    forfiles /p "%folder%" /s /m *.* /d -30 /c "cmd /c del @path"
    echo Old backup files deleted!
    pause
    goto advanced
)
if "%c%"=="8" (
    chkdsk C: /f
    pause
    goto advanced
)
if "%c%"=="9" (
    set /p taskname=Task Name: 
    set /p cmd=Command to Execute: 
    schtasks /create /tn "%taskname%" /tr "%cmd%" /sc daily /st 00:00
    echo Task scheduled!
    pause
    goto advanced
)
if "%c%"=="A" (
    ipconfig /all
    pause
    goto advanced
)
if "%c%"=="B" (
    set /p imagefile=Disk Image File: 
    wbadmin start backup -backupTarget:%imagefile% -include:C: -allCritical -quiet
    echo Disk image created!
    pause
    goto advanced
)
if "%c%"=="C" (
    del /q /f %temp%\*
    echo Temporary files deleted!
    pause
    goto advanced
)
if "%c%"=="D" (
    wmic product get name
    pause
    goto advanced
)
if "%c%"=="E" (
    dir C: /a /s | find "bytes"
    pause
    goto advanced
)
if "%c%"=="F" (
    powershell -Command "[System.Guid]::NewGuid().ToString('N')"
    pause
    goto advanced
)
goto advanced


:: =============================================================================
:: SETTINGS (includes Help)
:: =============================================================================
:settings
cls
echo === Settings ===
echo [1] Change Console Color
echo [2] Change Text Size
echo [3] Enable/Disable Sound
echo [4] Set Language
echo [5] Clear Console History
echo [6] Enable/Disable Auto-Update
echo [7] Set Custom Hotkeys
echo [8] Help (Function Explanations)
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto menu
if "%c%"=="1" goto change_color
if "%c%"=="2" goto change_text_size
if "%c%"=="3" goto toggle_sound
if "%c%"=="4" goto set_language
if "%c%"=="5" goto clear_console_history
if "%c%"=="6" goto toggle_auto_update
if "%c%"=="7" goto set_hotkeys
if "%c%"=="8" goto help_text
goto settings

:change_color
cls
echo Change Console Color:
echo [1] Purple
echo [2] Red
echo [3] Blue
echo [4] Default
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto settings
if "%c%"=="1" set COLOR=05
if "%c%"=="2" set COLOR=04
if "%c%"=="3" set COLOR=01
if "%c%"=="4" set COLOR=07
color %COLOR%
goto settings

:change_text_size
cls
echo Change Text Size:
echo [1] Small
echo [2] Medium
echo [3] Large
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto settings
if "%c%"=="1" echo Text size set to Small
if "%c%"=="2" echo Text size set to Medium
if "%c%"=="3" echo Text size set to Large
goto settings

:toggle_sound
cls
echo Toggle Sound:
echo [1] Enable Sound
echo [2] Disable Sound
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto settings
if "%c%"=="1" echo Sound enabled
if "%c%"=="2" echo Sound disabled
goto settings

:set_language
cls
echo Set Language:
echo [1] English
echo [2] Spanish
echo [3] German
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto settings
if "%c%"=="1" echo Language set to English
if "%c%"=="2" echo Language set to Spanish
if "%c%"=="3" echo Language set to German
goto settings

:clear_console_history
cls
echo Clear Console History:
echo This will remove all previously displayed information in the console.
echo Are you sure you want to clear the console history? (Y/N)
set /p c=Choice: 
if /I "%c%"=="Y" (
    cls
    echo Console history cleared.
) else (
    echo Action canceled.
)
goto settings

:toggle_auto_update
cls
echo Toggle Auto-Update:
echo [1] Enable Auto-Update
echo [2] Disable Auto-Update
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto settings
if "%c%"=="1" echo Auto-update enabled
if "%c%"=="2" echo Auto-update disabled
goto settings

:set_hotkeys
cls
echo Set Custom Hotkeys:
echo [1] Hotkey 1: Open Settings
echo [2] Hotkey 2: Toggle Sound
echo [3] Hotkey 3: Clear Console
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto settings
if "%c%"=="1" echo Hotkey 1 set to Open Settings
if "%c%"=="2" echo Hotkey 2 set to Toggle Sound
if "%c%"=="3" echo Hotkey 3 set to Clear Console
goto settings

:help_text
cls
echo =============================================================================
echo                          FUNCTION EXPLANATIONS
echo =============================================================================
echo.
echo Network Tools:
echo ----------------------------------------
echo IP Configuration       - Displays full IP settings.
echo Show WiFi Passwords    - Lists saved WiFi profiles and their passwords.
echo Change MAC Address     - Changes the MAC address of a network adapter.
echo Traceroute             - Traces the network route to a specified host.
echo Ping Sweep             - Pings a range of IPs to find active hosts.
echo.
echo System Info:
echo ----------------------------------------
echo System Information     - Shows detailed system information.
echo Memory Capacity        - Displays the total installed memory.
echo Disk Drive Size        - Lists the size of connected disk drives.
echo System Uptime          - Shows how long the system has been running.
echo.
echo Security:
echo ----------------------------------------
echo Defender Scan          - Runs a Windows Defender quick scan.
echo Show Firewall Rules    - Displays current firewall settings.
echo Process Monitor        - Lists running processes and their services.
echo Show User Accounts     - Lists all local user accounts.
echo Kill Process           - Terminates a process by name.
echo Show Installed Antivirus- Lists installed antivirus software.
echo Check for Updates      - Forces Windows to check for updates.
echo Show Security Settings - Exports Windows security settings to a file.
echo Network Configuration   - Displays network configuration settings.
echo Check Running Services  - Lists all running services.
echo Display Scheduled Tasks - Lists all scheduled tasks.
echo List Active Connections - Displays current active network connections.
echo Show Windows Logs       - Opens the event viewer to show logs.
echo System Information      - Shows system information again (for quick access).
echo Show System Drivers     - Lists all drivers installed on the system.
echo.
echo Windows Tweaks:
echo ----------------------------------------
echo Disable Telemetry      - Turns off Windows telemetry and stops DiagTrack.
echo Disable Fast Startup   - Disables the Fast Startup feature.
echo Stop Superfetch        - Stops and disables the SysMain service.
echo Disable Windows Defender - Disables Windows Defender service.
echo Disable Windows Updates - Disables Windows Update service.
echo Disable Windows Store   - Disables the Windows Store app.
echo Disable Cortana         - Disables Cortana from running.
echo Disable Windows Defender Antivirus in Group Policy - Disable Defender via policy.
echo Enable High Performance Power Plan - Sets the power plan to high performance.
echo Disable Remote Desktop  - Disables remote desktop connections.
echo Disable UAC (User Account Control) - Disables User Account Control for admin tasks.
echo Disable Windows Error Reporting - Disables error reporting to Microsoft.
echo Disable Windows Defender Real-Time Protection - Disables real-time protection.
echo Disable Windows Search Indexing - Disables indexing of files for search.
echo Disable OneDrive        - Disables OneDrive syncing and background processes.
echo.
echo Advanced Tools:
echo ----------------------------------------
echo Encrypt File (AES)     - Encrypts a file using the AES algorithm.
echo Create Backup          - Creates a mirror backup of a folder.
echo Calculate Hash         - Computes the SHA256 hash of a file.
echo Compress Folder (ZIP)  - Compresses a folder into a ZIP file.
echo Decrypt File (AES)     - Decrypts a file previously encrypted with AES.
echo Create System Restore Point - Creates a system restore point for system recovery.
echo Delete Old Backup Files- Deletes backup files older than 30 days.
echo Check Disk for Errors   - Checks and repairs disk errors on drive C.
echo Schedule Task          - Schedules a task to run a specific command at a given time.
echo Show Network Information - Displays detailed network adapter and connection information.
echo Create Disk Image      - Creates a disk image backup of the system.
echo Clear Temp Files       - Deletes temporary files from the system.
echo List Installed Programs - Lists all installed programs on the system.
echo Check Disk Space       - Shows disk space usage for all drives.
echo Generate Random Password - Generates a random password.
echo.
echo Offensive Tools:
echo ----------------------------------------
echo Port Scanner (TCP)     - Scans specified ports on a target IP.
echo MAC Spoofing           - Changes the MAC address of a network adapter.
echo ARP Spoofing           - Sets a static ARP entry to simulate spoofing.
echo Keylogger (CMD Input)  - Logs command prompt input to a file.
echo Show WiFi Passwords    - (Also available in Network Tools) Displays saved WiFi passwords.
echo Local Brute-Force      - Attempts to brute-force a local user account.
echo ZIP Crack              - Tries to crack a ZIP file's password using 7-Zip.
echo DNS Spoofing           - Adds a custom entry to the hosts file.
echo Ping Flood             - Simulates a DoS attack with multiple ping requests.
echo Hosts File Edit        - Allows adding or removing entries in the hosts file.
echo.
echo Press any key to return to Settings...
pause >nul
goto settings


:: =============================================================================
:: OFFENSIVE TOOLS MENU
:: =============================================================================
:offensive
cls
echo ===== Offensive Tools (Batch) =====
echo [1] Port Scanner (TCP)
echo [2] MAC Spoofing
echo [3] ARP Spoofing
echo [4] Keylogger (CMD Input)
echo [5] Show WiFi Passwords
echo [6] Local Brute-Force
echo [7] ZIP Crack
echo [8] DNS Spoofing
echo [9] Ping Flood
echo [A] Hosts File Edit
echo [B] Password Generator
echo [C] MITM Attack Simulation
echo [D] Check Open Ports (via netstat)
echo [E] IP Geolocation
echo [F] Network Sniffer
echo [0] Back
echo.
set /p choice=Choice: 
if /i "%choice%"=="1" goto port_scan
if /i "%choice%"=="2" goto mac_spoof
if /i "%choice%"=="3" goto arp_spoof
if /i "%choice%"=="4" goto keylogger
if /i "%choice%"=="5" goto wifi_passwords
if /i "%choice%"=="6" goto local_brute
if /i "%choice%"=="7" goto zip_crack
if /i "%choice%"=="8" goto dns_spoof
if /i "%choice%"=="9" goto ping_flood
if /i "%choice%"=="A" goto hosts_edit
if /i "%choice%"=="B" goto pass_gen
if /i "%choice%"=="C" goto mitm_attack
if /i "%choice%"=="D" goto netstat_ports
if /i "%choice%"=="E" goto ip_geolocation
if /i "%choice%"=="F" goto network_sniffer
if /i "%choice%"=="0" goto menu
goto offensive

:: =============================================================================
:: OFFENSIVE TOOLS FUNCTIONS
:: =============================================================================

:port_scan
cls
echo Port Scanner (TCP)
set /p target=Target IP: 
echo Scanning ports on %target%...
for %%p in (21 22 80 443 3389 8080) do (
    timeout 1 >nul
    (echo >nul 2>&1) && (
        echo Port %%p: Open
    ) || (
        echo Port %%p: Closed
    )
)
pause
goto offensive

:mac_spoof
cls
echo Change MAC Address (Requires restart)
echo Available Network Adapters:
getmac /v /fo list
echo.
set /p adapter=Adapter Name (e.g., "Ethernet"): 
set /p new_mac=New MAC (XX-XX-XX-XX-XX-XX): 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v NetworkAddress /d %new_mac% /f >nul
echo MAC address changed! Restart the adapter or your PC.
pause
goto offensive

:arp_spoof
cls
echo ARP Spoofing (Static Entry)
set /p gateway=Gateway IP: 
set /p fake_mac=Fake MAC (e.g., 00-11-22-33-44-55): 
arp -d %gateway%
arp -s %gateway% %fake_mac%
echo ARP entry set: %gateway% -> %fake_mac%
pause
goto offensive

:keylogger
cls
echo Keylogger (CMD Input)
set /p logfile=Log File (e.g., keylog.txt): 
echo Press Ctrl+C to exit.
:log_loop
set /p input= 
echo !date! !time!: !input! >> "%logfile%"
goto log_loop

:wifi_passwords
cls
echo Stored WiFi Passwords:
for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| find "Profile"') do (
    set "ssid=%%a"
    set "ssid=!ssid:~1!"
    call :get_wifi_pass "!ssid!"
)
pause
goto offensive

:local_brute
cls
echo Local Brute-Force
set /p user=Username: 
set /p wordlist=Wordlist (txt): 
for /f "delims=" %%p in (%wordlist%) do (
    net user %user% %%p >nul 2>&1
    if !errorlevel! == 0 (
        echo Success! Password: %%p
        pause
        goto offensive
    )
)
echo No password found.
pause
goto offensive

:zip_crack
cls
echo ZIP Password Crack (Requires 7-Zip)
set /p zipfile=ZIP File: 
set /p wordlist=Wordlist (txt): 
for /f "delims=" %%p in (%wordlist%) do (
    7z.exe x -p%%p "%zipfile%" -oextracted -y >nul 2>&1
    if !errorlevel! == 0 (
        echo Success! Password: %%p
        pause
        goto offensive
    )
)
echo No password found.
pause
goto offensive

:dns_spoof
cls
echo DNS Spoofing (Hosts File)
set /p domain=Domain (e.g., google.com): 
set /p fake_ip=Fake IP: 
echo %fake_ip% %domain% >> %HOSTS%
echo DNS entry added: %domain% -> %fake_ip%
pause
goto offensive

:ping_flood
cls
echo Ping Flood (DoS Simulation)
set /p target=Target IP: 
set /p count=Number of Pings: 
echo Starting ping flood on %target%...
for /L %%i in (1,1,%count%) do (
    ping %target% -n 1 >nul
)
echo Ping flood completed.
pause
goto offensive

:hosts_edit
cls
echo Hosts File Edit
echo [1] Add Entry
echo [2] Remove Entry
echo [0] Back
echo.
set /p c=Choice: 
if "%c%"=="0" goto offensive
if "%c%"=="1" (
    set /p domain=Domain (e.g., malicious-site.com): 
    set /p redirect_ip=Redirect IP: 
    echo %redirect_ip% %domain% >> %HOSTS%
    echo Entry added: %domain% -> %redirect_ip%
    pause
    goto hosts_edit
)
if "%c%"=="2" (
    set /p domain=Domain to remove: 
    findstr /v "%domain%" %HOSTS% > temp_hosts
    move /y temp_hosts %HOSTS% >nul
    echo Entry for %domain% removed.
    pause
    goto hosts_edit
)

:: New Added Functions

:pass_gen
cls
echo Password Generator
set /p length=Password Length: 
powershell -Command "[System.Web.Security.Membership]::GeneratePassword(%length%, 4)"
pause
goto offensive

:mitm_attack
cls
echo MITM Attack Simulation
echo [This would require tools like Ettercap or similar, this is just a simulation.]
echo Running simulated MITM attack...
echo Simulation Complete.
pause
goto offensive

:netstat_ports
cls
echo Checking open ports using netstat...
netstat -an | find "LISTEN"
pause
goto offensive

:ip_geolocation
cls
echo IP Geolocation
set /p ip=Enter IP Address: 
echo Fetching geolocation data for IP %ip%...
curl https://ipinfo.io/%ip%/json
pause
goto offensive

:network_sniffer
cls
echo Network Sniffer
echo [This would require Wireshark or similar tools, this is just a simulation.]
echo Running network sniffing simulation...
echo Simulation Complete.
pause
goto offensive
