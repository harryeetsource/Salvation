package main

import (
	"fmt"
	"os"
	"os/exec"
)

func executeCommand(command string) {
	cmd := exec.Command("cmd", "/C", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing command: %v\n", err)
	}
}

type PROCESSENTRY32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

func main() {
	fmt.Println("Performing full cleanup and system file check.")
	executeCommand("dism /online /cleanup-image /startcomponentcleanup")
	executeCommand("dism /online /cleanup-image /restorehealth")
	executeCommand("sfc /scannow")

	fmt.Println("Deleting Prefetch files.")
	executeCommand("del /s /q /f %systemroot%\\Prefetch\\*")

	fmt.Println("Cleaning up Windows Update cache.")
	executeCommand("net stop wuauserv")
	executeCommand("net stop bits")
	fmt.Println("Resetting WUAservice")
	executeCommand("net stop cryptsvc")
	executeCommand("rd /s /q %systemroot%\\SoftwareDistribution")
	executeCommand("Del \"%ALLUSERSPROFILE%\\Application Data\\Microsoft\\Network\\Downloader\\qmgr*.dat\"")
	executeCommand("Ren %Systemroot%\\SoftwareDistribution\\DataStore DataStore.bak")
	executeCommand("Ren %Systemroot%\\SoftwareDistribution\\Download Download.bak")
	executeCommand("Ren %Systemroot%\\System32\\catroot2 catroot2.bak")
	executeCommand("sc.exe sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)")
	executeCommand("sc.exe sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY))")
	executeCommand("cd /d %windir%\\system32")

	dlls := []string{
		"atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll",
		"vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll",
		"softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll", "gpkcsp.dll", "sccbase.dll",
		"slbcsp.dll", "cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll",
		"wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
		"wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll",
	}
	fmt.Println("Silently registering essential windows update modules")
	for _, dll := range dlls {
		command := "regsvr32.exe /s /i " + dll
		executeCommand(command)
	}
	executeCommand("net start bits")
	executeCommand("net start wuauserv")
	executeCommand("net start cryptsvc")
	executeCommand("net stop fontcache")
	executeCommand("del /f /s /q /a %systemroot%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*")
	executeCommand("del /f /s /q /a %systemroot%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*")
	executeCommand("net start fontcache")
	executeCommand("cleanmgr /sagerun:1")
	fmt.Println("Disabling Insecure Windows Features")
	executeCommand("dism /online /disable-feature /featurename:WindowsMediaPlayer")
	fmt.Println("Disabling SMBv1")
	executeCommand("dism /online /disable-feature /featurename:SMB1Protocol")
	fmt.Println("Disabling autorun for all drives")
	executeCommand("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f")
	fmt.Println("Disabling LLMNR")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f")
	fmt.Println("Enabling UAC")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f")
	fmt.Println("UAC step 2")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f")
	fmt.Println("Deleting windows logs older than 7 days")
	executeCommand("forfiles /p \"C:\\Windows\\Logs\" /s /m *.log /d -7 /c \"cmd /c del @path\"")
	fmt.Println("Enabling Windows Credential Guard")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v LsaCfgFlags /t REG_DWORD /d 1 /f")
	executeCommand("bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VSM")
	executeCommand("bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} device path '\\EFI\\Microsoft\\Boot\\SecConfig.efi'")
	fmt.Println("Enabling Exploit Protection")
	executeCommand("powershell -command \"Set-ProcessMitigation -System -Enable DEP,SEHOP\"")
	fmt.Println("Enabling DEP")
	executeCommand("bcdedit /set nx AlwaysOn")
	fmt.Println("Enabling Secure Boot")
	executeCommand("bcdedit /set {default} bootmenupolicy Standard")
	fmt.Println("Secure Boot Step 2")
	executeCommand("powershell -command \"Confirm-SecureBootUEFI\"")
	fmt.Println("Disabling Microsoft Office macros.")
	executeCommand("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f")
	executeCommand("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f")
	executeCommand("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f")
	fmt.Println("Enabling ASLR")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v MoveImages /t REG_DWORD /d 1 /f")
	fmt.Println("Enabling Defender Real-Time Protection VIA registry")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 0 /f")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 0 /f")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 0 /f")
	fmt.Println("Disabling Windows Delivery Optimization")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 0 /f")
	fmt.Println("Enabling Memory Integrity")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 0 /f")
	fmt.Println("Emptying the Recycling bin")
	executeCommand("rd /s /q %systemdrive%\\$Recycle.Bin")
	fmt.Println("Disabling Insecure Windows Features")
	executeCommand("powershell.exe Set-MpPreference -DisableRealtimeMonitoring 0")
	fmt.Println("Enabling Windows Security Center Service")
	executeCommand("sc config wscsvc start= auto")
	executeCommand("sc start wscsvc")
	fmt.Println("Updating Windows Defender Signatures")
	executeCommand("powershell.exe Update-MpSignature")
	fmt.Println("Checking for and installing Windows updates")
	executeCommand("powershell -ExecutionPolicy Bypass -command \"Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force\"")
	executeCommand("powershell -ExecutionPolicy Bypass -command \"Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber\"")
	fmt.Println("Disabling Insecure Windows Features")
	executeCommand("powershell -ExecutionPolicy Bypass -command \"Register-PackageSource -Trusted -ProviderName 'PowerShellGet' -Name 'PSGallery' -Location 'https://www.powershellgallery.com/api/v2'\"")
	executeCommand("powershell -ExecutionPolicy Bypass -command \"Install-Package -Name PSWindowsUpdate -ProviderName PowerShellGet -Force\"")
	executeCommand("powershell -ExecutionPolicy Bypass -command \"Import-Module PowerShellGet; Import-Module PSWindowsUpdate; Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install\"")
	fmt.Println("Restricting anonymous LSA access")
	executeCommand("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f")
}
