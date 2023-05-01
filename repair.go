package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func executeCommand(shell, command string) error {
	var cmd *exec.Cmd
	if shell == "powershell" {
		cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
	} else {
		cmd = exec.Command("cmd", "/C", command)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing command: %v\n", err)
	}
	return err
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
	executeCommand("cmd", "dism /online /cleanup-image /startcomponentcleanup")
	executeCommand("cmd", "dism /online /cleanup-image /restorehealth")
	executeCommand("cmd", "sfc /scannow")

	fmt.Println("Deleting Prefetch files.")
	systemRoot := os.Getenv("SystemRoot")
	cmd := fmt.Sprintf("del /s /q /f %s\\Prefetch\\*", systemRoot)
	executeCommand("cmd", cmd)
	fmt.Println("Cleaning up Windows Update cache.")
	executeCommand("cmd", "net stop wuauserv")
	executeCommand("cmd", "net stop bits")
	fmt.Println("Resetting WUAservice")
	executeCommand("cmd", "net stop cryptsvc")
	executeCommand("cmd", fmt.Sprintf("rd /s /q %s\\SoftwareDistribution", systemRoot))
	executeCommand("cmd", fmt.Sprintf("Del \"%s\\Application Data\\Microsoft\\Network\\Downloader\\qmgr*.dat\"", os.Getenv("ALLUSERSPROFILE")))
	executeCommand("cmd", fmt.Sprintf("Ren %s\\SoftwareDistribution\\DataStore DataStore.bak", systemRoot))
	executeCommand("cmd", fmt.Sprintf("Ren %s\\SoftwareDistribution\\Download Download.bak", systemRoot))
	executeCommand("cmd", fmt.Sprintf("Ren %s\\System32\\catroot2 catroot2.bak", systemRoot))

	executeCommand("cmd", "sc.exe sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)")
	executeCommand("cmd", "sc.exe sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY))")
	// Change the working directory
	windir := os.Getenv("windir")
	err := os.Chdir(fmt.Sprintf("%s\\system32", windir))
	if err != nil {
		fmt.Println("Error changing the working directory:", err)
	}

	dlls := []string{
		"atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll", "jscript.dll",
		"vbscript.dll", "scrrun.dll", "msxml3.dll", "msxml6.dll", "actxprxy.dll",
		"softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll",
		"cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll",
		"wuapi.dll", "wuaueng.dll", "wups.dll", "wups2.dll",
		"qmgr.dll", "qmgrprxy.dll",
	}
	fmt.Println("Silently registering essential windows update modules")
	regsvr32Path := filepath.Join(os.Getenv("SystemRoot"), "System32", "regsvr32.exe")
	for _, dll := range dlls {
		command := fmt.Sprintf("%s /s /i %s", regsvr32Path, dll)
		err := executeCommand("cmd", command)
		if err != nil {
			// Call regsvr32 with no arguments if an error is returned
			commandNoArgs := fmt.Sprintf("cmd", "%s /s %s", regsvr32Path, dll)
			executeCommand("cmd", commandNoArgs)
		}
	}

	executeCommand("cmd", "net start bits")
	executeCommand("cmd", "net start wuauserv")
	executeCommand("cmd", "net start cryptsvc")
	executeCommand("cmd", "net stop fontcache")
	executeCommand("cmd", fmt.Sprintf("del /f /s /q /a %s\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*", systemRoot))
	executeCommand("cmd", fmt.Sprintf("del /f /s /q /a %s\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*", systemRoot))
	executeCommand("cmd", "net start fontcache")
	executeCommand("cmd", "cleanmgr /sagerun:1")
	fmt.Println("Disabling Insecure Windows Features")
	executeCommand("cmd", "dism /online /disable-feature /featurename:WindowsMediaPlayer")
	fmt.Println("Disabling SMBv1")
	executeCommand("cmd", "dism /online /disable-feature /featurename:SMB1Protocol")
	fmt.Println("Disabling autorun for all drives")
	executeCommand("cmd", "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f")
	fmt.Println("Disabling LLMNR")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f")
	fmt.Println("Enabling UAC")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f")
	fmt.Println("UAC step 2")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f")
	fmt.Println("Deleting windows logs older than 7 days")
	executeCommand("cmd", fmt.Sprintf("cmd", "forfiles /p \"%s\\Logs\" /s /m *.log /d -7 /c \"cmd del @path\"", systemRoot))
	fmt.Println("Enabling Windows Credential Guard")
	executeCommand("cmd", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v LsaCfgFlags /t REG_DWORD /d 1 /f")
	executeCommand("cmd", "bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VSM")
	executeCommand("cmd", "bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} device path '\\EFI\\Microsoft\\Boot\\SecConfig.efi'")
	fmt.Println("Enabling Exploit Protection")
	executeCommand("powershell", "Set-ProcessMitigation -System -Enable DEP,SEHOP")
	fmt.Println("Enabling DEP")
	executeCommand("cmd", "bcdedit /set nx AlwaysOn")
	fmt.Println("Enabling Secure Boot")
	executeCommand("cmd", "bcdedit /set {default} bootmenupolicy Standard")
	fmt.Println("Secure Boot Step 2")
	executeCommand("powershell", "Confirm-SecureBootUEFI")
	fmt.Println("Disabling Microsoft Office macros.")
	executeCommand("cmd", "reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f")
	executeCommand("cmd", "reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f")
	executeCommand("cmd", "reg add \"HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f")
	fmt.Println("Enabling ASLR")
	executeCommand("cmd", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v MoveImages /t REG_DWORD /d 1 /f")
	fmt.Println("Enabling Defender Real-Time Protection VIA registry")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 0 /f")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 0 /f")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 0 /f")
	fmt.Println("Disabling Windows Delivery Optimization")
	executeCommand("cmd", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 0 /f")
	fmt.Println("Enabling Memory Integrity")
	executeCommand("cmd", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v Enabled /t REG_DWORD /d 1 /f")
	fmt.Println("Deleting Temporary files.")
	tempDir := os.Getenv("TEMP")
	cmd = fmt.Sprintf("del /s /q /f %s\\*", tempDir)
	executeCommand("cmd", cmd)

	fmt.Println("Emptying the Recycling bin")
	executeCommand("cmd", fmt.Sprintf("rd /s /q %s\\$Recycle.Bin", os.Getenv("systemdrive")))
	fmt.Println("Disabling Insecure Windows Features")
	executeCommand("powershell", "Set-MpPreference -DisableRealtimeMonitoring 0")
	fmt.Println("Enabling Windows Security Center Service")
	executeCommand("cmd", "sc config wscsvc start= auto")
	executeCommand("cmd", "sc start wscsvc")
	fmt.Println("Updating Windows Defender Signatures")
	executeCommand("powershell", "Update-MpSignature")
	fmt.Println("Checking for and installing Windows updates")
	executeCommand("powershell", "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force")
	executeCommand("powershell", "Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber")
	executeCommand("powershell", "Register-PackageSource -Trusted -ProviderName 'PowerShellGet' -Name 'PSGallery' -Location 'https://www.powershellgallery.com/api/v2'")
	executeCommand("powershell", "Install-Package -Name PSWindowsUpdate -ProviderName PowerShellGet -Force")
	executeCommand("powershell", "Import-Module PowerShellGet")
	executeCommand("powershell", "Import-Module PSWindowsUpdate")
	executeCommand("powershell", "Install-Module PSWindowsUpdate -Force")
	executeCommand("powershell", "Get-WindowsUpdate -Install")

	fmt.Println("Restricting anonymous LSA access")
	executeCommand("cmd", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f")
}
