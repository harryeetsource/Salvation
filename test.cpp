#include <cstdlib>

#include <cstdio>

#include <iostream>

#include <memory>

#include <stdexcept>

#include <string>

#include <array>

#include <vector>

#include <sstream>
#include "utils.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")


std::vector<DWORD> findProcessesUsingDriver(const std::string &driverPath) {
    std::vector<DWORD> pids;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32 processEntry = {0};
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &processEntry)) {
        CloseHandle(snapshot);
        return pids;
    }

    do {
        HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processEntry.th32ProcessID);
        if (moduleSnapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 moduleEntry = {0};
            moduleEntry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(moduleSnapshot, &moduleEntry)) {
                do {
                    if (_stricmp(moduleEntry.szExePath, driverPath.c_str()) == 0) {
                        pids.push_back(processEntry.th32ProcessID);
                        break;
                    }
                } while (Module32Next(moduleSnapshot, &moduleEntry));
            }
            CloseHandle(moduleSnapshot);
        }
    } while (Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);
    return pids;
}
std::ostream& operator<<(std::ostream& os, const DriverPackage& driverPackage) {
    os << "Module Name: " << driverPackage.moduleName << "\n"
       << "Display Name: " << driverPackage.displayName << "\n"
       << "Description: " << driverPackage.description << "\n"
       << "Driver Type: " << driverPackage.driver_type << "\n"
       << "Start Mode: " << driverPackage.start_mode << "\n"
       << "State: " << driverPackage.state << "\n"
       << "Status: " << driverPackage.status << "\n"
       << "Accept Stop: " << (driverPackage.accept_stop ? "TRUE" : "FALSE") << "\n"
       << "Accept Pause: " << (driverPackage.accept_pause ? "TRUE" : "FALSE") << "\n"
       << "Paged Pool(bytes): " << driverPackage.paged_pool_bytes << "\n"
       << "Code(bytes): " << driverPackage.code_bytes << "\n"
       << "BSS(bytes): " << driverPackage.bss_bytes << "\n"
       << "Link Date: " << driverPackage.link_date << "\n"
       << "Path: " << driverPackage.path;
    return os;
}
std::string extractDriverName(const std::string& driverPath) {
    size_t startPos = driverPath.rfind("\\") + 1;
    size_t endPos = driverPath.rfind(".");
    return driverPath.substr(startPos, endPos - startPos);
}




int main() {
    // Perform full cleanup and system file check
    std::cout << "Performing full cleanup and system file check." << std::endl;
    system("dism /online /cleanup-image /startcomponentcleanup");
    system("dism /online /cleanup-image /restorehealth");
    system("sfc /scannow");
    // Delete Prefetch files
    std::cout << "Deleting Prefetch files." << std::endl;
    system("del /s /q /f %systemroot%\\Prefetch\\*");

    // Clean up Windows Update cache
    std::cout << "Cleaning up Windows Update cache." << std::endl;
    system("net stop wuauserv");
    system("net stop bits");
    system("rd /s /q %systemroot%\\SoftwareDistribution");
    system("net start wuauserv");
    system("net start bits");

    // Perform additional cleanup steps
    std::cout << "Performing additional cleanup steps." << std::endl;
    system("cleanmgr /sagerun:1");
    // Remove temporary files
    std::cout << "Removing temporary files." << std::endl;
    system("del /s /q %temp%\\*");
    system("del /s /q %systemroot%\\temp\\*");
    // Cleanup font cache
    system("net stop fontcache");
    system("del /f /s /q /a %systemroot%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*");
    system("del /f /s /q /a %systemroot%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*");
    system("net start fontcache");

    {
    std::vector<std::string> storeApps = getWindowsStoreApps();
    if (!storeApps.empty()) {
        std::cout << "Windows Store apps found: " << std::endl;
        for (int i = 0; i < storeApps.size(); i++) {
            std::cout << i + 1 << ". " << storeApps[i].substr(0, storeApps[i].find(",")) << std::endl;
        }
        int index = -1;
        while (true) {
            std::cout << "Enter the number of the Windows Store app to uninstall or press Enter to skip: ";
            std::string input;
            std::getline(std::cin, input);
            if (input.empty()) {
                break;
            }
            index = std::stoi(input) - 1;
            if (index >= 0 && index < storeApps.size()) {
                std::string appFullName = storeApps[index].substr(storeApps[index].find(",") + 1);
                std::string command = "powershell -command \"Get-AppxPackage -AllUsers -Name " + appFullName + " | Remove-AppxPackage\"";
                std::cout << "Uninstalling Windows Store app: " << storeApps[index].substr(0, storeApps[index].find(",")) << std::endl;
                system(command.c_str());
            } else {
                std::cout << "Invalid selection. Please try again." << std::endl;
            }
        }
    } else {
        std::cout << "No Windows Store apps found. Skipping Windows Store app uninstallation." << std::endl;
    }
}

    // Delete driver package
    
      std::vector<DriverPackage> driverPackages = getDriverPackages(); // Changed to DriverPackage
if (!driverPackages.empty()) {
    std::cout << "Driver packages found: " << std::endl;
    for (int i = 0; i < driverPackages.size(); i++) {
        std::cout << i + 1 << ". " << driverPackages[i] << std::endl;
    }

    // Modified driver package deletion section
    int index = -1;
    while (true) {
        std::cout << "Enter the number of the driver package to delete or press Enter to skip: ";
        std::string input;
        std::getline(std::cin, input);
        if (input.empty()) {
            break;
        }
        index = std::stoi(input) - 1;
         if (index >= 0 && index < driverPackages.size()) {
        std::string command = "pnputil /d \"" + driverPackages[index].infFile+ "\"";

        // Execute the command to delete the selected driver package
        std::cout << "Deleting driver package: " << driverPackages[index] << std::endl;
        int result = system(command.c_str());

        if (result != 0) {
            std::cout << "Failed to uninstall driver. Identifying processes using the driver..." << std::endl;

            std::string driverName = extractDriverName(driverPackages[index].path);
            std::vector<unsigned long> pids = findProcessesUsingDriver(driverName);

            if (!pids.empty()) {
                std::cout << "The following processes are using the driver:" << std::endl;
                for (unsigned long pid : pids) {
                    std::cout << "PID: " << pid << std::endl;
                }
            } else {
                std::cout << "No processes are using the driver." << std::endl;
            }
        }
    } else {
        std::cout << "Invalid selection. Please try again." << std::endl;
    }
    }

      // Modified WMIC app uninstallation section
      {
        std::vector < std::string > wmicApps = getWMICApps();
        if (!wmicApps.empty()) {
          std::cout << "WMIC apps found: " << std::endl;
          for (int i = 0; i < wmicApps.size(); i++) {
            std::cout << i + 1 << ". " << wmicApps[i].substr(wmicApps[i].find(",") + 1) << std::endl;
          }
          int index = -1;
          while (true) {
            std::cout << "Enter the number of the WMIC app to uninstall or press Enter to skip: ";
            std::string input;
            std::getline(std::cin, input);
            if (input.empty()) {
              break;
            }
            index = std::stoi(input) - 1;
            if (index >= 0 && index < wmicApps.size()) {
              std::string appId = wmicApps[index].substr(0, wmicApps[index].find(","));
              std::string command = "wmic product where \"IdentifyingNumber='" + appId + "'\" call uninstall /nointeractive";
              std::cout << "Uninstalling WMIC app: " << wmicApps[index].substr(wmicApps[index].find(",") + 1) << std::endl;
              system(command.c_str());
            } else {
              std::cout << "Invalid selection. Please try again." << std::endl;
            }
          }
        } else {
          std::cout << "No WMIC apps found. Skipping WMIC app uninstallation." << std::endl;
        }
      }
    }
      // Disable insecure windows features
      std::cout << "Disabling insecure windows features" << std::endl;
      system("dism /online /disable-feature /featurename:WindowsMediaPlayer");
      std::cout << "Disabling SMBV1" << std::endl;
      system("dism /online /disable-feature /featurename:SMB1Protocol");
      std::cout << "Disabling RDP" << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f");
      std::cout << "Disabling Remote Assistance" << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\" /v fAllowToGetHelp /t REG_DWORD /d 0 /f");
      std::cout << "Disable Autorun for all drives" << std::endl;
      system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f");
      std::cout << "Disabling LLMNR" << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f");
      std::cout << "Deleting oldest shadowcopy" << std::endl;
      system("vssadmin delete shadows /for=C: /oldest");
      std::cout << "Enable UAC" << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f");
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f");

      system("forfiles /p \"C:\\Windows\\Logs\" /s /m *.log /d -7 /c \"cmd /c del @path\"");
      std::cout << "Enabling Windows Defender Credential Guard" << std::endl;
      std::cout << "Enabling Credential Guard." << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v LsaCfgFlags /t REG_DWORD /d 1 /f");
      system("bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VSM");
      system("bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} device path '\\EFI\\Microsoft\\Boot\\SecConfig.efi'");


      std::cout << "Enabling Exploit Protection settings" << std::endl;
      system("powershell -command \"Set-ProcessMitigation -System -Enable DEP,SEHOP\"");
      std::cout << "Enabling Data Execution Prevention (DEP)" << std::endl;
      system("bcdedit /set nx AlwaysOn");
      std::cout << "Enabling Secure Boot" << std::endl;
      system("bcdedit /set {default} bootmenupolicy Standard");
      std::cout << "Enabling secure boot-step 2." << std::endl;
      system("powershell -command \"Confirm-SecureBootUEFI\"");

      std::cout << "Disabling Microsoft Office macros." << std::endl;
      system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f");
      system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f");
      system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\" /v VBAWarnings /t REG_DWORD /d 4 /f");
      std::cout << "Enabling Address Space Layout Randomization." << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v MoveImages /t REG_DWORD /d 1 /f");

      std::cout << "Enabling DNS-over-HTTPS (DoH) in Windows 11." << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\" /v EnableAutoDoh /t REG_DWORD /d 2 /f");
      std::cout << "Checking for and installing Windows updates." << std::endl;
      system("powershell -ExecutionPolicy Bypass -command \"Install-Module -Name PowerShellGet -Scope CurrentUser -Force\"");
      system("powershell -ExecutionPolicy Bypass -command \"Register-PackageSource -Trusted -ProviderName 'PowerShellGet' -Name 'PSGallery' -Location 'https://www.powershellgallery.com/api/v2'\"");
      system("powershell -ExecutionPolicy Bypass -command \"Install-Package -Name PSWindowsUpdate -ProviderName PowerShellGet -Force\"");
      system("powershell -ExecutionPolicy Bypass -command \"Import-Module PowerShellGet; Import-Module PSWindowsUpdate; Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install\"");
      std::cout << "Restricting access to the Local System Authority." << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f");

      // Disable Windows Delivery Optimization
      std::cout << "Disabling Windows Delivery Optimization" << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\" /v DODownloadMode /t REG_DWORD /d 0 /f");
      std::cout << "Enabling Memory Integrity" << std::endl;
      system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v Enabled /t REG_DWORD /d 1 /f");
      std::cout << "Memory Integrity enabled. Please reboot your system for the changes to take effect." << std::endl;
      std::cout << "Emptying the Recycle Bin." << std::endl;
      system("rd /s /q %systemdrive%\\$Recycle.Bin");

      std::cout << "Cleanup complete. Press Enter to exit." << std::endl;
      std::cin.ignore();
      return 0;
    }