#include <cstdlib>

#include <cstdio>

#include <iostream>

#include <memory>

#include <stdexcept>

#include <string>

#include <array>

#include <vector>
#include <algorithm>
#include <sstream>

#include <Windows.h>
#include <fstream>
#include <Psapi.h>
#include <regex>
#include <TlHelp32.h>
#pragma comment(lib, "Psapi.lib")
struct DriverPackage {
    std::string driverName;
    std::string publishedName;
    std::string driverPackagePath;
    std::string providerName;
    std::string driverClass;
    std::string version;
    std::string date;
    std::string description;
    std::string infFileName;
    std::string infPublishedName;
    std::string infManufacturer;
    std::string infDriverVersion;
    std::string infClassName;
    std::string infClassGuid;
    std::string infProvider;
    std::string infDriverDate;
    int rank;
};


std::ostream& operator<<(std::ostream& os, const DriverPackage& driverPackage) {
    os << "Driver Name: " << driverPackage.driverName << std::endl;
    os << "Published Name: " << driverPackage.publishedName << std::endl;
    os << "Driver Package Path: " << driverPackage.driverPackagePath << std::endl;
    os << "Provider Name: " << driverPackage.providerName << std::endl;
    os << "Driver Class: " << driverPackage.driverClass << std::endl;
    os << "Version: " << driverPackage.version << std::endl;
    os << "Date: " << driverPackage.date << std::endl;
    os << "Description: " << driverPackage.description << std::endl;
    os << "Inf File Name: " << driverPackage.infFileName << std::endl;
    os << "Inf Published Name: " << driverPackage.infPublishedName << std::endl;
    os << "Inf Manufacturer: " << driverPackage.infManufacturer << std::endl;
    os << "Inf Driver Version: " << driverPackage.infDriverVersion << std::endl;
    os << "Inf Class Name: " << driverPackage.infClassName << std::endl;
    os << "Inf Class Guid: " << driverPackage.infClassGuid << std::endl;
    os << "Inf Provider: " << driverPackage.infProvider << std::endl;

    return os;
}


std::string exec(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(_popen(cmd.c_str(), "r"), _pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}

std::vector<std::string> splitString(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delim)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::vector<std::string> getDriverFilesFromOEM(const std::string& oemPath) {
    std::string command = "dir /b /s \"" + oemPath + "\"";
    std::vector<std::string> outputLines = splitString(exec(command.c_str()), '\n');
    outputLines.erase(std::remove_if(outputLines.begin(), outputLines.end(), [](const std::string& line) { return line.empty(); }), outputLines.end());
    return outputLines;
}


std::string getModulePath(const std::string& driverName) {
    std::string command = "driverquery /FO LIST /V /SI | find /I \"" + driverName + "\"";
    std::vector<std::string> outputLines = splitString(exec(command.c_str()), '\n');
    std::string modulePath;
    for (const std::string& line : outputLines) {
        if (line.find("Path:") != std::string::npos) {
            modulePath = line.substr(line.find(":") + 2);
            break;
        }
    }
    return modulePath;
}

bool isModuleLoadedInProcess(DWORD processID, const std::string& modulePath) {
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == nullptr) {
        return false;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];

            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string modulePathName(szModName);
                if (modulePathName.find(modulePath) != std::string::npos) {
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return false;
}
std::vector<long unsigned int> getProcessesWithModule(const std::string& modulePath) {
    std::vector<long unsigned int> pids;
    DWORD processes[1024], cbNeeded;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        std::cerr << "Error: Failed to enumerate processes.\n";
        return pids;
    }
    DWORD numProcesses = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < numProcesses; i++) {
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (processHandle != NULL) {
            HMODULE moduleHandles[1024];
            DWORD cbNeeded;
            if (EnumProcessModules(processHandle, moduleHandles, sizeof(moduleHandles), &cbNeeded)) {
                DWORD numModules = cbNeeded / sizeof(HMODULE);
                for (DWORD j = 0; j < numModules; j++) {
                    TCHAR moduleName[MAX_PATH];
                    if (GetModuleFileNameEx(processHandle, moduleHandles[j], moduleName, sizeof(moduleName))) {
                        std::string moduleNameString = moduleName;
                        if (moduleNameString.find(modulePath) != std::string::npos) {
                            pids.push_back(processes[i]);
                        }
                    }
                }
            }
            CloseHandle(processHandle);
        }
    }
    return pids;
}
std::vector<DriverPackage> getDriverPackages() {
    std::vector<DriverPackage> driverPackages;
    std::string command = "pnputil /enum-drivers /all /v /fo list";
    std::vector<std::string> outputLines = splitString(exec(command), '\n');

    DriverPackage currentDriverPackage;

    for (const std::string& line : outputLines) {
        if (line.find("Published name") != std::string::npos) {
            if (!currentDriverPackage.driverName.empty()) {
                driverPackages.push_back(currentDriverPackage);
                currentDriverPackage = DriverPackage();
            }
            currentDriverPackage.publishedName = line.substr(line.find(": ") + 2);
        } else if (line.find("Driver package provider") != std::string::npos) {
            currentDriverPackage.providerName = line.substr(line.find(": ") + 2);
        } else if (line.find("Class name") != std::string::npos) {
            currentDriverPackage.driverClass = line.substr(line.find(": ") + 2);
        } else if (line.find("Driver date and version") != std::string::npos) {
            std::string dateAndVersion = line.substr(line.find(": ") + 2);
            currentDriverPackage.date = dateAndVersion.substr(0, dateAndVersion.find(","));
            currentDriverPackage.version = dateAndVersion.substr(dateAndVersion.find(",") + 2);
        } else if (line.find("Driver description") != std::string::npos) {
            currentDriverPackage.description = line.substr(line.find(": ") + 2);
        } else if (line.find("Driver rank") != std::string::npos) {
            currentDriverPackage.rank = std::stoi(line.substr(line.find(": ") + 2));
        }
    }

    if (!currentDriverPackage.driverName.empty()) {
        driverPackages.push_back(currentDriverPackage);
    }

    return driverPackages;
}






std::vector<std::string> getWMICApps() {
    std::vector<std::string> wmicApps;
    std::istringstream input(exec("wmic product get IdentifyingNumber,Name"));
    std::string line;
    std::getline(input, line); // Skip the header line

    while (std::getline(input, line)) {
        if (!line.empty()) {
            size_t delimiter = line.find("  ");
            if (delimiter != std::string::npos) {
                std::string appId = line.substr(0, delimiter);
                std::string appName = line.substr(delimiter + 2);
                wmicApps.push_back(appId + "," + appName);
            }
        }
    }

    return wmicApps;
}
std::vector<std::string> getWindowsStoreApps() {
    std::vector<std::string> storeApps;
    std::istringstream input(exec("powershell -command \"Get-AppxPackage -AllUsers | Format-Table Name,PackageFullName -AutoSize\""));
    std::string line;
    std::getline(input, line); // Skip the header line

    while (std::getline(input, line)) {
        if (!line.empty()) {
            size_t delimiter = line.find("  ");
            if (delimiter != std::string::npos) {
                std::string appName = line.substr(0, delimiter);
                std::string appFullName = line.substr(delimiter + 2);
                storeApps.push_back(appName + "," + appFullName);
            }
        }
    }

    return storeApps;
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
    {
      std::vector<DriverPackage> driverPackages = getDriverPackages(); // Changed to DriverPackage
if (!driverPackages.empty()) {
    std::cout << "Driver packages found: " << std::endl;
    for (int i = 0; i < driverPackages.size(); i++) {
        std::cout << i + 1 << ". " << driverPackages[i] << std::endl;
    }
}

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
            std::string command = "pnputil /d \"" + driverPackages[index].publishedName + "\"";
            std::cout << "Deleting driver package: " << driverPackages[index] << std::endl;
            int ret = system(command.c_str());

            if (ret != 0) {
                std::cout << "Failed to delete driver package. Checking for related modules..." << std::endl;
                std::string driverName = driverPackages[index].driverName;
std::string command = "driverquery /FO LIST /V | find /i \"" + driverName + "\"";

std::string outputString = exec(command);
std::vector<std::string> outputLines = {outputString};

std::string modulePath;

for (const std::string& line : outputLines) {
    if (line.find("Path:") != std::string::npos) {
        modulePath = line.substr(line.find(": ") + 2);
        break;
    }
}

if (!modulePath.empty()) {
    std::cout << "The following module is associated with the driver package:" << std::endl;
    std::cout << modulePath << std::endl;

    std::vector<long unsigned int> processIDs = getProcessesWithModule(modulePath);
    if (!processIDs.empty()) {
        std::cout << "The following processes have the module loaded:" << std::endl;
        for (const auto& pid : processIDs) {
            std::cout << pid << std::endl;
        }
    } else {
        std::cout << "No processes found with the module loaded." << std::endl;
    }
} else {
    std::cout << "No module found associated with the driver package." << std::endl;
}

            }
        } else {
            std::cout << "Invalid selection. Please try again." << std::endl;
        }
    }
} else {
    std::cout << "No driver packages found. Skipping driver package deletion." << std::endl;
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
      std::cout << "Enabling Windows Defender Real-Time protection VIA registry." << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 0 /f");
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f");
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 0 /f");
      system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 0 /f");
      std::cout << "Enabling DNS-over-HTTPS (DoH) in Windows 11." << std::endl;
      system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\" /v EnableAutoDoh /t REG_DWORD /d 2 /f");
      std::cout << "Checking for and installing Windows updates." << std::endl;
      system("powershell -ExecutionPolicy Bypass -command \"Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force\"");
      system("powershell -ExecutionPolicy Bypass -command \"Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber\"");
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
      std::cout << "Enabling Windows Defender and Security Center." << std::endl;
    
    // Enabling Windows Defender Real-time protection
    system("powershell.exe Set-MpPreference -DisableRealtimeMonitoring 0");

    // Enabling Windows Security Center
    std::cout << "Enabling Windows Security Center service" << std::endl;
    system("sc config wscsvc start= auto");
    system("sc start wscsvc");
    // Updating Windows Defender signatures
    std::cout << "Updating Windows Defender signatures." << std::endl;
    system("powershell.exe Update-MpSignature");

      std::cout << "Cleanup complete. Press Enter to exit." << std::endl;
      std::cin.ignore();
      return 0;
    }
