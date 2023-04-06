#include "utils.h"
#include <unordered_map>

std::vector<DriverPackage> getDriverPackages() {
    std::vector<DriverPackage> driverPackages;

    // Retrieve the output from driverquery
    std::istringstream driverqueryInput(exec("driverquery /FO LIST /V"));
    std::unordered_map<std::string, std::string> driverPaths;
    std::string line;
    std::string currentModuleName;

    // Iterate through the driverquery output to obtain the driver paths
    while (std::getline(driverqueryInput, line)) {
        if (line.find("Module Name:") != std::string::npos) {
            currentModuleName = line.substr(line.find(":") + 2);
        } else if (line.find("Path:") != std::string::npos) {
            driverPaths[currentModuleName] = line.substr(line.find(":") + 2);
        }
    }

    // Retrieve the output from pnputil /enum-drivers
    std::istringstream pnputilInput(exec("pnputil /enum-drivers"));
    DriverPackage currentDriverPackage;

    // Iterate through the pnputil output to obtain the driver information
    while (std::getline(pnputilInput, line)) {
        if (line.find("Published Name:") != std::string::npos) {
            currentDriverPackage.infFile = line.substr(line.find(":") + 2);
        } else if (line.find("Driver package provider:") != std::string::npos) {
            currentDriverPackage.displayName = line.substr(line.find(":") + 2);
        } else if (line.find("Class:") != std::string::npos) {
            currentDriverPackage.moduleName = line.substr(line.find(":") + 2);
            auto it = driverPaths.find(currentDriverPackage.moduleName);
            if (it != driverPaths.end()) {
                currentDriverPackage.path = it->second;
                driverPackages.push_back(currentDriverPackage);
            }
        }
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
std::string exec(const char * cmd) {
  std::array < char, 128 > buffer;
  std::string result;
  std::unique_ptr < FILE, decltype( & pclose) > pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}
