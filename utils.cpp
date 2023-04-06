#include "utils.h"
std::vector<DriverPackage> getDriverPackages() {
    std::vector<DriverPackage> driverPackages;
    std::istringstream input(exec("driverquery /FO LIST /V"));
    std::string line;
    DriverPackage currentDriverPackage;

    while (std::getline(input, line)) {
        size_t delimiter = line.find(':');
        if (delimiter != std::string::npos) {
            std::string key = line.substr(0, delimiter);
            std::string value = line.substr(delimiter + 1);
            value.erase(0, value.find_first_not_of(" ")); // Remove leading spaces

            if (key == "Module Name") {
                if (!currentDriverPackage.module_name.empty()) {
                    driverPackages.push_back(currentDriverPackage);
                    currentDriverPackage = DriverPackage(); // Reset the struct for the next driver package
                }
                currentDriverPackage.module_name = value;
            } else if (key == "Display Name") {
                currentDriverPackage.display_name = value;
            } else if (key == "Description") {
                currentDriverPackage.description = value;
            } else if (key == "Driver Type") {
                currentDriverPackage.driver_type = value;
            } else if (key == "Start Mode") {
                currentDriverPackage.start_mode = value;
            } else if (key == "State") {
                currentDriverPackage.state = value;
            } else if (key == "Status") {
                currentDriverPackage.status = value;
            } else if (key == "Accept Stop") {
                currentDriverPackage.accept_stop = (value == "TRUE");
            } else if (key == "Accept Pause") {
                currentDriverPackage.accept_pause = (value == "TRUE");
            } else if (key == "Paged Pool(bytes)") {
                currentDriverPackage.paged_pool_bytes = std::stoi(value);
            } else if (key == "Code(bytes)") {
                currentDriverPackage.code_bytes = std::stoi(value);
            } else if (key == "BSS(bytes)") {
                currentDriverPackage.bss_bytes = std::stoi(value);
            } else if (key == "Link Date") {
                currentDriverPackage.link_date = value;
            } else if (key == "Path") {
                currentDriverPackage.path = value;
            }
        }
    }

    if (!currentDriverPackage.module_name.empty()) {
        driverPackages.push_back(currentDriverPackage); // Add the last driver package
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
