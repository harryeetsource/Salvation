#include "utils.h"
#include <unordered_map>
#include <regex>
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}
std::vector<DriverPackage> getDriverPackages() {
    std::vector<DriverPackage> driverPackages;

    std::string pnputilOutput = exec("pnputil /enum-drivers");
    std::istringstream pnputilStream(pnputilOutput);
    std::string line;

    while (std::getline(pnputilStream, line)) {
        if (line.find(".inf") != std::string::npos) {
            DriverPackage driverPackage;
            driverPackage.infFile = split(line, ' ')[0];

            std::string moduleName = split(line, ' ')[1];
            driverPackage.moduleName = moduleName;

            std::string driverqueryCommand = "driverquery /V /FO LIST ";
std::string moduleNameQuoted = "\"" + driverPackage.moduleName + "\"";
std::string driverqueryOutput = exec((driverqueryCommand + moduleNameQuoted).c_str());

            std::istringstream driverqueryStream(driverqueryOutput);
            std::string driverLine;
            bool foundModuleName = false;
            while (std::getline(driverqueryStream, driverLine)) {
                std::vector<std::string> parts = split(driverLine, ',');

                if (!foundModuleName) {
                    if (parts.size() >= 2 && parts[0].substr(1, parts[0].size() - 2) == moduleName) {
                        foundModuleName = true;
                    }
                } else if (foundModuleName && parts.size() >= 2 && parts[0].substr(1, parts[0].size() - 2) == "Path") {
                    driverPackage.path = parts[1].substr(1, parts[1].size() - 2);
                    break;
                }
            }

            driverPackages.push_back(driverPackage);
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
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

