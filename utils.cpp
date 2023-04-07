#include "utils.h"
#include <unordered_map>
#include <regex>
#include <iostream>
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

    std::cout << "Starting to process pnputil output..." << std::endl;

    while (std::getline(pnputilStream, line)) {
        if (line.find(".inf") != std::string::npos) {
            std::cout << "Found .inf line: " << line << std::endl;
            DriverPackage driverPackage;
            driverPackage.infFile = trim(split(line, ':')[1]);

            std::string moduleName = trim(split(line, ':')[3]);
            driverPackage.moduleName = moduleName;

            std::string driverqueryCommand = "driverquery /V /FO LIST /FI \"MODULENAME eq " + moduleName + "\"";
            std::string driverqueryOutput = exec(driverqueryCommand.c_str());

            std::istringstream driverqueryStream(driverqueryOutput);
            std::string driverqueryLine;

            std::cout << "Processing driverquery output for: " << moduleName << std::endl;

            while (std::getline(driverqueryStream, driverqueryLine)) {
                if (driverqueryLine.find("Path") != std::string::npos) {
                    std::vector<std::string> pathParts = split(driverqueryLine, ':');
                    if (pathParts.size() > 1) {
                        driverPackage.path = trim(pathParts[1]);
                        break;
                    }
                }
            }

            driverPackages.push_back(driverPackage);
            std::cout << "Added driver package for: " << moduleName << std::endl;
        }
    }

    std::cout << "Finished processing pnputil output." << std::endl;

    return driverPackages;
}





std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t");
    return str.substr(first, (last - first + 1));
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

