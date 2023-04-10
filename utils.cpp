#include "utils.h"
#include <unordered_map>
#include <regex>
#include <iostream>
#include <fstream>
#include <iterator>
#include <memory>
#include <array>
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

    std::string driverqueryOutput = exec("driverquery /V /FO LIST");
    std::istringstream driverqueryStream(driverqueryOutput);
    std::vector<std::string> driverqueryLines;
    std::string driverqueryLine;

    while (std::getline(driverqueryStream, driverqueryLine)) {
        driverqueryLines.push_back(driverqueryLine);
    }

    while (std::getline(pnputilStream, line)) {
        if (line.find(".inf") != std::string::npos) {
            std::cout << "Found .inf line: " << line << std::endl;
            DriverPackage driverPackage;
            driverPackage.infFile = trim(split(line, ':')[1]);

            std::string moduleName = trim(split(line, ':')[3]);
            driverPackage.moduleName = moduleName;
            std::cout << "Parsed moduleName: " << moduleName << std::endl;

            std::cout << "Processing driverquery output for: " << moduleName << std::endl;

            bool foundModuleName = false;
            for (const auto& dqLine : driverqueryLines) {
                std::cout << "Driverquery line: " << dqLine << std::endl;
                if (dqLine.find(moduleName) != std::string::npos) {
                    foundModuleName = true;
                    std::cout << "Found moduleName in driverquery output: " << moduleName << std::endl;
                } else if (foundModuleName && dqLine.find("Path") != std::string::npos) {
                    driverPackage.path = trim(split(dqLine, ':')[1]);
                    std::cout << "Found Path: " << driverPackage.path << std::endl;
                    break;
                }
            }

            driverPackages.push_back(driverPackage);
            std::cout << "Added driver package for: " << moduleName << std::endl;
        }
    }

    std::cout << "Finished processing pnputil output." << std::endl;

    return driverPackages;
}




std::string exec(const char* cmd) {
    std::array<char, 128> buffer{};
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


