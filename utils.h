#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <array>
#include <memory>
#include <stdexcept>

struct DriverPackage {
    std::string moduleName;
    std::string infFile;
    std::string path;
};
std::string trim(const std::string& str);
std::vector<DriverPackage> getDriverPackages();
std::vector<std::string> getWMICApps();
std::vector<std::string> getWindowsStoreApps();
std::string exec(const char *cmd);
