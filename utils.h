#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <array>
#include <memory>
#include <stdexcept>

struct DriverPackage {
    std::string displayName;
    std::string moduleName;
    std::string infFile;
    std::string path;
    std::string description;
    std::string driver_type;
    std::string start_mode;
    std::string state;
    std::string status;
    bool accept_stop;
    bool accept_pause;
    int paged_pool_bytes;
    int code_bytes;
    int bss_bytes;
    std::string link_date;
};
std::vector<DriverPackage> getDriverPackages();
std::vector<std::string> getWMICApps();
std::vector<std::string> getWindowsStoreApps();
std::string exec(const char *cmd);
