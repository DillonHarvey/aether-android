#pragma once
#include <string>
#include <vector>

namespace aether::host {
struct Prerequisite {
    std::string name;
    std::string status;
    std::string location;
    std::string scope;
};
struct DoctorReport {
    std::string windows_build;
    std::string host_architecture;
    bool supported_host = false;
    std::vector<Prerequisite> prerequisites;
    bool development_ready() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
DoctorReport query_doctor();
} // namespace aether::host
