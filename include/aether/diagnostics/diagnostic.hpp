#pragma once
#include <map>
#include <string>

namespace aether {
struct DiagnosticEvent {
    std::string code;
    std::string phase;
    std::string message;
    std::string action;
    std::string app_id;
    std::string module;
    std::map<std::string, std::string> details;
    std::string json() const;
    std::string text() const;
};
} // namespace aether
