#include "aether/diagnostics/diagnostic.hpp"
#include "aether/common/text.hpp"

namespace aether {
std::string DiagnosticEvent::json() const {
    std::string result = "{\"schemaVersion\":1,\"level\":\"error\",\"code\":" + json_quote(code) +
                         ",\"phase\":" + json_quote(phase) + ",\"appId\":" + json_quote(app_id) +
                         ",\"module\":" + json_quote(module) + ",\"message\":" + json_quote(message) +
                         ",\"action\":" + json_quote(action) + ",\"details\":{";
    bool first = true;
    for (const auto &[key, value] : details) {
        if (!first)
            result += ',';
        first = false;
        result += json_quote(key) + ':' + json_quote(value);
    }
    return result + "}}";
}
std::string DiagnosticEvent::text() const {
    return code + " [" + phase + "]: " + message + "\nAction: " + action;
}
} // namespace aether
