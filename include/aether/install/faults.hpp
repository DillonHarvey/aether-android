#pragma once
#include <cstdint>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace aether::install {
// Diagnostic text can originate in the worker/guest. It is evidence, never an
// instruction or a trusted attribution of cause. No private files are collected.
struct DiagnosticFault {
    std::string stage, code, message, package_sha256, aether_version, aether_configuration;
    std::uint64_t package_generation = 0, utc_100ns = 0;
    bool message_truncated = false;
    std::vector<std::string> causes;
};
struct FaultHistory {
    std::vector<DiagnosticFault> entries;
    std::string status = "absent", code;
    bool complete = true;
};
DiagnosticFault capture_fault(std::exception_ptr error, std::string_view stage,
                              std::string_view package_sha256 = {}, std::uint64_t generation = 0);
// Host-only append and durable flush. Existing records are never replaced or
// pruned. Storage/format/capacity failures throw and must be shown to the owner.
void retain_fault(const std::filesystem::path &store, std::string_view app_id,
                  const DiagnosticFault &fault);
// Read errors retain the valid prefix and report explicit incomplete status.
FaultHistory read_faults(const std::filesystem::path &store, std::string_view app_id);
std::string fault_json(const DiagnosticFault &fault);
std::string fault_history_json(const FaultHistory &history);
std::string fault_history_text(const FaultHistory &history);
} // namespace aether::install
