#pragma once
#include "aether/security/worker.hpp"
#include <array>

namespace aether::security {
// Compiled first-party hostile-resource fixtures, selected only by the trusted test parent.
void run_resource_probe(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t scenario);
// Compiled original DEX only; no caller-supplied APK, method, code or path.
void run_async_task_probe(HANDLE writer, std::uint64_t session);
void run_stream_probe(HANDLE writer, std::uint64_t session);
void run_uuid_probe(HANDLE writer, std::uint64_t session);
void run_regex_probe(HANDLE writer, std::uint64_t session);
void run_progress_probe(HANDLE owned_mapping);
void run_native_fault_probe(HANDLE owned_mapping,std::uint64_t action);
// Fixed original ARM64 exit proof only: no caller-selected code, APK or host path.
std::uint8_t run_process_exit_probe(HANDLE writer, std::uint64_t session, std::uint8_t status);
void run_nano_time_probe(HANDLE reader, HANDLE writer, std::uint64_t session, bool allowed);
void run_preferences_probe(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t action, std::uint64_t marker);
std::array<DWORD, 16> runtime_image_probe();
} // namespace aether::security
