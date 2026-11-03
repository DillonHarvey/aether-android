#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>
#include <vector>

namespace aether::apk {
struct RuntimePathCommand {
    char verb = 0;
    std::array<double, 7> arguments{};
    std::uint8_t count = 0;
};
struct RuntimePath {
    std::vector<RuntimePathCommand> commands;
    // Dynamic retained capacity only; the enclosing owner accounts this object.
    std::size_t storage_bytes() const noexcept;
};
// Retains original absolute/relative geometry without rasterizing or flattening.
// Additional moveto pairs become lineto commands. Empty data denotes an empty
// path. working_bytes admits the fixed parser object and peak simultaneously live
// old/new command-vector capacity. The caller accounts its input owner and any
// allocated callback state separately; this function neither copies nor owns them.
// The host-owned callback charges bounded parsing steps: each consumed input byte
// and emitted command once, each numeric substring byte visited again by numeric
// conversion, and each old command relocated during growth (not host CPU
// instructions). It must not yield on soft
// quantum expiry: this synchronous provider completes before the next managed
// safepoint. It may throw only for terminal cancellation/failure or a hard stop.
// Parsing is not resumable
// and must not be restarted to obtain a fresh allowance. No guest callback occurs.
// InspectError: AETHER_PATH_INVALID or AETHER_PATH_LIMIT; bad_alloc propagates.
RuntimePath parse_runtime_path(std::string_view input, std::size_t working_bytes,
                               const std::function<void(std::uint64_t)> &charge_work);
} // namespace aether::apk
