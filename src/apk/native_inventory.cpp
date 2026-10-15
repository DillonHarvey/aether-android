#include "aether/apk/native_inventory.hpp"
#include "aether/elf/limits.hpp"
#include <algorithm>

namespace aether::apk {
namespace {
[[noreturn]] void bad(std::string message, bool selection = false) {
    throw InspectError(selection ? "AETHER_APK_NATIVE_SELECTION" : "AETHER_APK_NATIVE_INVENTORY",
                       selection ? "native-load" : "apk-admission", std::move(message));
}
bool leaf(std::string_view name) {
    return !name.empty() && name.size() <= 255 && name != "." && name != ".." &&
           std::none_of(name.begin(), name.end(), [](unsigned char c) {
               return c < 32 || c == 127 || c == '/' || c == '\\' || c == ':';
           });
}
} // namespace
NativeInventory::NativeInventory(std::span<const NativeInfo> inputs) {
    const auto count = static_cast<std::size_t>(std::count_if(
        inputs.begin(), inputs.end(), [](const auto &input) { return input.abi == "arm64-v8a"; }));
    if (!inputs.empty() && !count)
        bad("Native libraries require arm64-v8a; this APK provides only unsupported ABIs.");
    if (count > maximum_members)
        bad("ARM64 package inventory exceeds 1024 members; executable graph limits are independent.");
    members_.reserve(count);
    const auto charge = [&](std::size_t bytes) {
        if (bytes > maximum_metadata_bytes - metadata_bytes_)
            bad("ARM64 package inventory exceeds 4 MiB of accounted metadata.");
        metadata_bytes_ += bytes;
    };
    constexpr std::string_view prefix = "lib/arm64-v8a/";
    for (const auto &input : inputs) {
        if (input.abi != "arm64-v8a")
            continue;
        const auto path = std::string_view(input.file.path);
        if (!path.starts_with(prefix) || !leaf(path.substr(prefix.size())))
            bad("ARM64 native members require unique bounded leaf names: " + input.file.path);
        const auto name = path.substr(prefix.size());
        if (input.file.sha256.size() != 64 ||
            std::any_of(input.file.sha256.begin(), input.file.sha256.end(),
                        [](char c) { return !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }))
            bad("ARM64 native inventory requires an inspected SHA-256: " + input.file.path);
        if (input.file.bytes > elf::streamed_native_bytes)
            bad("An ARM64 member exceeds the current 128 MiB streamed native file limit: " + input.file.path);
        if ((input.is_elf && (input.machine != 183 || !input.file.bytes)) ||
            (!input.is_elf && (input.machine || !input.dependencies.empty())))
            bad("Inconsistent ELF/data classification in ARM64 inventory: " + input.file.path);
        if (input.dependencies.size() > 256)
            bad("ARM64 member inventory exceeds 256 dependency names: " + input.file.path);
        charge(sizeof(NativeMember) + path.size() + name.size() * 2 + input.file.sha256.size() +
               input.file.container.size() + input.dependencies.size() * sizeof(std::string));
        for (const auto &dependency : input.dependencies) {
            if (!leaf(dependency))
                bad("Unsupported native dependency name in " + input.file.path);
            charge(dependency.size());
        }
        if (!names_.emplace(name, members_.size()).second)
            bad("Duplicate ARM64 native member: " + input.file.path);
        members_.push_back({input.file, std::string(name), input.dependencies, input.is_elf});
    }
}
std::span<const NativeMember> NativeInventory::members() const noexcept { return members_; }
std::size_t NativeInventory::metadata_bytes() const noexcept { return metadata_bytes_; }
std::optional<std::size_t> NativeInventory::find(std::string_view name) const {
    const auto found = names_.find(name);
    return found == names_.end() ? std::nullopt : std::optional<std::size_t>(found->second);
}
std::vector<std::size_t> NativeInventory::select(std::string_view root) const {
    const auto start = find(root);
    if (!start)
        bad("APK has no arm64-v8a/" + std::string(root), true);
    std::vector<std::size_t> selected;
    std::vector<bool> visited(members_.size());
    std::uint64_t bytes = 0;
    const auto add = [&](std::size_t index) {
        if (visited[index])
            return;
        const auto &member = members_[index];
        if (!member.is_elf)
            bad("Native member is opaque data, not executable ELF: " + member.file.path, true);
        if (selected.size() == elf::native_graph_modules)
            bad("Requested native dependency graph exceeds 16 packaged ELF modules.", true);
        if (member.file.bytes > elf::streamed_native_bytes - bytes)
            bad("Requested native dependency graph exceeds 128 MiB of ELF input.", true);
        bytes += member.file.bytes;
        visited[index] = true;
        selected.push_back(index);
    };
    add(*start);
    for (std::size_t next = 0; next < selected.size(); ++next)
        for (const auto &dependency : members_[selected[next]].dependencies)
            if (const auto index = find(dependency))
                add(*index);
    // Unpackaged dependencies still require GuestLoader's actual import provider;
    // selection never invents a system library or treats its absence as success.
    return selected;
}
} // namespace aether::apk
