#pragma once
#include "aether/apk/inspect.hpp"
#include <map>

namespace aether::apk {
struct NativeMember {
    PackageFile file;
    std::string name;
    std::vector<std::string> dependencies;
    bool is_elf = false;
};
// Immutable package metadata, distinct from the much smaller executable graph.
// Selecting a closure never reads, maps, initializes or executes a member.
class NativeInventory {
  public:
    static constexpr std::size_t maximum_members = 1024;
    static constexpr std::size_t maximum_metadata_bytes = 4 * 1024 * 1024;
    NativeInventory() = default;
    explicit NativeInventory(std::span<const NativeInfo> inputs);
    std::span<const NativeMember> members() const noexcept;
    std::optional<std::size_t> find(std::string_view name) const;
    std::vector<std::size_t> select(std::string_view root) const;
    std::size_t metadata_bytes() const noexcept;

  private:
    std::vector<NativeMember> members_;
    std::map<std::string, std::size_t, std::less<>> names_;
    std::size_t metadata_bytes_ = 0;
};
} // namespace aether::apk
