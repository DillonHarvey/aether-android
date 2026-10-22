#pragma once
#include "aether/dex/runtime.hpp"
#include <array>
namespace aether::dex {
inline constexpr std::string_view uuid_type="Ljava/util/UUID;";
std::optional<HostClass> uuid_class(std::string_view descriptor);
// Deterministic RFC version/variant transformation, not an entropy source.
std::array<std::uint64_t,2> uuid_v4_bits(std::span<const std::uint8_t,16> bytes) noexcept;
class ManagedUuid {
  public:
    void initialize(std::uint64_t most,std::uint64_t least);
    std::uint64_t most() const;
    std::uint64_t least() const;
    std::uint32_t hash() const;
    bool equals(const ManagedUuid *other) const;
    std::optional<Value> invoke(ManagedRuntime &,std::string_view name,std::string_view signature,
                               std::span<const Value> arguments,const ManagedUuid *other);
  private:
    std::uint64_t most_=0,least_=0;
    bool initialized_=false;
};
} // namespace aether::dex
