#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view character_type = "Ljava/lang/Character;";
std::optional<HostClass> character_class(std::string_view type);
bool character_method(std::string_view name, std::string_view signature) noexcept;
bool character_static(std::string_view name, std::string_view signature) noexcept;
class ManagedCharacter {
  public:
    void initialize(std::uint32_t bits);
    std::uint16_t value() const;
    std::optional<Value> invoke(ManagedRuntime &, std::string_view name, std::string_view signature,
                                std::span<const Value>, const ManagedCharacter *other);
  private:
    std::uint16_t value_ = 0;
    bool initialized_ = false;
};
}
