#pragma once
#include "aether/dex/runtime.hpp"
namespace aether::dex {
inline constexpr std::string_view byte_type="Ljava/lang/Byte;";
std::optional<HostClass> byte_class(std::string_view type);
bool byte_method(std::string_view name,std::string_view signature) noexcept;
class ManagedByte {
  public:
    void initialize(std::uint32_t bits);
    std::int32_t value() const;
    std::optional<Value> invoke(ManagedRuntime &,std::string_view name,std::string_view signature,
                               std::span<const Value>,const ManagedByte *other);
  private:
    std::int32_t value_=0;
    bool initialized_=false;
};
}
