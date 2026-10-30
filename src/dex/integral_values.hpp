#pragma once
#include "aether/dex/runtime.hpp"
namespace aether::dex {
inline constexpr std::string_view long_type="Ljava/lang/Long;", short_type="Ljava/lang/Short;";
std::optional<HostClass> integral_class(std::string_view type);
bool integral_method(std::string_view type,std::string_view name,std::string_view signature) noexcept;
// Signed 64-bit two's-complement input, nearest-even IEEE output, no host fenv.
std::uint64_t integral_floating_bits(std::uint64_t bits, bool wide) noexcept;
class ManagedIntegral {
  public:
    explicit ManagedIntegral(bool is_long):long_(is_long){}
    void initialize(std::uint64_t bits);
    std::uint64_t bits() const;
    bool is_long() const noexcept{return long_;}
    std::optional<Value> invoke(ManagedRuntime &,std::string_view name,std::string_view signature,
                               std::span<const Value>,const ManagedIntegral *other);
  private:
    const bool long_;
    bool initialized_=false;
    std::uint64_t bits_=0;
};
}
