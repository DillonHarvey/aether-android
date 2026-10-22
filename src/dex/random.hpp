#pragma once
#include "aether/dex/runtime.hpp"
#include <functional>
namespace aether::dex {
inline constexpr std::string_view random_type="Ljava/util/Random;";
std::optional<HostClass> random_class(std::string_view);
bool random_method(std::string_view,std::string_view) noexcept;
class ManagedRandom {
  public:
    void initialize(std::uint64_t seed,bool subclass=false);
    void set_seed(std::uint64_t seed);
    std::uint32_t next(std::uint32_t bits);
    void check() const;
    std::optional<Value> invoke(ManagedRuntime &,std::string_view,std::string_view,std::span<const Value>,
                               const std::function<std::uint32_t(unsigned)> &next_bits);
  private:
    std::uint64_t state_=0;
    bool initialized_=false;
};
}
