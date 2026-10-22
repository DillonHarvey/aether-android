#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view boolean_type="Ljava/lang/Boolean;";
std::optional<HostClass> boolean_class(std::string_view descriptor);
class ManagedBoolean {
  public:
    void initialize(bool value);
    bool value() const;
    std::optional<Value> invoke(ManagedRuntime &,std::string_view name,std::string_view signature,
                                std::span<const Value> arguments,const ManagedBoolean *other);
  private:
    bool value_=false,initialized_=false;
};
} // namespace aether::dex
