#pragma once
#include "aether/dex/runtime.hpp"
namespace aether::dex {
inline constexpr std::string_view float_type="Ljava/lang/Float;",double_type="Ljava/lang/Double;";
std::optional<HostClass> floating_class(std::string_view);
bool floating_method(std::string_view type,std::string_view name,std::string_view signature) noexcept;
bool floating_static(std::string_view name,std::string_view signature) noexcept;
std::optional<Value> floating_static_call(std::string_view type,std::string_view name,std::string_view signature,std::span<const Value>);
std::optional<Value> floating_constant(std::string_view type,std::string_view name,std::string_view descriptor);
class ManagedFloating {
  public:
    explicit ManagedFloating(bool wide):wide_(wide){}
    void initialize(std::uint64_t);
    std::uint64_t bits() const;
    std::uint64_t canonical() const;
    std::uint32_t hash() const;
    bool equals(const ManagedFloating *) const;
    std::optional<Value> invoke(ManagedRuntime &,std::string_view name,std::string_view signature,
                               std::span<const Value>,const ManagedFloating *other);
  private:
    const bool wide_;
    bool initialized_=false;
    std::uint64_t bits_=0;
};
}
