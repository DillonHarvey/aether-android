#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view integer_type = "Ljava/lang/Integer;";
std::optional<HostClass> integer_class(std::string_view descriptor);
// ASCII Character.digit subset only; unsupported Unicode is never reported as
// an invalid number. Both public parseInt overloads share this bounded parser.
std::uint32_t parse_integer(ManagedRuntime &runtime,ObjectId text,std::int32_t radix);
class ManagedInteger {
  public:
    void initialize(std::uint32_t bits);
    std::uint32_t value() const;
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view name, std::string_view signature,
                                std::span<const Value> arguments, const ManagedInteger *other);

  private:
    std::uint32_t bits_ = 0;
    bool initialized_ = false;
};
} // namespace aether::dex
