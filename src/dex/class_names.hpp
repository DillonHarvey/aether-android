#pragma once
#include <optional>
#include <string>
#include <string_view>

namespace aether::dex {
// Binary names and array names map only into the existing DEX namespace.
std::optional<std::string> binary_descriptor(std::u16string_view name);
std::u16string binary_name(std::string_view descriptor);
} // namespace aether::dex
