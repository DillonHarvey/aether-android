#pragma once
#include "aether/dex/string_table.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace aether::dex {
struct Class;
// Binary names and array names map only into the existing DEX namespace.
std::optional<std::string> binary_descriptor(std::u16string_view name);
std::u16string binary_name(std::string_view descriptor);
// The definition describes the non-array component. A null definition is a
// core/provider class without retained DEX nesting metadata, not an annotation
// absence proof for an arbitrarily named nested provider class.
std::u16string simple_name(std::string_view descriptor, const Class *definition,
                          const StringTable &strings);
} // namespace aether::dex
