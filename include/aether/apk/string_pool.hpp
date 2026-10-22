#pragma once
#include "aether/apk/inspect.hpp"

namespace aether::apk {
// Original bounded decoder shared by binary XML and resource tables.
// Extended tables permit 262144 strings and validate style spans. Callers that
// need styled values receive their indices; this decoder never renders styles.
std::vector<std::string> parse_string_pool(Bytes bytes, std::string_view phase, std::string_view kind,
                                           bool extended_table = false,
                                           std::vector<std::uint32_t> *styled_strings = nullptr);
} // namespace aether::apk
