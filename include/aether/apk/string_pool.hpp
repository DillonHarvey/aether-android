#pragma once
#include "aether/apk/inspect.hpp"

namespace aether::apk {
// Original bounded decoder shared by binary XML and resource tables.
std::vector<std::string> parse_string_pool(Bytes bytes, std::string_view phase, std::string_view kind,
                                           bool metadata_preview = false);
} // namespace aether::apk
