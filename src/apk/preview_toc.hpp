#pragma once
#include "aether/apk/inspect.hpp"
#include <string>

namespace aether::apk {
struct PreviewToc {
    std::string package;
    std::string base;
};
// Original bounded protobuf wire reader. Only bundletool selection metadata is
// interpreted; unknown fields and asset-slice bodies are skipped by their extent.
PreviewToc preview_toc(Bytes bytes);
} // namespace aether::apk
