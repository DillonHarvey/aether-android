#pragma once
#include <optional>
#include <string>
#include <string_view>

namespace aether::install {
struct LinkActivation {
    std::string app_id;
    std::u16string uri;
};
// The raw wWinMain command tail excludes the executable name. A different
// command returns no value; recognized but ambiguous activation syntax refuses.
// This parser performs no registry, store, permission or launch operation.
std::optional<LinkActivation> parse_link_activation(std::u16string_view raw_tail);
} // namespace aether::install
