#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace aether::install {
struct FileActivation {
    std::string app_id;
    std::filesystem::path file;
};
// Parse the raw wWinMain tail before argv. This does not open a file or grant
// access; the held-document provider and explicit recipient review do that.
std::optional<FileActivation> parse_file_activation(std::u16string_view raw_tail);
} // namespace aether::install
