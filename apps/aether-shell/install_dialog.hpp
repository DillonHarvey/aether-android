#pragma once
#include <filesystem>

namespace aether::install {
int show_install_dialog(const std::filesystem::path &source, const std::filesystem::path &root, bool json);
}
