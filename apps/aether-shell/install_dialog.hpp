#pragma once
#include <filesystem>
#include <string>

namespace aether::install {
int show_install_dialog(const std::filesystem::path &source, const std::filesystem::path &root, bool json);
int show_uninstall_dialog(const std::filesystem::path &root, const std::string &id, bool json);
}
