#pragma once
#include "aether/install/open_link.hpp"
#include "aether/install/open_file.hpp"

namespace aether::install {
// Returns only the explicitly selected, freshly prepared installed application.
// The caller launches after this chooser and its reads have closed.
std::optional<security::InstalledActivity> show_link_dialog(const OpenLinkOptions &options);
std::optional<security::InstalledActivity> show_file_dialog(const OpenFileOptions &options);
} // namespace aether::install
