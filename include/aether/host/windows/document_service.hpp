#pragma once
#include "aether/host/document_service.hpp"
#include <filesystem>
#include <memory>

namespace aether::host {
struct PreparedDocumentSource {
    DocumentInfo info;
    std::shared_ptr<DocumentService> service;
};
// Host preparation only. This acquires no app consent or guest authority;
// a caller must separately review and approve the recipient and document.
// Only metadata and the service are returned, never the selected host path.
PreparedDocumentSource prepare_document_source(const std::filesystem::path &path,
                                                std::string_view canonical_mime);
} // namespace aether::host
