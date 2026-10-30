#pragma once
#include "aether/host/document_service.hpp"
#include "aether/host/drop_text.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace aether::android {
// Android DragEvent action values. One host-issued identity spans an actual
// external drag; a document or plain-text descriptor appears only on DROP.
enum class DragAction : std::uint32_t { started = 1, location = 2, drop = 3, ended = 4, entered = 5, exited = 6 };
struct DragInput {
    DragAction action = DragAction::location;
    host::DropPayloadKind kind = host::DropPayloadKind::file;
    std::uint64_t id = 0;
    float x = 0, y = 0; // Activity-local density-independent coordinates.
    std::string mime_type;
    std::optional<host::DocumentInfo> document;
    std::optional<host::DropTextInfo> text_info; // DROP-only broker descriptor.
    // Worker-only exact broker-resolved payload. Never serialized in commands.
    std::optional<std::u16string> text;
};
} // namespace aether::android
