#pragma once
#include "aether/apk/inspect.hpp"
#include <functional>
#include <string_view>

namespace aether::apk {
inline constexpr std::uint32_t runtime_xml_absent = UINT32_MAX;

struct RuntimeXmlString {
    std::size_t offset = 0, length = 0;
};
struct RuntimeXmlAttribute {
    std::uint32_t namespace_index = runtime_xml_absent, name_index = runtime_xml_absent;
    std::uint32_t raw_value_index = runtime_xml_absent, resource_id = 0;
    std::uint32_t data = 0;
    std::uint8_t type = 0;
    std::size_t source_offset = 0;
};
enum class RuntimeXmlNodeKind : std::uint8_t {
    namespace_start, namespace_end, element_start, element_end, text
};
struct RuntimeXmlNode {
    RuntimeXmlNodeKind kind = RuntimeXmlNodeKind::element_start;
    std::uint32_t namespace_index = runtime_xml_absent, name_index = runtime_xml_absent;
    std::uint32_t comment_index = runtime_xml_absent;
    std::uint32_t parent = runtime_xml_absent, matching = runtime_xml_absent;
    // Namespace-start stack link; unused by other kinds.
    std::uint32_t previous_namespace = runtime_xml_absent;
    std::uint32_t line = 0, depth = 0;
    std::size_t source_offset = 0, attribute_begin = 0;
    std::uint16_t attribute_count = 0;
    // Encoded one-based indexes: zero means absent, not attribute zero.
    std::uint16_t id_index = 0, class_index = 0, style_index = 0;
    // Text nodes retain their Res_value as well as their string index (name_index).
    std::uint32_t data = 0;
    std::uint8_t type = 0;
};
struct RuntimeXmlDocument {
    std::vector<RuntimeXmlString> strings;
    std::vector<char> utf8;
    std::vector<std::uint32_t> resource_map;
    std::vector<RuntimeXmlNode> nodes;
    std::vector<RuntimeXmlAttribute> attributes;
    // Includes the document object and actual owned vector capacities; excludes
    // the externally owned encoded input. No borrowed input survives decoding.
    std::size_t storage_bytes() const noexcept;
    // Peak includes input.size() plus all live decoder/document storage.
    std::size_t peak_storage_bytes = 0;
    std::string_view string(std::uint32_t index) const;
    std::string_view optional_string(std::uint32_t index) const;
    std::span<const RuntimeXmlAttribute> node_attributes(const RuntimeXmlNode &) const;
};
// Runtime-only original AXML decoder. working_bytes includes input.size(); the
// caller separately subtracts any unused capacity in its encoded-input owner.
// Fixed-count allocation avoids vector growth and simultaneous old/new buffers.
// Work units are actual encoded-byte reads, initialized vector elements,
// emitted UTF-8 bytes and string-comparison visits. Each is charged before its
// operation; the callback must not reenter guest execution. Exceptions propagate.
// Invalid/unsupported/admission failures use AETHER_AXML_INVALID, _UNSUPPORTED,
// and _LIMIT. Allocation failure propagates; no fallback document is returned.
RuntimeXmlDocument decode_runtime_xml(Bytes input, std::size_t working_bytes,
                                     const std::function<void(std::uint64_t)> &charge_work);
} // namespace aether::apk
