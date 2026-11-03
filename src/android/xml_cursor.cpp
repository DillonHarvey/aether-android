#include "aether/android/xml_cursor.hpp"
#include <utility>

namespace aether::android {
[[noreturn]] void XmlCursor::invalid(std::string message) {
    throw apk::InspectError("AETHER_XML_CURSOR_STATE", "runtime-xml-cursor", std::move(message));
}
void XmlCursor::require_open() const {
    if (closed_)
        throw apk::InspectError("AETHER_XML_CURSOR_CLOSED", "runtime-xml-cursor", "XML parser is closed");
}
void XmlCursor::charge(const XmlWorkCharge &charge_work) {
    if (!charge_work) invalid("XML cursor traversal has no host work ledger");
    charge_work(1);
}
bool XmlCursor::equal(std::string_view left, std::string_view right, const XmlWorkCharge &charge_work) {
    charge(charge_work);
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        charge(charge_work);
        if (left[index] != right[index]) return false;
    }
    return true;
}
XmlCursor::XmlCursor(apk::RuntimeXmlDocument &&document, XmlCursorSource source)
    : document_(std::move(document)), source_(source) {
    if (!source_.provenance_complete || !source_.resource_id || !source_.asset_cookie ||
        (!source_.sdk && !source_.source_id))
        invalid("XML cursor requires actual held resource/source-cookie provenance");
    if (document_.nodes.size() >= apk::runtime_xml_absent)
        invalid("XML cursor node indexes exceed their representation");
}
XmlCursor::XmlCursor(XmlCursor &&other) noexcept
    : document_(std::move(other.document_)), source_(other.source_), position_(other.position_),
      event_(other.event_), closed_(other.closed_) {
    other.close();
}
XmlCursor &XmlCursor::operator=(XmlCursor &&other) noexcept {
    if (this != &other) {
        document_ = std::move(other.document_);
        source_ = other.source_;
        position_ = other.position_;
        event_ = other.event_;
        closed_ = other.closed_;
        other.close();
    }
    return *this;
}
const apk::RuntimeXmlDocument &XmlCursor::document() const { require_open(); return document_; }
const XmlCursorSource &XmlCursor::source() const { require_open(); return source_; }
std::uint32_t XmlCursor::position() const { require_open(); return position_; }
XmlCursorEvent XmlCursor::event() const { require_open(); return event_; }
const apk::RuntimeXmlNode &XmlCursor::current() const {
    require_open();
    if (position_ == apk::runtime_xml_absent || position_ >= document_.nodes.size())
        invalid("XML cursor is not positioned on a document node");
    return document_.nodes[position_];
}
XmlCursorEvent XmlCursor::next(const XmlWorkCharge &charge_work) {
    require_open();
    if (event_ == XmlCursorEvent::end_document) return event_;
    for (;;) {
        const auto index = position_ == apk::runtime_xml_absent ? std::size_t{0} : std::size_t(position_) + 1;
        if (index >= document_.nodes.size()) {
            position_ = apk::runtime_xml_absent;
            event_ = XmlCursorEvent::end_document;
            return event_;
        }
        charge(charge_work);
        position_ = static_cast<std::uint32_t>(index);
        switch (document_.nodes[index].kind) {
        case apk::RuntimeXmlNodeKind::namespace_start: event_ = XmlCursorEvent::namespace_start; continue;
        case apk::RuntimeXmlNodeKind::namespace_end: event_ = XmlCursorEvent::namespace_end; continue;
        case apk::RuntimeXmlNodeKind::element_start: event_ = XmlCursorEvent::start_tag; return event_;
        case apk::RuntimeXmlNodeKind::element_end: event_ = XmlCursorEvent::end_tag; return event_;
        case apk::RuntimeXmlNodeKind::text: event_ = XmlCursorEvent::text; return event_;
        }
        invalid("XML cursor encountered an unknown node kind");
    }
}
std::span<const apk::RuntimeXmlAttribute> XmlCursor::attributes() const {
    return document_.node_attributes(current());
}
const apk::RuntimeXmlAttribute &XmlCursor::attribute(std::size_t index) const {
    const auto values = attributes();
    if (index >= values.size()) invalid("XML attribute index exceeds the current element");
    return values[index];
}
const apk::RuntimeXmlAttribute *XmlCursor::find_attribute(std::uint32_t resource_id,
                                                        const XmlWorkCharge &charge_work) const {
    require_open();
    if (!resource_id) return nullptr; // Zero denotes absence of a resource-map identity.
    const apk::RuntimeXmlAttribute *found = nullptr;
    for (const auto &value : attributes()) {
        charge(charge_work);
        if (value.resource_id == resource_id) {
            if (found) invalid("XML element has ambiguous repeated numeric attribute identity");
            found = &value;
        }
    }
    return found;
}
const apk::RuntimeXmlAttribute *XmlCursor::find_attribute(XmlAttributeName name,
                                                        const XmlWorkCharge &charge_work) const {
    for (const auto &value : attributes()) {
        charge(charge_work);
        const bool present = value.namespace_index != apk::runtime_xml_absent;
        if (present != name.namespace_present) continue;
        if (present && !equal(document_.string(value.namespace_index), name.namespace_text, charge_work)) continue;
        if (equal(document_.string(value.name_index), name.name, charge_work)) return &value;
    }
    return nullptr;
}
const apk::RuntimeXmlAttribute *XmlCursor::special(XmlSpecial which) const {
    const auto &node = current();
    if (node.kind != apk::RuntimeXmlNodeKind::element_start)
        invalid("Special XML attribute access requires a start element");
    std::uint16_t one_based = 0;
    switch (which) {
    case XmlSpecial::id: one_based = node.id_index; break;
    case XmlSpecial::class_name: one_based = node.class_index; break;
    case XmlSpecial::style: one_based = node.style_index; break;
    default: invalid("Unknown special XML attribute selector");
    }
    return one_based ? &attribute(std::size_t(one_based) - 1) : nullptr;
}
std::optional<std::string_view> XmlCursor::raw_string(const apk::RuntimeXmlAttribute &value) const {
    require_open();
    if (value.raw_value_index == apk::runtime_xml_absent) return std::nullopt;
    return document_.string(value.raw_value_index);
}
std::string_view XmlCursor::literal_string(const apk::RuntimeXmlAttribute &value) const {
    require_open();
    if (value.type != 3) invalid("XML attribute is not a literal XML-pool string");
    return document_.string(value.data);
}
std::size_t XmlCursor::storage_bytes() const noexcept {
    return sizeof(*this) + document_.storage_bytes() - sizeof(document_);
}
void XmlCursor::close() noexcept {
    document_ = apk::RuntimeXmlDocument{};
    source_ = {};
    position_ = apk::runtime_xml_absent;
    event_ = XmlCursorEvent::end_document;
    closed_ = true;
}
} // namespace aether::android
