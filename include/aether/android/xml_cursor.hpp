#pragma once
#include "aether/apk/runtime_xml.hpp"
#include <functional>
#include <optional>

namespace aether::android {
// Supplied by the held-resource consumer, not inferred from XML pool indexes.
// A zero source_id is valid only for the authenticated embedded SDK source.
struct XmlCursorSource {
    std::uint32_t resource_id = 0, asset_cookie = 0, source_id = 0, native_flags = 0;
    std::uint16_t density = 0;
    bool sdk = false, provenance_complete = false;
};
enum class XmlCursorEvent : std::uint8_t {
    start_document, end_document, start_tag, end_tag, text, namespace_start, namespace_end
};
enum class XmlSpecial : std::uint8_t { id, class_name, style };
struct XmlAttributeName {
    // An absent namespace and a present empty pool string remain distinct.
    bool namespace_present = false;
    std::string_view namespace_text, name;
};
// The caller's existing aggregate host-work ledger, never a new allowance.
// It must not reenter guest execution or mutate/replace the cursor. Lookup
// scans are atomic native operations; scheduling suspension must not replay
// them. Hard admission exceptions propagate without a retry or fallback.
using XmlWorkCharge = std::function<void(std::uint64_t)>;

// Native backing for one live parser identity. No guest object is fabricated by
// this adapter. The framework owns that identity and any traced Resources root.
// Every returned reference/view is borrowed until move, close, destruction or
// replacement of the owning provider state; none may cross a guest callback.
class XmlCursor {
  public:
    XmlCursor(apk::RuntimeXmlDocument &&document, XmlCursorSource source);
    XmlCursor(const XmlCursor &) = delete;
    XmlCursor &operator=(const XmlCursor &) = delete;
    XmlCursor(XmlCursor &&other) noexcept;
    XmlCursor &operator=(XmlCursor &&other) noexcept;

    const apk::RuntimeXmlDocument &document() const;
    const XmlCursorSource &source() const;
    std::uint32_t position() const;
    XmlCursorEvent event() const;
    const apk::RuntimeXmlNode &current() const;
    // Namespace stack nodes are retained in the document but skipped by the
    // ordinary pull advance. Each committed step survives a later charge error.
    XmlCursorEvent next(const XmlWorkCharge &charge_work);
    std::span<const apk::RuntimeXmlAttribute> attributes() const;
    const apk::RuntimeXmlAttribute &attribute(std::size_t index) const;
    const apk::RuntimeXmlAttribute *find_attribute(std::uint32_t resource_id,
                                                  const XmlWorkCharge &charge_work) const;
    const apk::RuntimeXmlAttribute *find_attribute(XmlAttributeName name,
                                                  const XmlWorkCharge &charge_work) const;
    const apk::RuntimeXmlAttribute *special(XmlSpecial which) const;
    std::optional<std::string_view> raw_string(const apk::RuntimeXmlAttribute &value) const;
    std::string_view literal_string(const apk::RuntimeXmlAttribute &value) const;

    // Includes this cursor and actual document capacities, counting its embedded
    // RuntimeXmlDocument object once. No work callback or input bytes are owned.
    std::size_t storage_bytes() const noexcept;
    bool closed() const noexcept { return closed_; }
    // Releases actual owned document capacity. An embedding HostObjectState must
    // also reconcile its recorded charge through ManagedRuntime::set_host_state;
    // changing a state's live bytes() alone does not refund its recorded bytes.
    void close() noexcept;

  private:
    apk::RuntimeXmlDocument document_;
    XmlCursorSource source_;
    std::uint32_t position_ = apk::runtime_xml_absent;
    XmlCursorEvent event_ = XmlCursorEvent::start_document;
    bool closed_ = false;
    void require_open() const;
    [[noreturn]] static void invalid(std::string message);
    static void charge(const XmlWorkCharge &charge_work);
    static bool equal(std::string_view left, std::string_view right,
                      const XmlWorkCharge &charge_work);
};
} // namespace aether::android
