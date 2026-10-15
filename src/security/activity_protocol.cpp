#include "aether/security/activity_protocol.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <functional>
#include <set>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ACTIVITY_PROTOCOL: ") + message);
}
struct Writer {
    std::vector<std::uint8_t> bytes;
    std::size_t limit;
    void number(std::uint64_t value) {
        require(bytes.size() <= limit - 8, "Encoded message exceeds limit");
        for (unsigned i = 0; i < 8; ++i)
            bytes.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
    }
    void scalar(float value) { number(std::bit_cast<std::uint32_t>(value)); }
    void text(std::string_view value, std::size_t maximum) {
        require(value.size() <= maximum, "Text exceeds field limit");
        number(value.size());
        require(value.size() <= limit - bytes.size(), "Text exceeds message limit");
        bytes.insert(bytes.end(), value.begin(), value.end());
    }
    void wide(std::u16string_view value, std::size_t maximum) {
        require(value.size() <= maximum, "UTF-16 text exceeds field limit");
        number(value.size());
        require(value.size() <= (limit - bytes.size()) / 2, "UTF-16 text exceeds message limit");
        for (const auto unit : value) {
            bytes.push_back(static_cast<std::uint8_t>(unit));
            bytes.push_back(static_cast<std::uint8_t>(unit >> 8));
        }
    }
};
struct Reader {
    std::span<const std::uint8_t> bytes;
    std::size_t offset = 0;
    std::uint64_t number() {
        const auto value = read_u64(bytes, offset);
        offset += 8;
        return value;
    }
    std::uint32_t word() {
        const auto value = number();
        require(value <= UINT32_MAX, "Integer exceeds field width");
        return static_cast<std::uint32_t>(value);
    }
    bool boolean() {
        const auto value = number();
        require(value <= 1, "Noncanonical boolean");
        return value != 0;
    }
    float scalar() {
        const auto value = std::bit_cast<float>(word());
        require(std::isfinite(value), "Non-finite geometry");
        return value;
    }
    std::string text(std::size_t maximum) {
        const auto value = read_text(bytes, offset, maximum);
        require(value.find('\0') == std::string::npos, "Embedded null in identity");
        (void)utf16(value);
        return value;
    }
    std::u16string wide(std::size_t maximum) {
        const auto size = number();
        require(size <= maximum && size <= (bytes.size() - offset) / 2, "UTF-16 length exceeds bounds");
        std::u16string value;
        value.reserve(static_cast<std::size_t>(size));
        for (std::uint64_t i = 0; i < size; ++i) {
            value.push_back(static_cast<char16_t>(bytes[offset] | (unsigned(bytes[offset + 1]) << 8)));
            offset += 2;
        }
        return value;
    }
    void finish() const { require(offset == bytes.size(), "Trailing message data"); }
};
void bounds(const android::ViewBounds &value) {
    require(std::isfinite(value.x) && std::isfinite(value.y) && std::isfinite(value.width) &&
                std::isfinite(value.height) && std::abs(value.x) <= 32768 && std::abs(value.y) <= 32768 &&
                value.width >= 0 && value.width <= 32768 && value.height >= 0 && value.height <= 32768,
            "View rectangle exceeds the framework bounds");
}
void rectangle(Writer &out, const android::ViewBounds &value) {
    bounds(value);
    for (const auto item : {value.x, value.y, value.width, value.height})
        out.scalar(item);
}
android::ViewBounds rectangle(Reader &in) {
    const android::ViewBounds result{in.scalar(), in.scalar(), in.scalar(), in.scalar()};
    bounds(result);
    return result;
}
} // namespace
std::vector<std::uint8_t> ActivityCommand::encode() const {
    Writer out{{}, activity_command_limit};
    out.number(1);
    out.number(static_cast<std::uint64_t>(kind));
    switch (kind) {
    case ActivityCommandKind::refresh:
    case ActivityCommandKind::close:
        break;
    case ActivityCommandKind::signal:
        out.number(static_cast<std::uint64_t>(signal));
        break;
    case ActivityCommandKind::pointer:
        out.number(static_cast<std::uint64_t>(pointer.action));
        out.number(pointer.pointer);
        out.number(pointer.source);
        out.scalar(pointer.x);
        out.scalar(pointer.y);
        break;
    case ActivityCommandKind::key:
        out.number(key.up);
        out.number(key.code);
        out.number(key.meta);
        out.number(key.repeat);
        break;
    case ActivityCommandKind::place:
        require(placements.size() <= 256, "Too many placements");
        out.number(placements.size());
        for (const auto &item : placements) {
            out.number(item.view);
            rectangle(out, item.bounds);
        }
        break;
    default:
        require(false, "Unknown Activity command");
    }
    return out.bytes;
}
ActivityCommand ActivityCommand::decode(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= activity_command_limit, "Activity command exceeds limit");
    Reader in{bytes};
    require(in.number() == 1, "Unsupported Activity command version");
    const auto kind = in.number();
    require(kind <= static_cast<std::uint64_t>(ActivityCommandKind::close), "Unknown Activity command");
    ActivityCommand result;
    result.kind = static_cast<ActivityCommandKind>(kind);
    switch (result.kind) {
    case ActivityCommandKind::refresh:
    case ActivityCommandKind::close:
        break;
    case ActivityCommandKind::signal: {
        const auto signal = in.number();
        require(signal <= static_cast<std::uint64_t>(android::WindowSignal::close),
                "Invalid lifecycle signal");
        result.signal = static_cast<android::WindowSignal>(signal);
        break;
    }
    case ActivityCommandKind::pointer: {
        const auto action = in.number();
        require(action <= 3, "Invalid pointer action");
        result.pointer = {static_cast<android::PointerAction>(action), in.word(), in.word(), in.scalar(),
                          in.scalar()};
        require(result.pointer.pointer <= 65535 && std::abs(result.pointer.x) <= 65536 &&
                    std::abs(result.pointer.y) <= 65536 &&
                    (result.pointer.source == 0x1002 || result.pointer.source == 0x2002),
                "Invalid pointer input");
        break;
    }
    case ActivityCommandKind::key:
        result.key = {in.boolean(), in.word(), in.word(), in.word()};
        require(result.key.code <= 512 && result.key.repeat <= 65535 && !(result.key.meta & ~0x11003u),
                "Invalid key input");
        break;
    case ActivityCommandKind::place: {
        const auto count = in.number();
        require(count <= 256, "Too many placements");
        std::set<dex::ObjectId> ids;
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto id = in.number();
            require(id && ids.insert(id).second, "Invalid or duplicate placement ID");
            result.placements.push_back({id, rectangle(in)});
        }
        break;
    }
    }
    in.finish();
    return result;
}
void ActivityState::validate() const {
    require(views.size() <= 256 && lifecycle <= android::Lifecycle::failed, "Invalid Activity state");
    require(!content || (views.contains(content) && !views.at(content).parent), "Invalid content root");
    std::map<dex::ObjectId, unsigned> marks;
    for (const auto &[id, view] : views) {
        require(id && view.object == id && view.kind <= android::ViewKind::button &&
                    view.text.size() <= 65536 && (view.orientation == 0 || view.orientation == 1) &&
                    view.children.size() <= 256,
                "Invalid view fields");
        bounds(view.bounds);
        require(!view.parent || views.contains(view.parent), "Unknown view parent");
        require(view.kind == android::ViewKind::linear_layout || view.children.empty(),
                "Leaf view has children");
        std::set<dex::ObjectId> children;
        for (auto child : view.children)
            require(views.contains(child) && child != id && views.at(child).parent == id &&
                        children.insert(child).second,
                    "Invalid view child");
        if (view.parent) {
            const auto &siblings = views.at(view.parent).children;
            require(std::count(siblings.begin(), siblings.end(), id) == 1, "Parent omits its child");
        }
    }
    const auto visit = [&](auto &self, dex::ObjectId id) -> void {
        require(marks[id] != 1, "Cyclic view tree");
        if (marks[id] == 2)
            return;
        marks[id] = 1;
        for (auto child : views.at(id).children)
            self(self, child);
        marks[id] = 2;
    };
    for (const auto &[id, view] : views) {
        (void)view;
        visit(visit, id);
    }
}
std::vector<std::uint8_t> ActivityState::encode() const {
    validate();
    Writer out{{}, activity_state_limit};
    out.number(1);
    out.text(apk_hash, 64);
    out.text(package, 255);
    out.text(activity, 512);
    out.number(static_cast<std::uint64_t>(lifecycle));
    out.number(content);
    out.number(handled);
    for (const auto value : {framework.api_calls,
                             framework.lifecycle_callbacks,
                             framework.managed_clicks,
                             framework.denied_permissions,
                             framework.unsupported_services,
                             framework.view_revision,
                             framework.pointer_events,
                             framework.key_events,
                             managed.instructions,
                             static_cast<std::uint64_t>(managed.pinned_references),
                             jni.native_calls,
                             jni.managed_callbacks,
                             jni.on_load_calls,
                             static_cast<std::uint64_t>(jni.local_references),
                             static_cast<std::uint64_t>(jni.global_references),
                             static_cast<std::uint64_t>(jni.string_buffers),
                             cpu.compiled_blocks,
                             cpu.emitted_bytes,
                             cpu.rx_failures,
                             cpu.interpreter_fallbacks})
        out.number(value);
    for (auto value : probes)
        out.number(value);
    out.wide(trace, 65536);
    out.number(views.size());
    for (const auto &[id, view] : views) {
        out.number(id);
        out.number(view.parent);
        out.number(static_cast<std::uint64_t>(view.kind));
        out.number(std::bit_cast<std::uint32_t>(view.id));
        out.number(static_cast<std::uint64_t>(view.orientation));
        out.number(view.enabled);
        out.number(view.pressed);
        out.number(view.focused);
        rectangle(out, view.bounds);
        out.wide(view.text, 65536);
        out.number(view.children.size());
        for (auto child : view.children)
            out.number(child);
    }
    return out.bytes;
}
ActivityState ActivityState::decode(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= activity_state_limit, "Activity state exceeds limit");
    Reader in{bytes};
    require(in.number() == 1, "Unsupported Activity state version");
    ActivityState result;
    result.apk_hash = in.text(64);
    result.package = in.text(255);
    result.activity = in.text(512);
    const auto lifecycle = in.number();
    require(lifecycle <= static_cast<std::uint64_t>(android::Lifecycle::failed), "Invalid lifecycle state");
    result.lifecycle = static_cast<android::Lifecycle>(lifecycle);
    result.content = in.number();
    result.handled = in.boolean();
    auto &f = result.framework;
    f.api_calls = in.number();
    f.lifecycle_callbacks = in.number();
    f.managed_clicks = in.number();
    f.denied_permissions = in.number();
    f.unsupported_services = in.number();
    f.view_revision = in.number();
    f.pointer_events = in.number();
    f.key_events = in.number();
    result.managed.instructions = in.number();
    result.managed.pinned_references = in.number();
    auto &j = result.jni;
    j.native_calls = in.number();
    j.managed_callbacks = in.number();
    j.on_load_calls = in.number();
    j.local_references = in.number();
    j.global_references = in.number();
    j.string_buffers = in.number();
    auto &cpu = result.cpu;
    cpu.compiled_blocks = in.number();
    cpu.emitted_bytes = in.number();
    cpu.rx_failures = in.number();
    cpu.interpreter_fallbacks = in.number();
    for (auto &value : result.probes)
        value = in.word();
    result.trace = in.wide(65536);
    const auto count = in.number();
    require(count <= 256, "Too many views");
    for (std::uint64_t i = 0; i < count; ++i) {
        android::ViewState view;
        view.object = in.number();
        view.parent = in.number();
        const auto kind = in.number();
        require(kind <= static_cast<std::uint64_t>(android::ViewKind::button), "Unknown view type");
        view.kind = static_cast<android::ViewKind>(kind);
        view.id = std::bit_cast<std::int32_t>(in.word());
        const auto orientation = in.number();
        require(orientation <= 1, "Invalid layout orientation");
        view.orientation = static_cast<std::int32_t>(orientation);
        view.enabled = in.boolean();
        view.pressed = in.boolean();
        view.focused = in.boolean();
        view.bounds = rectangle(in);
        view.text = in.wide(65536);
        const auto children = in.number();
        require(children <= 256, "Too many children");
        for (std::uint64_t c = 0; c < children; ++c)
            view.children.push_back(in.number());
        const auto id = view.object;
        require(result.views.emplace(id, std::move(view)).second, "Duplicate view identity");
    }
    in.finish();
    result.validate();
    return result;
}
Frame activity_fragment(std::span<const std::uint8_t> bytes, std::size_t offset, Operation operation,
                        std::uint64_t sequence, std::uint64_t session) {
    require(!bytes.empty() && offset < bytes.size(), "Invalid fragment offset");
    Frame result{{operation, sequence, session, 0, Status::ok}, {}};
    append_u64(result.payload, bytes.size());
    append_u64(result.payload, offset);
    const auto part = bytes.subspan(offset, std::min(bytes.size() - offset, maximum_payload - 16));
    result.payload.insert(result.payload.end(), part.begin(), part.end());
    result.header.payload_size = static_cast<std::uint32_t>(result.payload.size());
    return result;
}
void validate_activity_read_unavailable(const Frame &frame, std::uint64_t sequence, std::uint64_t session,
                                        bool reading, bool response_started) {
    require(reading && !response_started && sequence && session &&
                frame.header.operation == Operation::activity_read_unavailable &&
                frame.header.sequence == sequence && frame.header.session == session &&
                frame.header.status == Status::ok && frame.header.payload_size == 0 && frame.payload.empty(),
            "Invalid read-unavailable response");
}
ActivityReassembly::ActivityReassembly(Operation operation, std::uint64_t sequence, std::uint64_t session,
                                       std::size_t limit)
    : operation_(operation), sequence_(sequence), session_(session), limit_(limit) {
    require(session && limit && limit <= activity_state_limit, "Invalid fragment receiver");
}
void ActivityReassembly::accept(const Frame &frame) {
    require(!complete() && frame.header.operation == operation_ && frame.header.sequence == sequence_ &&
                frame.header.session == session_ && frame.header.status == Status::ok &&
                frame.header.payload_size == frame.payload.size() && frame.payload.size() > 16 &&
                frame.payload.size() <= maximum_payload,
            "Invalid fragment envelope");
    const auto size = read_u64(frame.payload, 0), offset = read_u64(frame.payload, 8);
    require(size && size <= limit_ && offset == bytes_.size() && (!total_ || total_ == size) &&
                offset < size && frame.payload.size() - 16 <= size - offset,
            "Invalid fragment range");
    if (!total_) {
        total_ = static_cast<std::size_t>(size);
        bytes_.reserve(total_);
    }
    bytes_.insert(bytes_.end(), frame.payload.begin() + 16, frame.payload.end());
}
bool ActivityReassembly::complete() const noexcept { return total_ && bytes_.size() == total_; }
std::vector<std::uint8_t> ActivityReassembly::take() {
    require(complete(), "Incomplete fragmented message");
    return std::move(bytes_);
}
} // namespace aether::security
