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
void drag_fields(const ActivityCommand &command) {
    const auto &input = command.drag;
    const auto action = static_cast<std::uint32_t>(input.action);
    require(input.id && action >= 1 && action <= 4 && host::valid_document_mime(input.mime_type) &&
                std::isfinite(input.x) && std::isfinite(input.y) &&
                std::abs(input.x) <= 32768 && std::abs(input.y) <= 32768,
            "Invalid captured drag identity, phase, MIME or coordinates");
    require(!input.text, "Resolved drag text must never enter command IPC");
    require(input.kind == host::DropPayloadKind::file || input.kind == host::DropPayloadKind::plain_text,
            "Unknown drag payload kind");
    const bool dropping = input.action == android::DragAction::drop;
    if (input.kind == host::DropPayloadKind::file) {
        require(input.document.has_value() == dropping && !input.text_info,
                "Only a reviewed file DROP carries document metadata");
    } else {
        require(input.mime_type == "text/plain" && !input.document && input.text_info.has_value() == dropping &&
                    (!input.text_info || host::valid_drop_text_info(*input.text_info)),
                "Invalid reviewed plain-text drag descriptor");
    }
    require(input.action == android::DragAction::started || !command.expected_view_revision,
            "Only STARTED carries a geometry baseline");
    if (input.document)
        require(host::valid_document_info(*input.document) && input.document->mime_type == input.mime_type,
                "Invalid reviewed drag document metadata");
}
void ime_fields(const ActivityCommand &value) {
    require(value.view && value.ime_token &&
                static_cast<std::uint64_t>(value.ime_kind) <= static_cast<std::uint64_t>(android::ImeEditKind::conversion),
            "Invalid IME view, token or phase");
    require(!value.ime_conversion || value.ime_kind == android::ImeEditKind::update ||
                value.ime_kind == android::ImeEditKind::conversion,
            "Conversion metadata is only valid on composition updates/metadata packets");
    if (value.ime_conversion) {
        const auto &target = *value.ime_conversion;
        const bool absent = target.start == -1 && target.end == -1;
        require((!target.available && absent) || (target.available &&
                    (absent || (target.start >= 0 && target.end > target.start &&
                     static_cast<std::size_t>(target.end) <= value.replacement_text.size()))),
                "Invalid native conversion target metadata");
        const bool no_prefix = target.unchanged_prefix == -1 && target.previous_composition_sha256.empty();
        const bool digest_valid = target.previous_composition_sha256.size() == 64 &&
            std::all_of(target.previous_composition_sha256.begin(), target.previous_composition_sha256.end(),
                [](char character) { return (character >= '0' && character <= '9') ||
                    (character >= 'a' && character <= 'f'); });
        const bool prefix_in_range = target.unchanged_prefix > 0 &&
            static_cast<std::size_t>(target.unchanged_prefix) <= value.replacement_text.size();
        bool prefix_boundary = false;
        if (prefix_in_range) {
            const auto prefix = static_cast<std::size_t>(target.unchanged_prefix);
            prefix_boundary = prefix == value.replacement_text.size() ||
                !(value.replacement_text[prefix - 1] >= 0xd800 && value.replacement_text[prefix - 1] <= 0xdbff &&
                  value.replacement_text[prefix] >= 0xdc00 && value.replacement_text[prefix] <= 0xdfff);
        }
        require(no_prefix || (value.ime_kind == android::ImeEditKind::update && target.available &&
                    prefix_in_range && prefix_boundary && digest_valid),
                "Invalid native unchanged-prefix evidence");
    }
    if (value.ime_kind == android::ImeEditKind::begin) {
        require(value.expected_text.size() <= android::editable_text_limit && value.replacement_text.empty() &&
                    value.ime_cursor == 0, "Invalid IME begin fields");
        return;
    }
    require(value.expected_text.empty() && !value.expected_view_revision,
            "Only IME begin carries an expected text/revision binding");
    switch (value.ime_kind) {
    case android::ImeEditKind::update:
    case android::ImeEditKind::commit:
        require(value.replacement_text.size() <= android::editable_text_limit && value.ime_cursor >= 0 &&
                    static_cast<std::size_t>(value.ime_cursor) <= value.replacement_text.size() &&
                    (value.ime_kind != android::ImeEditKind::commit ||
                     static_cast<std::size_t>(value.ime_cursor) == value.replacement_text.size()),
                "Invalid IME update or commit text/cursor");
        break;
    case android::ImeEditKind::cursor:
        require(value.replacement_text.empty() && value.ime_cursor >= 0 &&
                    static_cast<std::size_t>(value.ime_cursor) <= android::editable_text_limit,
                "Invalid IME composition cursor");
        break;
    case android::ImeEditKind::conversion:
        require(value.ime_conversion.has_value() && value.ime_cursor == 0 &&
                    value.replacement_text.size() <= android::editable_text_limit,
                "Invalid metadata-only IME packet");
        break;
    case android::ImeEditKind::finish:
    case android::ImeEditKind::cancel:
        require(value.replacement_text.empty() && value.ime_cursor == 0,
                "IME finish/cancel cannot carry text or a cursor");
        break;
    case android::ImeEditKind::begin:
        break;
    }
}
void conversion_target(Writer &out, const android::ImeConversionTarget &target) {
    out.number(target.available);
    out.number(std::bit_cast<std::uint32_t>(target.start));
    out.number(std::bit_cast<std::uint32_t>(target.end));
    out.number(std::bit_cast<std::uint32_t>(target.unchanged_prefix));
    out.text(target.previous_composition_sha256, 64);
}
android::ImeConversionTarget conversion_target(Reader &in) {
    android::ImeConversionTarget result;
    result.available = in.boolean();
    result.start = std::bit_cast<std::int32_t>(in.word());
    result.end = std::bit_cast<std::int32_t>(in.word());
    result.unchanged_prefix = std::bit_cast<std::int32_t>(in.word());
    result.previous_composition_sha256 = in.text(64);
    return result;
}
void validate_text_mutation_chain(const android::ViewState &view) {
    require(view.text_mutations.size() <= android::text_mutation_history_limit &&
                view.text_mutation_base_revision <= view.text_event_revision,
            "Invalid text mutation coverage");
    auto mutation_revision = view.text_mutation_base_revision;
    std::int32_t mutation_length = -1;
    constexpr auto mutation_limit = static_cast<std::int32_t>(android::editable_text_limit);
    for (const auto &mutation : view.text_mutations) {
        require(mutation_revision != UINT64_MAX && mutation.revision == mutation_revision + 1 &&
                    mutation.before_length >= 0 && mutation.before_length <= mutation_limit &&
                    mutation.start >= 0 && mutation.start <= mutation.before_length &&
                    mutation.removed >= 0 && mutation.removed <= mutation.before_length - mutation.start &&
                    mutation.inserted >= 0 && mutation.inserted <= mutation_limit &&
                    (mutation.removed || mutation.inserted) &&
                    mutation.before_length - mutation.removed <= mutation_limit - mutation.inserted &&
                    (mutation_length < 0 || mutation_length == mutation.before_length),
                "Invalid text mutation chain");
        mutation_length = mutation.before_length - mutation.removed + mutation.inserted;
        mutation_revision = mutation.revision;
    }
    require(mutation_revision == view.text_event_revision &&
                (mutation_length < 0 || static_cast<std::size_t>(mutation_length) == view.text.size()) &&
                (view.kind == android::ViewKind::edit_text ||
                 (!view.text_mutation_base_revision && view.text_mutations.empty())) &&
                (view.text_mutations.empty() || view.text_buffer_revision),
            "Incomplete text mutation chain or invalid owner");
}
void validate_editor_document(const android::ViewState &document) {
    require(document.object && document.kind == android::ViewKind::edit_text &&
                document.text_buffer_revision && document.text.size() <= android::editable_text_limit &&
                document.text_edit_dropped_revision <= document.text_edit_event_revision,
            "Invalid TextEdit observation document");
    for (const auto position : {document.selection_start, document.selection_end})
        require(position >= -1 && (position < 0 || static_cast<std::size_t>(position) <= document.text.size()),
                "Invalid TextEdit observation selection");
    validate_text_mutation_chain(document);
    const bool composing_none = document.composing_start == -1 && document.composing_end == -1;
    const bool converting_none = document.conversion_start == -1 && document.conversion_end == -1;
    require(composing_none || (document.composing_start >= 0 && document.composing_end > document.composing_start &&
                static_cast<std::size_t>(document.composing_end) <= document.text.size()),
            "Invalid TextEdit observation composition");
    require(converting_none || (!composing_none && document.conversion_start >= document.composing_start &&
                document.conversion_end > document.conversion_start && document.conversion_end <= document.composing_end),
            "Invalid TextEdit observation conversion target");
    require(document.conversion_available || converting_none, "Unavailable TextEdit observation has a target");
}
void validate_text_edit_observation(const android::TextEditObservation &observation) {
    const auto &document = observation.document;
    const auto &event = observation.event;
    validate_editor_document(document);
    require(event.revision && event.revision == document.text_edit_event_revision &&
                event.buffer_revision == document.text_buffer_revision &&
                (event.kind == android::TextEditEventKind::composition ||
                 event.kind == android::TextEditEventKind::composition_finalized ||
                 event.kind == android::TextEditEventKind::conversion_target_changed) &&
                event.text.size() <= android::editable_text_limit &&
                (event.kind != android::TextEditEventKind::conversion_target_changed || event.text.empty()),
            "Invalid current known TextEdit observation event");
}
void validate_soft_input_request(const android::SoftInputRequest &request) {
    require(request.revision && request.window_generation &&
                (request.show ? request.view != 0 : !request.view && !request.implicit),
            "Invalid soft input request identity or flags");
}
void write_soft_input_request(Writer &out, const android::SoftInputRequest &request) {
    validate_soft_input_request(request);
    out.number(request.revision); out.number(request.window_generation); out.number(request.view);
    out.number(request.show); out.number(request.implicit);
}
android::SoftInputRequest read_soft_input_request(Reader &in) {
    android::SoftInputRequest result;
    result.revision = in.number(); result.window_generation = in.number(); result.view = in.number();
    result.show = in.boolean(); result.implicit = in.boolean();
    validate_soft_input_request(result);
    return result;
}
void write_editor_content(Writer &out, const android::ViewState &document) {
    out.number(document.text_buffer_revision);
    out.number(document.text_event_revision);
    out.number(document.selection_event_revision);
    out.number(std::bit_cast<std::uint32_t>(document.selection_start));
    out.number(std::bit_cast<std::uint32_t>(document.selection_end));
    out.number(std::bit_cast<std::uint32_t>(document.composing_start));
    out.number(std::bit_cast<std::uint32_t>(document.composing_end));
    out.number(document.composition_event_revision);
    out.number(document.ime_token);
    out.number(document.conversion_available);
    out.number(std::bit_cast<std::uint32_t>(document.conversion_start));
    out.number(std::bit_cast<std::uint32_t>(document.conversion_end));
    out.number(document.text_mutation_base_revision);
    out.number(document.text_mutations.size());
    for (const auto &mutation : document.text_mutations) {
        out.number(mutation.revision);
        out.number(static_cast<std::uint32_t>(mutation.start));
        out.number(static_cast<std::uint32_t>(mutation.removed));
        out.number(static_cast<std::uint32_t>(mutation.inserted));
        out.number(static_cast<std::uint32_t>(mutation.before_length));
    }
    out.number(document.text_edit_event_revision);
    out.number(document.text_edit_dropped_revision);
    out.wide(document.text, android::editable_text_limit);
}
void read_editor_content(Reader &in, android::ViewState &document) {
    document.text_buffer_revision = in.number();
    document.text_event_revision = in.number();
    document.selection_event_revision = in.number();
    document.selection_start = std::bit_cast<std::int32_t>(in.word());
    document.selection_end = std::bit_cast<std::int32_t>(in.word());
    document.composing_start = std::bit_cast<std::int32_t>(in.word());
    document.composing_end = std::bit_cast<std::int32_t>(in.word());
    document.composition_event_revision = in.number();
    document.ime_token = in.number();
    document.conversion_available = in.boolean();
    document.conversion_start = std::bit_cast<std::int32_t>(in.word());
    document.conversion_end = std::bit_cast<std::int32_t>(in.word());
    document.text_mutation_base_revision = in.number();
    const auto count = in.number();
    require(count <= android::text_mutation_history_limit, "Too many TextEdit observation mutations");
    document.text_mutations.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        android::TextMutation mutation;
        mutation.revision = in.number();
        mutation.start = std::bit_cast<std::int32_t>(in.word());
        mutation.removed = std::bit_cast<std::int32_t>(in.word());
        mutation.inserted = std::bit_cast<std::int32_t>(in.word());
        mutation.before_length = std::bit_cast<std::int32_t>(in.word());
        document.text_mutations.push_back(mutation);
    }
    document.text_edit_event_revision = in.number();
    document.text_edit_dropped_revision = in.number();
    document.text = in.wide(android::editable_text_limit);
}
void validate_soft_input_observation(const android::SoftInputObservation &observation) {
    validate_soft_input_request(observation.request);
    require(observation.lifecycle <= android::Lifecycle::failed, "Invalid soft input observation lifecycle");
    if (observation.request.show) {
        validate_editor_document(observation.document);
        require(observation.document.object == observation.request.view && observation.document.ime_token,
                "Invalid soft input observation editor or connection");
    } else {
        require(!observation.document.object && !observation.document.ime_token &&
                    observation.document.text.empty() && !observation.rooted,
                "Hide soft input observation contains an editor");
    }
}
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
std::vector<std::uint8_t> encode_activity_terminal_activations(const ActivityTerminalActivations &batch) {
    require(batch.reason == ActivityTerminalReason::guest_exit || batch.reason == ActivityTerminalReason::failure,
            "Invalid activation terminal reason");
    require(batch.records.size() <= android::view_activation_limit,
            "Invalid terminal activation count");
    Writer out{{}, activity_terminal_activations_limit - 8};
    out.number(1);
    out.number(static_cast<std::uint64_t>(batch.reason));
    out.number(batch.through_revision);
    out.number(batch.records.size());
    std::uint64_t previous = 0;
    for (const auto &record : batch.records) {
        require(record.revision && record.view && record.window_generation &&
                    (!previous || (previous != UINT64_MAX && record.revision == previous + 1)),
                "Invalid consecutive terminal activation record");
        out.number(record.revision);
        out.number(record.view);
        out.number(record.window_generation);
        previous = record.revision;
    }
    require(batch.records.empty() || previous == batch.through_revision, "Terminal activation coverage mismatch");
    return out.bytes;
}
ActivityTerminalActivations decode_activity_terminal_activations(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= activity_terminal_activations_limit - 8, "Terminal activation batch exceeds limit");
    Reader in{bytes};
    require(in.number() == 1, "Unsupported terminal activation version");
    ActivityTerminalActivations result;
    const auto reason = in.number();
    require(reason == static_cast<std::uint64_t>(ActivityTerminalReason::guest_exit) ||
                reason == static_cast<std::uint64_t>(ActivityTerminalReason::failure),
            "Invalid activation terminal reason");
    result.reason = static_cast<ActivityTerminalReason>(reason);
    result.through_revision = in.number();
    const auto count = in.number();
    require(count <= android::view_activation_limit, "Invalid terminal activation count");
    result.records.reserve(static_cast<std::size_t>(count));
    std::uint64_t previous = 0;
    for (std::uint64_t index = 0; index < count; ++index) {
        android::ViewActivation record{in.number(), in.number(), in.number()};
        require(record.revision && record.view && record.window_generation &&
                    (!previous || (previous != UINT64_MAX && record.revision == previous + 1)),
                "Invalid consecutive terminal activation record");
        previous = record.revision;
        result.records.push_back(record);
    }
    require(result.records.empty() || previous == result.through_revision, "Terminal activation coverage mismatch");
    in.finish();
    return result;
}
std::vector<std::uint8_t> encode_activity_text_edit_observation(const android::TextEditObservation &observation) {
    static_assert(activity_text_edit_observation_limit <= activity_state_limit);
    validate_text_edit_observation(observation);
    const auto &document = observation.document;
    const auto &event = observation.event;
    Writer out{{}, activity_text_edit_observation_limit};
    out.number(1); // Standalone record schema, independent of final Activity state and commands.
    out.number(document.object);
    out.number(static_cast<std::uint64_t>(document.kind));
    out.number(observation.rooted);
    out.number(observation.view_revision);
    write_editor_content(out, document);
    out.number(event.revision);
    out.number(event.buffer_revision);
    out.number(static_cast<std::uint64_t>(event.kind));
    out.wide(event.text, android::editable_text_limit);
    return out.bytes;
}
android::TextEditObservation decode_activity_text_edit_observation(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= activity_text_edit_observation_limit, "TextEdit observation exceeds limit");
    Reader in{bytes};
    require(in.number() == 1, "Unsupported TextEdit observation record version");
    android::TextEditObservation result;
    auto &document = result.document;
    auto &event = result.event;
    document.object = in.number();
    require(in.number() == static_cast<std::uint64_t>(android::ViewKind::edit_text),
            "TextEdit observation is not an editor");
    document.kind = android::ViewKind::edit_text;
    result.rooted = in.boolean();
    result.view_revision = in.number();
    read_editor_content(in, document);
    event.revision = in.number();
    event.buffer_revision = in.number();
    const auto kind = in.number();
    require(kind <= static_cast<std::uint64_t>(android::TextEditEventKind::conversion_target_changed),
            "Unknown TextEdit observation event kind");
    event.kind = static_cast<android::TextEditEventKind>(kind);
    event.text = in.wide(android::editable_text_limit);
    in.finish();
    validate_text_edit_observation(result);
    return result;
}
std::vector<std::uint8_t> encode_activity_soft_input_observation(const android::SoftInputObservation &observation) {
    validate_soft_input_observation(observation);
    Writer out{{}, activity_soft_input_observation_limit};
    out.number(2);
    write_soft_input_request(out, observation.request);
    out.number(observation.view_revision);
    out.number(static_cast<std::uint64_t>(observation.lifecycle)); out.number(observation.window_focused);
    if (observation.request.show) {
        out.number(observation.document.object); out.number(static_cast<std::uint64_t>(observation.document.kind));
        out.number(observation.rooted);
        out.number(observation.document.enabled); out.number(observation.document.focused);
        write_editor_content(out, observation.document);
    }
    return out.bytes;
}
android::SoftInputObservation decode_activity_soft_input_observation(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= activity_soft_input_observation_limit, "Soft input observation exceeds limit");
    Reader in{bytes};
    require(in.number() == 2, "Unsupported soft input observation record version");
    android::SoftInputObservation result;
    result.request = read_soft_input_request(in);
    result.view_revision = in.number();
    const auto lifecycle = in.number();
    require(lifecycle <= static_cast<std::uint64_t>(android::Lifecycle::failed), "Invalid soft input lifecycle");
    result.lifecycle = static_cast<android::Lifecycle>(lifecycle); result.window_focused = in.boolean();
    if (result.request.show) {
        result.document.object = in.number();
        require(in.number() == static_cast<std::uint64_t>(android::ViewKind::edit_text), "Soft input target is not an editor");
        result.document.kind = android::ViewKind::edit_text;
        result.rooted = in.boolean();
        result.document.enabled = in.boolean(); result.document.focused = in.boolean();
        read_editor_content(in, result.document);
    }
    in.finish();
    validate_soft_input_observation(result);
    return result;
}
std::vector<std::uint8_t> ActivityCommand::encode() const {
    Writer out{{}, activity_command_limit};
    out.number(17);
    out.number(static_cast<std::uint64_t>(kind));
    switch (kind) {
    case ActivityCommandKind::refresh:
    case ActivityCommandKind::close:
        break;
    case ActivityCommandKind::prepare_accessibility_metadata:
        require(view != 0, "Metadata preparation requires an expected content root");
        out.number(view);
        out.number(expected_view_revision);
        break;
    case ActivityCommandKind::collection_selection:
        require(view && collection_owner && view != collection_owner && expected_metadata_revision &&
                    static_cast<std::uint64_t>(collection_selection_operation) <=
                        static_cast<std::uint64_t>(android::CollectionSelectionOperation::remove),
                "Invalid collection selection identity or operation");
        out.number(view);
        out.number(collection_owner);
        out.number(expected_metadata_revision);
        out.number(expected_view_revision);
        out.number(static_cast<std::uint64_t>(collection_selection_operation));
        break;
    case ActivityCommandKind::invoke:
    case ActivityCommandKind::focus:
    case ActivityCommandKind::toggle:
        require(view != 0, "Accessibility action requires a view identity");
        out.number(view);
        break;
    case ActivityCommandKind::scroll:
        require(view && (scroll_amount == -2 || scroll_amount == -1 || scroll_amount == 1 || scroll_amount == 2),
                "Invalid semantic scroll amount");
        out.number(view);
        out.number(std::bit_cast<std::uint32_t>(scroll_amount));
        break;
    case ActivityCommandKind::set_scroll_percent:
        require(view && std::isfinite(scroll_percent) && scroll_percent >= 0 && scroll_percent <= 100,
                "Invalid semantic scroll percent");
        out.number(view);
        out.number(std::bit_cast<std::uint64_t>(scroll_percent));
        break;
    case ActivityCommandKind::replace_text:
        require(view != 0, "Text replacement requires a View identity");
        out.number(view);
        out.wide(replacement_text, android::editable_text_limit);
        break;
    case ActivityCommandKind::set_selection:
        require(view && expected_buffer_revision &&
                    static_cast<std::uint64_t>(selection_operation) <= static_cast<std::uint64_t>(android::SelectionOperation::remove) &&
                    selection_start >= 0 && selection_end >= 0 &&
                    static_cast<std::size_t>(selection_start) <= expected_text.size() &&
                    static_cast<std::size_t>(selection_end) <= expected_text.size() &&
                    (selection_operation == android::SelectionOperation::replace || selection_start <= selection_end),
                "Invalid text selection");
        out.number(view);
        out.number(expected_buffer_revision);
        out.number(expected_text_revision);
        out.number(static_cast<std::uint64_t>(selection_operation));
        out.number(static_cast<std::uint32_t>(selection_start));
        out.number(static_cast<std::uint32_t>(selection_end));
        out.wide(expected_text, android::editable_text_limit);
        break;
    case ActivityCommandKind::reveal_text_range:
        require(view && std::isfinite(range_top) && std::isfinite(range_bottom) &&
                    range_top >= 0 && range_bottom >= range_top && range_bottom <= 32768,
                "Invalid text range reveal geometry");
        out.number(view);
        out.number(expected_view_revision);
        out.scalar(range_top);
        out.scalar(range_bottom);
        out.number(align_top);
        out.wide(expected_text, android::editable_text_limit);
        break;
    case ActivityCommandKind::claim_soft_input:
        require(soft_input_revision && (view || (!ime_token && !expected_view_revision && expected_text.empty())),
                "Invalid soft input claim identity or hide fields");
        out.number(view); out.number(soft_input_revision); out.number(ime_token);
        out.number(expected_view_revision); out.wide(expected_text, android::editable_text_limit);
        break;
    case ActivityCommandKind::drag:
        drag_fields(*this);
        out.number(static_cast<std::uint32_t>(drag.action)); out.number(drag.id);
        out.number(static_cast<std::uint32_t>(drag.kind));
        out.scalar(drag.x); out.scalar(drag.y); out.text(drag.mime_type, 255);
        out.number(expected_view_revision);
        if (drag.document) {
            out.text(drag.document->uri, 128); out.text(drag.document->display_name, 255);
            out.number(drag.document->size);
        }
        if (drag.text_info) {
            out.number(drag.text_info->units); out.text(drag.text_info->utf16le_sha256, 64);
        }
        break;
    case ActivityCommandKind::ime_edit:
        ime_fields(*this);
        out.number(static_cast<std::uint64_t>(ime_kind));
        out.number(view);
        out.number(ime_token);
        if (ime_kind == android::ImeEditKind::begin) {
            out.number(expected_view_revision);
            out.wide(expected_text, android::editable_text_limit);
        } else if (ime_kind == android::ImeEditKind::update || ime_kind == android::ImeEditKind::commit) {
            out.number(static_cast<std::uint32_t>(ime_cursor));
            out.wide(replacement_text, android::editable_text_limit);
            if (ime_kind == android::ImeEditKind::update) {
                out.number(ime_conversion.has_value());
                if (ime_conversion) conversion_target(out, *ime_conversion);
            }
        } else if (ime_kind == android::ImeEditKind::conversion) {
            out.wide(replacement_text, android::editable_text_limit);
            conversion_target(out, *ime_conversion);
        } else if (ime_kind == android::ImeEditKind::cursor) {
            out.number(static_cast<std::uint32_t>(ime_cursor));
        }
        break;
    case ActivityCommandKind::configure:
        require(configuration.valid(), "Invalid display configuration");
        out.number(configuration.screen_width_dp);
        out.number(configuration.screen_height_dp);
        out.number(configuration.smallest_screen_width_dp);
        out.number(configuration.density_dpi);
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
        require(android::valid_key_input(key), "Invalid key input");
        out.number(key.up);
        out.number(key.code);
        out.number(key.meta);
        out.number(key.repeat);
        out.number(static_cast<std::uint32_t>(key.character_status));
        out.number(key.unicode);
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
    require(in.number() == 17, "Unsupported Activity command version");
    const auto kind = in.number();
    require(kind <= static_cast<std::uint64_t>(ActivityCommandKind::collection_selection), "Unknown Activity command");
    ActivityCommand result;
    result.kind = static_cast<ActivityCommandKind>(kind);
    switch (result.kind) {
    case ActivityCommandKind::refresh:
    case ActivityCommandKind::close:
        break;
    case ActivityCommandKind::prepare_accessibility_metadata:
        result.view = in.number();
        result.expected_view_revision = in.number();
        require(result.view != 0, "Metadata preparation requires an expected content root");
        break;
    case ActivityCommandKind::collection_selection: {
        result.view = in.number();
        result.collection_owner = in.number();
        result.expected_metadata_revision = in.number();
        result.expected_view_revision = in.number();
        const auto operation = in.number();
        require(result.view && result.collection_owner && result.view != result.collection_owner &&
                    result.expected_metadata_revision && operation <=
                        static_cast<std::uint64_t>(android::CollectionSelectionOperation::remove),
                "Invalid collection selection identity or operation");
        result.collection_selection_operation = static_cast<android::CollectionSelectionOperation>(operation);
        break;
    }
    case ActivityCommandKind::invoke:
    case ActivityCommandKind::focus:
    case ActivityCommandKind::toggle:
        result.view = in.number();
        require(result.view != 0, "Accessibility action requires a view identity");
        break;
    case ActivityCommandKind::scroll:
        result.view = in.number();
        result.scroll_amount = std::bit_cast<std::int32_t>(in.word());
        require(result.view && (result.scroll_amount == -2 || result.scroll_amount == -1 ||
                    result.scroll_amount == 1 || result.scroll_amount == 2), "Invalid semantic scroll amount");
        break;
    case ActivityCommandKind::set_scroll_percent:
        result.view = in.number();
        result.scroll_percent = std::bit_cast<double>(in.number());
        require(result.view && std::isfinite(result.scroll_percent) && result.scroll_percent >= 0 &&
                    result.scroll_percent <= 100, "Invalid semantic scroll percent");
        break;
    case ActivityCommandKind::replace_text:
        result.view = in.number();
        require(result.view != 0, "Text replacement requires a View identity");
        result.replacement_text = in.wide(android::editable_text_limit);
        break;
    case ActivityCommandKind::set_selection:
        result.view = in.number();
        result.expected_buffer_revision = in.number();
        result.expected_text_revision = in.number();
        {
            const auto operation = in.number();
            require(operation <= static_cast<std::uint64_t>(android::SelectionOperation::remove),
                    "Invalid text selection operation");
            result.selection_operation = static_cast<android::SelectionOperation>(operation);
        }
        result.selection_start = std::bit_cast<std::int32_t>(in.word());
        result.selection_end = std::bit_cast<std::int32_t>(in.word());
        result.expected_text = in.wide(android::editable_text_limit);
        require(result.view && result.expected_buffer_revision && result.selection_start >= 0 && result.selection_end >= 0 &&
                    static_cast<std::size_t>(result.selection_start) <= result.expected_text.size() &&
                    static_cast<std::size_t>(result.selection_end) <= result.expected_text.size() &&
                    (result.selection_operation == android::SelectionOperation::replace || result.selection_start <= result.selection_end),
                "Invalid text selection");
        break;
    case ActivityCommandKind::reveal_text_range:
        result.view = in.number();
        result.expected_view_revision = in.number();
        result.range_top = in.scalar();
        result.range_bottom = in.scalar();
        result.align_top = in.boolean();
        result.expected_text = in.wide(android::editable_text_limit);
        require(result.view && result.range_top >= 0 && result.range_bottom >= result.range_top &&
                    result.range_bottom <= 32768, "Invalid text range reveal geometry");
        break;
    case ActivityCommandKind::claim_soft_input:
        result.view = in.number(); result.soft_input_revision = in.number(); result.ime_token = in.number();
        result.expected_view_revision = in.number(); result.expected_text = in.wide(android::editable_text_limit);
        require(result.soft_input_revision && (result.view ||
                    (!result.ime_token && !result.expected_view_revision && result.expected_text.empty())),
                "Invalid soft input claim identity or hide fields");
        break;
    case ActivityCommandKind::drag: {
        const auto phase = in.number();
        require(phase >= 1 && phase <= 4, "Invalid captured drag phase");
        result.drag.action = static_cast<android::DragAction>(phase); result.drag.id = in.number();
        const auto payload_kind = in.number();
        require(payload_kind <= 1, "Unknown drag payload kind");
        result.drag.kind = static_cast<host::DropPayloadKind>(payload_kind);
        result.drag.x = in.scalar(); result.drag.y = in.scalar(); result.drag.mime_type = in.text(255);
        result.expected_view_revision = in.number();
        if (result.drag.action == android::DragAction::drop && result.drag.kind == host::DropPayloadKind::file) {
            host::DocumentInfo info;
            info.uri = in.text(128); info.display_name = in.text(255); info.size = in.number();
            info.mime_type = result.drag.mime_type; result.drag.document = std::move(info);
        }
        if (result.drag.action == android::DragAction::drop && result.drag.kind == host::DropPayloadKind::plain_text) {
            host::DropTextInfo info;
            info.units = in.number(); info.utf16le_sha256 = in.text(64); result.drag.text_info = std::move(info);
        }
        drag_fields(result);
        break;
    }
    case ActivityCommandKind::ime_edit: {
        const auto phase = in.number();
        require(phase <= static_cast<std::uint64_t>(android::ImeEditKind::conversion), "Invalid IME phase");
        result.ime_kind = static_cast<android::ImeEditKind>(phase);
        result.view = in.number();
        result.ime_token = in.number();
        if (result.ime_kind == android::ImeEditKind::begin) {
            result.expected_view_revision = in.number();
            result.expected_text = in.wide(android::editable_text_limit);
        } else if (result.ime_kind == android::ImeEditKind::update || result.ime_kind == android::ImeEditKind::commit) {
            result.ime_cursor = std::bit_cast<std::int32_t>(in.word());
            result.replacement_text = in.wide(android::editable_text_limit);
            if (result.ime_kind == android::ImeEditKind::update && in.boolean())
                result.ime_conversion = conversion_target(in);
        } else if (result.ime_kind == android::ImeEditKind::conversion) {
            result.replacement_text = in.wide(android::editable_text_limit);
            result.ime_conversion = conversion_target(in);
        } else if (result.ime_kind == android::ImeEditKind::cursor) {
            result.ime_cursor = std::bit_cast<std::int32_t>(in.word());
        }
        ime_fields(result);
        break;
    }
    case ActivityCommandKind::configure:
        result.configuration = {in.word(), in.word(), in.word(), in.word()};
        require(result.configuration.valid(), "Invalid display configuration");
        break;
    case ActivityCommandKind::signal: {
        const auto signal = in.number();
        require(signal <= static_cast<std::uint64_t>(android::WindowSignal::resume),
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
        result.key.character_status = static_cast<android::KeyCharacterStatus>(in.word());
        result.key.unicode = in.word();
        require(android::valid_key_input(result.key), "Invalid key input");
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
    require(static_cast<std::uint64_t>(accessibility_metadata_status) <=
                static_cast<std::uint64_t>(android::AccessibilityMetadataStatus::mutated),
            "Unknown accessibility metadata status");
    require((accessibility_metadata_status == android::AccessibilityMetadataStatus::none) ==
                (accessibility_metadata_attempt == 0),
            "Invalid accessibility metadata attempt status");
    require(view_activations.size() <= android::view_activation_limit, "Too many View activation records");
    std::uint64_t previous_activation = 0;
    for (const auto &activation : view_activations) {
        require(activation.revision && activation.view && activation.window_generation &&
                    activation.revision > previous_activation &&
                    activation.revision <= view_activation_revision,
                "Invalid View activation record");
        previous_activation = activation.revision;
    }
    require(configuration.valid(), "Invalid Activity display configuration");
    require(requested_orientation == -1 || requested_orientation == 0 || requested_orientation == 1,
            "Unsupported Activity orientation request");
    require(soft_input_requests.size() <= 32, "Too many soft input requests");
    std::uint64_t soft_input_previous = 0;
    for (const auto &request : soft_input_requests) {
        validate_soft_input_request(request);
        require(request.revision > soft_input_previous, "Soft input request order regressed");
        soft_input_previous = request.revision;
    }
    require(views.size() <= 256 && lifecycle <= android::Lifecycle::failed, "Invalid Activity state");
    require(!content || (views.contains(content) && !views.at(content).parent), "Invalid content root");
    std::map<dex::ObjectId, unsigned> marks;
    std::size_t description_units = 0;
    std::set<std::uint64_t> text_edit_revisions;
    for (const auto &[id, view] : views) {
        require(id && view.object == id && view.kind <= android::ViewKind::edit_text &&
                    view.text.size() <= 65536 && (view.orientation == 0 || view.orientation == 1) &&
                    view.children.size() <= 256,
                "Invalid view fields");
        require(view.selection_start >= -1 && view.selection_end >= -1 &&
                    (view.kind == android::ViewKind::edit_text
                        ? view.text.size() <= android::editable_text_limit &&
                          (view.selection_start < 0 || static_cast<std::size_t>(view.selection_start) <= view.text.size()) &&
                          (view.selection_end < 0 || static_cast<std::size_t>(view.selection_end) <= view.text.size())
                        : view.selection_start == -1 && view.selection_end == -1),
                "Invalid editable text or selection");
        require(view.kind == android::ViewKind::edit_text ||
                    (!view.text_event_revision && !view.selection_event_revision),
                "Editable event revisions on a non-editable view");
        validate_text_mutation_chain(view);
        const bool composing_none = view.composing_start == -1 && view.composing_end == -1;
        const bool converting_none = view.conversion_start == -1 && view.conversion_end == -1;
        require(composing_none || (view.composing_start >= 0 && view.composing_end > view.composing_start &&
                    static_cast<std::size_t>(view.composing_end) <= view.text.size()),
                "Invalid published composition range");
        require(converting_none || (!composing_none && view.conversion_start >= view.composing_start &&
                    view.conversion_end > view.conversion_start && view.conversion_end <= view.composing_end),
                "Invalid published conversion target range");
        require(view.conversion_available || converting_none, "Unavailable conversion metadata has a target");
        // These are actual guest Editable markers, including Java-initiated
        // composition. A native token denotes host-session ownership only;
        // valid guest composition never acquires a synthetic token/authority.
        require(view.kind == android::ViewKind::edit_text ||
                    (composing_none && converting_none && view.conversion_available && !view.ime_token && !view.composition_event_revision),
                "IME state on a non-editable view");
        require(view.text_edit_events.size() <= android::text_edit_history_limit &&
                    view.text_edit_dropped_revision <= view.text_edit_event_revision,
                "Invalid TextEdit history revisions or count");
        std::size_t event_units = 0;
        // The watermark marks missing history, not an invalidation of known
        // records before a later gap. Retained operations stay independently
        // ordered, positive and unique across all published View histories.
        std::uint64_t previous_event = 0;
        for (const auto &event : view.text_edit_events) {
            require(event.revision > previous_event && event.revision <= view.text_edit_event_revision &&
                        event.buffer_revision && event.buffer_revision <= view.text_buffer_revision &&
                        event.kind <= android::TextEditEventKind::conversion_target_changed &&
                        (event.kind != android::TextEditEventKind::conversion_target_changed || event.text.empty()) &&
                        event.text.size() <= android::text_edit_history_units - event_units &&
                        text_edit_revisions.insert(event.revision).second,
                    "Invalid TextEdit operation history");
            previous_event = event.revision;
            event_units += event.text.size();
        }
        require(std::max(previous_event, view.text_edit_dropped_revision) == view.text_edit_event_revision &&
                    (view.text_edit_events.empty() || view.text_buffer_revision),
                "Incomplete TextEdit history tail or buffer identity");
        require(view.kind == android::ViewKind::edit_text ||
                    (!view.text_edit_event_revision && !view.text_edit_dropped_revision &&
                     !view.text_buffer_revision && view.text_edit_events.empty()),
                "TextEdit history on a non-editable view");
        require(view.content_description.size() <= android::view_description_limit &&
                    view.content_description.size() <= android::activity_description_limit - description_units,
                "View content descriptions exceed the publication quota");
        description_units += view.content_description.size();
        require(view.kind == android::ViewKind::checkbox || !view.checked,
                "Checked state on a non-checkable view");
        require(view.kind != android::ViewKind::checkbox || view.clickable,
                "Compound button lacks its intrinsic click action");
        require(view.scroll_y >= 0 && view.scroll_range_y >= view.scroll_y && view.scroll_range_y <= 327680 &&
                    view.scroll_viewport_y >= 0 && view.scroll_viewport_y <= 327680 &&
                    (!view.scroll_range_y || view.scroll_viewport_y <= 327680 - view.scroll_range_y),
                "Invalid vertical scroll geometry");
        require(view.kind == android::ViewKind::scroll_view ||
                    (!view.scroll_y && !view.scroll_range_y && !view.scroll_viewport_y),
                "Scroll geometry on a non-ScrollView");
        require(view.kind != android::ViewKind::scroll_view ||
                    (!view.parent && view.children.size() <= 1 &&
                     (view.scroll_viewport_y > 0 || !view.scroll_range_y)),
                "Nested or invalid ScrollView");
        bounds(view.bounds);
        require(!view.parent || views.contains(view.parent), "Unknown view parent");
        require(view.kind == android::ViewKind::linear_layout || view.kind == android::ViewKind::scroll_view || view.children.empty(),
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
    // Collection metadata is copied evidence only. Raw Android factory int32
    // values remain intact; native pattern eligibility is a separate decision.
    for (const auto &[id, view] : views) {
        const auto revision = view.accessibility_metadata_revision;
        if (!revision) {
            require(!view.accessibility_collection && !view.accessibility_collection_item &&
                        !view.accessibility_collection_owner && !view.accessibility_node_provider_present &&
                        !view.accessibility_actions && !view.accessibility_selection_required,
                    "Untagged accessibility collection metadata");
            continue;
        }
        require(accessibility_metadata_status == android::AccessibilityMetadataStatus::ready &&
                    revision == accessibility_metadata_attempt,
                "Stale accessibility collection metadata tag");
        require(!view.accessibility_selection_required || view.accessibility_collection.has_value(),
                "Selection policy has no prepared collection owner");
        bool rooted = false;
        for (auto ancestor = id; ancestor; ancestor = views.at(ancestor).parent)
            if (ancestor == content) { rooted = true; break; }
        require(rooted, "Accessibility metadata source is outside the content hierarchy");
        const auto owner = view.accessibility_collection_owner;
        if (!owner) continue; // An unresolved item never acquires an inferred owner.
        require(view.accessibility_collection_item && views.contains(owner),
                "Invalid accessibility collection owner");
        const auto &collection = views.at(owner);
        require(collection.accessibility_collection && collection.accessibility_metadata_revision == revision,
                "Accessibility collection owner has different preparation identity");
        bool ancestor_owner = false;
        for (auto ancestor = view.parent; ancestor; ancestor = views.at(ancestor).parent)
            if (ancestor == owner) { ancestor_owner = true; break; }
        require(ancestor_owner, "Accessibility collection owner is not an ancestor");
    }
}
std::vector<std::uint8_t> ActivityState::encode() const {
    validate();
    Writer out{{}, activity_state_limit};
    out.number(20);
    out.text(apk_hash, 64);
    out.text(package, 255);
    out.text(activity, 512);
    out.number(static_cast<std::uint64_t>(lifecycle));
    out.number(content);
    out.number(handled);
    out.number(std::bit_cast<std::uint32_t>(requested_orientation));
    out.number(configuration.screen_width_dp);
    out.number(configuration.screen_height_dp);
    out.number(configuration.smallest_screen_width_dp);
    out.number(configuration.density_dpi);
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
        out.number(view.clickable);
        out.number(view.checked);
        out.number(view.focusable);
        out.number(std::bit_cast<std::uint32_t>(view.selection_start));
        out.number(std::bit_cast<std::uint32_t>(view.selection_end));
        out.number(view.text_event_revision);
        out.number(view.selection_event_revision);
        out.number(view.text_mutation_base_revision);
        out.number(view.text_mutations.size());
        for (const auto &mutation : view.text_mutations) {
            out.number(mutation.revision);
            out.number(static_cast<std::uint32_t>(mutation.start));
            out.number(static_cast<std::uint32_t>(mutation.removed));
            out.number(static_cast<std::uint32_t>(mutation.inserted));
            out.number(static_cast<std::uint32_t>(mutation.before_length));
        }
        out.number(std::bit_cast<std::uint32_t>(view.composing_start));
        out.number(std::bit_cast<std::uint32_t>(view.composing_end));
        out.number(view.composition_event_revision);
        out.number(view.ime_token);
        out.number(view.conversion_available);
        out.number(std::bit_cast<std::uint32_t>(view.conversion_start));
        out.number(std::bit_cast<std::uint32_t>(view.conversion_end));
        out.number(view.text_edit_event_revision);
        out.number(view.text_edit_dropped_revision);
        out.number(view.text_buffer_revision);
        out.number(view.text_edit_events.size());
        for (const auto &event : view.text_edit_events) {
            out.number(event.revision);
            out.number(event.buffer_revision);
            out.number(static_cast<std::uint64_t>(event.kind));
            out.wide(event.text, android::text_edit_history_units);
        }
        out.number(static_cast<std::uint32_t>(view.scroll_y));
        out.number(static_cast<std::uint32_t>(view.scroll_range_y));
        out.number(static_cast<std::uint32_t>(view.scroll_viewport_y));
        rectangle(out, view.bounds);
        out.wide(view.text, 65536);
        out.wide(view.content_description, android::view_description_limit);
        out.number(view.children.size());
        for (auto child : view.children)
            out.number(child);
        out.number(view.accessibility_metadata_revision);
        out.number(view.accessibility_collection_owner);
        out.number(view.accessibility_node_provider_present);
        out.number(view.accessibility_actions);
        out.number(view.accessibility_selection_required.has_value());
        if (view.accessibility_selection_required)
            out.number(*view.accessibility_selection_required);
        out.number(view.accessibility_collection.has_value());
        if (view.accessibility_collection) {
            const auto &collection = *view.accessibility_collection;
            out.number(std::bit_cast<std::uint32_t>(collection.row_count));
            out.number(std::bit_cast<std::uint32_t>(collection.column_count));
            out.number(collection.hierarchical);
            out.number(std::bit_cast<std::uint32_t>(collection.selection_mode));
            out.number(std::bit_cast<std::uint32_t>(collection.item_count));
            out.number(std::bit_cast<std::uint32_t>(collection.important_item_count));
        }
        out.number(view.accessibility_collection_item.has_value());
        if (view.accessibility_collection_item) {
            const auto &item = *view.accessibility_collection_item;
            out.number(std::bit_cast<std::uint32_t>(item.row_index));
            out.number(std::bit_cast<std::uint32_t>(item.row_span));
            out.number(std::bit_cast<std::uint32_t>(item.column_index));
            out.number(std::bit_cast<std::uint32_t>(item.column_span));
            out.number(item.heading);
            out.number(item.selected);
        }
    }
    out.number(soft_input_requests.size());
    for (const auto &request : soft_input_requests) write_soft_input_request(out, request);
    out.number(view_activation_revision);
    out.number(view_activations.size());
    for (const auto &activation : view_activations) {
        out.number(activation.revision);
        out.number(activation.view);
        out.number(activation.window_generation);
    }
    out.number(accessibility_metadata_attempt);
    out.number(static_cast<std::uint64_t>(accessibility_metadata_status));
    out.number(accessibility_invalidation_revision);
    return out.bytes;
}
ActivityState ActivityState::decode(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= activity_state_limit, "Activity state exceeds limit");
    Reader in{bytes};
    require(in.number() == 20, "Unsupported Activity state version");
    ActivityState result;
    result.apk_hash = in.text(64);
    result.package = in.text(255);
    result.activity = in.text(512);
    const auto lifecycle = in.number();
    require(lifecycle <= static_cast<std::uint64_t>(android::Lifecycle::failed), "Invalid lifecycle state");
    result.lifecycle = static_cast<android::Lifecycle>(lifecycle);
    result.content = in.number();
    result.handled = in.boolean();
    result.requested_orientation = std::bit_cast<std::int32_t>(in.word());
    result.configuration = {in.word(), in.word(), in.word(), in.word()};
    require(result.configuration.valid(), "Invalid Activity display configuration");
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
    std::size_t description_units = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        android::ViewState view;
        view.object = in.number();
        view.parent = in.number();
        const auto kind = in.number();
        require(kind <= static_cast<std::uint64_t>(android::ViewKind::edit_text), "Unknown view type");
        view.kind = static_cast<android::ViewKind>(kind);
        view.id = std::bit_cast<std::int32_t>(in.word());
        const auto orientation = in.number();
        require(orientation <= 1, "Invalid layout orientation");
        view.orientation = static_cast<std::int32_t>(orientation);
        view.enabled = in.boolean();
        view.pressed = in.boolean();
        view.focused = in.boolean();
        view.clickable = in.boolean();
        view.checked = in.boolean();
        view.focusable = in.boolean();
        view.selection_start = std::bit_cast<std::int32_t>(in.word());
        view.selection_end = std::bit_cast<std::int32_t>(in.word());
        view.text_event_revision = in.number();
        view.selection_event_revision = in.number();
        view.text_mutation_base_revision = in.number();
        const auto mutation_count = in.number();
        require(mutation_count <= android::text_mutation_history_limit, "Too many text mutation records");
        for (std::uint64_t index = 0; index < mutation_count; ++index) {
            android::TextMutation mutation;
            mutation.revision = in.number();
            mutation.start = std::bit_cast<std::int32_t>(in.word());
            mutation.removed = std::bit_cast<std::int32_t>(in.word());
            mutation.inserted = std::bit_cast<std::int32_t>(in.word());
            mutation.before_length = std::bit_cast<std::int32_t>(in.word());
            view.text_mutations.push_back(mutation);
        }
        view.composing_start = std::bit_cast<std::int32_t>(in.word());
        view.composing_end = std::bit_cast<std::int32_t>(in.word());
        view.composition_event_revision = in.number();
        view.ime_token = in.number();
        view.conversion_available = in.boolean();
        view.conversion_start = std::bit_cast<std::int32_t>(in.word());
        view.conversion_end = std::bit_cast<std::int32_t>(in.word());
        view.text_edit_event_revision = in.number();
        view.text_edit_dropped_revision = in.number();
        view.text_buffer_revision = in.number();
        const auto event_count = in.number();
        require(event_count <= android::text_edit_history_limit, "Too many TextEdit history records");
        std::size_t event_units = 0;
        for (std::uint64_t index = 0; index < event_count; ++index) {
            android::TextEditEvent event;
            event.revision = in.number();
            event.buffer_revision = in.number();
            const auto event_kind = in.number();
            require(event_kind <= static_cast<std::uint64_t>(android::TextEditEventKind::conversion_target_changed),
                    "Unknown TextEdit operation kind");
            event.kind = static_cast<android::TextEditEventKind>(event_kind);
            event.text = in.wide(android::text_edit_history_units - event_units);
            event_units += event.text.size();
            view.text_edit_events.push_back(std::move(event));
        }
        const auto scroll_y = in.word(), scroll_range = in.word(), scroll_viewport = in.word();
        require(scroll_y <= scroll_range && scroll_range <= 327680 && scroll_viewport <= 327680 &&
                    (!scroll_range || scroll_viewport <= 327680 - scroll_range),
                "Invalid vertical scroll geometry");
        view.scroll_y = static_cast<std::int32_t>(scroll_y);
        view.scroll_range_y = static_cast<std::int32_t>(scroll_range);
        view.scroll_viewport_y = static_cast<std::int32_t>(scroll_viewport);
        view.bounds = rectangle(in);
        view.text = in.wide(65536);
        view.content_description = in.wide(std::min(android::view_description_limit,
            android::activity_description_limit - description_units));
        description_units += view.content_description.size();
        const auto children = in.number();
        require(children <= 256, "Too many children");
        for (std::uint64_t c = 0; c < children; ++c)
            view.children.push_back(in.number());
        view.accessibility_metadata_revision = in.number();
        view.accessibility_collection_owner = in.number();
        view.accessibility_node_provider_present = in.boolean();
        view.accessibility_actions = in.word();
        if (in.boolean()) view.accessibility_selection_required = in.boolean();
        if (in.boolean()) {
            android::AccessibilityCollectionInfo collection;
            collection.row_count = std::bit_cast<std::int32_t>(in.word());
            collection.column_count = std::bit_cast<std::int32_t>(in.word());
            collection.hierarchical = in.boolean();
            collection.selection_mode = std::bit_cast<std::int32_t>(in.word());
            collection.item_count = std::bit_cast<std::int32_t>(in.word());
            collection.important_item_count = std::bit_cast<std::int32_t>(in.word());
            view.accessibility_collection = collection;
        }
        if (in.boolean()) {
            android::AccessibilityCollectionItemInfo item;
            item.row_index = std::bit_cast<std::int32_t>(in.word());
            item.row_span = std::bit_cast<std::int32_t>(in.word());
            item.column_index = std::bit_cast<std::int32_t>(in.word());
            item.column_span = std::bit_cast<std::int32_t>(in.word());
            item.heading = in.boolean();
            item.selected = in.boolean();
            view.accessibility_collection_item = item;
        }
        const auto id = view.object;
        require(result.views.emplace(id, std::move(view)).second, "Duplicate view identity");
    }
    const auto soft_count = in.number();
    require(soft_count <= 32, "Too many encoded soft input requests");
    result.soft_input_requests.reserve(static_cast<std::size_t>(soft_count));
    for (std::uint64_t index = 0; index < soft_count; ++index)
        result.soft_input_requests.push_back(read_soft_input_request(in));
    result.view_activation_revision = in.number();
    const auto activation_count = in.number();
    require(activation_count <= android::view_activation_limit, "Too many encoded View activation records");
    result.view_activations.reserve(static_cast<std::size_t>(activation_count));
    for (std::uint64_t index = 0; index < activation_count; ++index)
        result.view_activations.push_back({in.number(), in.number(), in.number()});
    result.accessibility_metadata_attempt = in.number();
    const auto metadata_status = in.number();
    require(metadata_status <= static_cast<std::uint64_t>(android::AccessibilityMetadataStatus::mutated),
            "Unknown accessibility metadata status");
    result.accessibility_metadata_status = static_cast<android::AccessibilityMetadataStatus>(metadata_status);
    result.accessibility_invalidation_revision = in.number();
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
