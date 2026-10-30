#include "aether/security/activity_launch.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <limits>

namespace aether::security {
namespace {
[[noreturn]] void invalid(std::string_view message) {
    throw ProtocolError("AETHER_ACTIVITY_LAUNCH_INVALID: " + std::string(message));
}
void require(bool condition, std::string_view message) { if (!condition) invalid(message); }
std::u16string units(std::string_view text) {
    const auto wide = utf16(text);
    return {wide.begin(), wide.end()};
}
void launch_flags(std::uint32_t flags, bool document = false) {
    if (flags & ~(document ? std::uint32_t{0x10000001} : std::uint32_t{0x10000000}))
        throw ProtocolError("AETHER_ACTIVITY_LAUNCH_UNSUPPORTED: task, grant or other launch flags are not implemented");
}
class Writer {
    std::vector<std::uint8_t> bytes_;
    void room(std::size_t count) {
        require(count <= activity_launch_limit - bytes_.size(), "Startup payload exceeds its existing 4 MiB bound");
        const auto required = bytes_.size() + count;
        if (required > bytes_.capacity()) {
            const auto growth = bytes_.capacity() ? bytes_.capacity() * 2 : std::size_t{256};
            bytes_.reserve(std::min(activity_launch_limit, std::max(required, growth)));
            require(bytes_.capacity() <= activity_launch_limit, "Encoded startup capacity exceeds its bound");
        }
    }
  public:
    void number(std::uint64_t value) {
        room(8);
        for (unsigned shift = 0; shift < 64; shift += 8) bytes_.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void wide(std::u16string_view value) {
        require(value.size() <= 4096, "Startup text exceeds 4096 UTF-16 units");
        number(value.size());
        room(value.size() * 2);
        for (const auto unit : value) {
            bytes_.push_back(static_cast<std::uint8_t>(unit));
            bytes_.push_back(static_cast<std::uint8_t>(unit >> 8));
        }
    }
    void text(std::string_view value) {
        number(value.size());
        room(value.size());
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    void optional(const std::optional<std::u16string> &value) {
        number(value ? 1 : 0);
        if (value) wide(*value);
    }
    void policy(std::optional<bool> value) { number(!value ? 0 : *value ? 2 : 1); }
    std::vector<std::uint8_t> take() { return std::move(bytes_); }
};
class Reader {
    std::span<const std::uint8_t> bytes_;
    std::size_t at_ = 0;
  public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {
        require(!bytes.empty() && bytes.size() <= activity_launch_limit, "Invalid startup payload size");
    }
    std::uint64_t number() {
        require(at_ <= bytes_.size() && bytes_.size() - at_ >= 8, "Truncated startup integer");
        const auto value = read_u64(bytes_, at_);
        at_ += 8;
        return value;
    }
    bool boolean() { const auto value = number(); require(value <= 1, "Invalid startup boolean"); return value != 0; }
    std::uint32_t word() {
        const auto value = number();
        require(value <= std::numeric_limits<std::uint32_t>::max(), "Startup integer is not a uint32");
        return static_cast<std::uint32_t>(value);
    }
    std::u16string wide() {
        const auto count = number();
        require(count <= 4096 && count <= (bytes_.size() - at_) / 2, "Invalid startup UTF-16 range");
        std::u16string result(static_cast<std::size_t>(count), u'\0');
        for (auto &unit : result) {
            unit = static_cast<char16_t>(bytes_[at_] | (static_cast<std::uint16_t>(bytes_[at_ + 1]) << 8));
            at_ += 2;
        }
        return result;
    }
    std::string text(std::size_t maximum) {
        const auto count = number();
        require(count <= maximum && count <= bytes_.size() - at_, "Invalid startup document text range");
        const auto first = bytes_.begin() + static_cast<std::ptrdiff_t>(at_);
        std::string result(first, first + static_cast<std::ptrdiff_t>(count));
        at_ += static_cast<std::size_t>(count);
        return result;
    }
    std::optional<std::u16string> optional() { if (!boolean()) return {}; return wide(); }
    std::optional<bool> policy() {
        const auto value = number(); require(value <= 2, "Invalid effective caller/feature policy");
        return value == 0 ? std::optional<bool>{} : std::optional<bool>{value == 2};
    }
    void finish() const { require(at_ == bytes_.size(), "Trailing startup fields or unsupported extensions"); }
    std::size_t remaining() const noexcept { return bytes_.size() - at_; }
};
void match_selection(const ActivityLaunch &launch, const apk::ManifestInfo &manifest) {
    require(launch.declaration < manifest.activities.size() && launch.target < manifest.activities.size(),
            "Selected declaration or target no longer exists");
    const auto resolution = apk::resolve_intent_value(manifest, launch.intent, launch.policy);
    const bool member = std::any_of(resolution.matches.begin(), resolution.matches.end(), [&](const auto &match) {
        return match.declaration == launch.declaration && match.target == launch.target;
    });
    const bool chosen = launch.user_selected && member &&
        (resolution.status == apk::LauncherStatus::selected || resolution.status == apk::LauncherStatus::ambiguous);
    const bool unique = !launch.user_selected && resolution.status == apk::LauncherStatus::selected &&
        resolution.declaration && resolution.target && *resolution.declaration == launch.declaration &&
        *resolution.target == launch.target;
    require(chosen || unique, "Request does not re-resolve to the captured original matching choice");
    require(launch.package == units(manifest.package_id) &&
                launch.component_name == units(manifest.activities[launch.declaration].name) &&
                launch.target_name == units(manifest.activities[launch.target].name) &&
                manifest.activities[launch.target].target.empty(),
            "Captured package, alias or executable target differs from the held manifest");
    require(launch.policy.filters.target_sdk == manifest.target_sdk.value_or(manifest.min_sdk.value_or(1)),
            "Captured target SDK differs from the held manifest");
}
} // namespace

void ActivityLaunch::validate() const {
    require(apk_hash.size() == 64 && std::all_of(apk_hash.begin(), apk_hash.end(), [](char unit) {
        return (unit >= '0' && unit <= '9') || (unit >= 'a' && unit <= 'f');
    }), "Invalid captured APK identity");
    require(!package.empty() && package.size() <= 4096 && !component_name.empty() && component_name.size() <= 4096 &&
                !target_name.empty() && target_name.size() <= 4096 && declaration < apk::manifest_activity_count &&
                target < apk::manifest_activity_count, "Invalid captured component identities");
    intent.validate();
    launch_flags(intent.flags, read_document.has_value());
    if (read_document) {
        require(host::valid_document_info(*read_document) && user_selected && intent.flags == 0x10000001u &&
                    intent.action == std::optional<std::u16string>{u"android.intent.action.VIEW"} &&
                    intent.data == std::optional<std::u16string>{units(read_document->uri)} &&
                    intent.mime_type == std::optional<std::u16string>{units(read_document->mime_type)} &&
                    intent.resolved_mime_type == intent.mime_type &&
                    intent.mime_state == apk::IntentMimeState::resolved,
                "Document metadata does not match the approved VIEW request and read-only flag");
    }
    // Capacity accounting includes the envelope's owned metadata and value.
    // Existing process quotas still cover temporary encode/decode/delivery copies.
    auto remaining = activity_launch_limit - intent.accounted_bytes();
    const auto charge = [&](std::size_t count, std::size_t width) {
        require(count <= remaining / width, "Captured launch metadata exceeds its retained storage bound");
        remaining -= count * width;
    };
    charge(sizeof(*this), 1);
    require(apk_hash.capacity() < std::numeric_limits<std::size_t>::max(), "Invalid captured hash capacity");
    charge(apk_hash.capacity() + 1, 1);
    for (const auto *value : {&package, &component_name, &target_name}) {
        require(value->capacity() < std::numeric_limits<std::size_t>::max(), "Invalid captured text capacity");
        charge(value->capacity() + 1, sizeof(char16_t));
    }
    if (read_document)
        for (const auto *value : {&read_document->uri, &read_document->mime_type, &read_document->display_name}) {
            require(value->capacity() < std::numeric_limits<std::size_t>::max(), "Invalid document metadata capacity");
            charge(value->capacity() + 1, 1);
        }
}
void ActivityLaunch::validate_against(const apk::ManifestInfo &manifest, std::string_view hash) const {
    validate();
    require(apk_hash == hash, "Captured request belongs to different APK bytes");
    match_selection(*this, manifest);
}
apk::IntentValue ActivityLaunch::delivered_intent() const {
    validate();
    auto result = intent;
    result.component = apk::IntentComponentValue{package, component_name};
    result.validate();
    return result;
}
ActivityLaunch resolve_activity_launch(const apk::ManifestInfo &manifest, std::string_view hash,
                                       apk::IntentValue intent, const apk::ActivityIntentPolicy &policy,
                                       std::optional<std::size_t> chosen_declaration) {
    apk::canonicalize_intent_categories(intent);
    intent.validate();
    launch_flags(intent.flags);
    const auto resolution = apk::resolve_intent_value(manifest, intent, policy);
    std::optional<std::size_t> declaration = resolution.declaration, target = resolution.target;
    if (chosen_declaration) {
        if (resolution.status != apk::LauncherStatus::selected && resolution.status != apk::LauncherStatus::ambiguous)
            throw ProtocolError("AETHER_ACTIVITY_LAUNCH_UNRESOLVED: request has unsupported or unavailable choices");
        const auto found = std::find_if(resolution.matches.begin(), resolution.matches.end(), [&](const auto &match) {
            return match.declaration == *chosen_declaration;
        });
        if (found == resolution.matches.end())
            throw ProtocolError("AETHER_ACTIVITY_LAUNCH_UNRESOLVED: selected Activity does not match the original request");
        declaration = found->declaration;
        target = found->target;
    } else if (resolution.status != apk::LauncherStatus::selected || !declaration || !target) {
        throw ProtocolError("AETHER_ACTIVITY_LAUNCH_UNRESOLVED: request has no unique supported external target");
    }
    ActivityLaunch result;
    result.apk_hash = hash;
    result.package = units(manifest.package_id);
    result.declaration = *declaration;
    result.target = *target;
    result.user_selected = chosen_declaration.has_value();
    result.component_name = units(manifest.activities[result.declaration].name);
    result.target_name = units(manifest.activities[result.target].name);
    result.intent = std::move(intent);
    result.policy = policy;
    result.policy.filters.target_sdk = manifest.target_sdk.value_or(manifest.min_sdk.value_or(1));
    result.validate();
    return result;
}
std::vector<std::uint8_t> ActivityLaunch::encode() const {
    validate();
    Writer out;
    out.number(activity_launch_schema);
    // Hash uses the same raw-unit representation, constrained above to ASCII.
    out.wide(std::u16string(apk_hash.begin(), apk_hash.end()));
    out.wide(package); out.wide(component_name); out.wide(target_name);
    out.number(declaration); out.number(target);
    out.number(user_selected ? 1 : 0);
    out.policy(policy.filters.relative_reference_groups);
    out.number(policy.filters.target_sdk);
    out.policy(policy.enforce_explicit_filters); out.policy(policy.block_null_action);
    out.optional(intent.action); out.optional(intent.package); out.optional(intent.data);
    out.optional(intent.mime_type); out.optional(intent.identifier); out.optional(intent.resolved_mime_type);
    out.number(intent.component ? 1 : 0);
    if (intent.component) { out.wide(intent.component->package); out.wide(intent.component->class_name); }
    out.number(intent.categories ? 1 : 0);
    if (intent.categories) {
        out.number(intent.categories->size());
        for (const auto &category : *intent.categories) out.optional(category);
    }
    out.number(intent.flags);
    out.number(static_cast<std::uint64_t>(intent.mime_state));
    out.number(intent.default_only ? 1 : 0);
    out.number(read_document ? 1 : 0);
    if (read_document) {
        out.text(read_document->uri); out.text(read_document->mime_type); out.text(read_document->display_name);
        out.number(read_document->size);
    }
    return out.take();
}
ActivityLaunch ActivityLaunch::decode(std::span<const std::uint8_t> bytes) {
    Reader in(bytes);
    require(in.number() == activity_launch_schema, "Unsupported startup schema");
    ActivityLaunch result;
    const auto hash = in.wide();
    require(hash.size() == 64 && std::all_of(hash.begin(), hash.end(), [](char16_t unit) {
        return (unit >= u'0' && unit <= u'9') || (unit >= u'a' && unit <= u'f');
    }), "Invalid encoded APK hash");
    for (const auto unit : hash) result.apk_hash.push_back(static_cast<char>(unit));
    result.package = in.wide(); result.component_name = in.wide(); result.target_name = in.wide();
    const auto declaration = in.number(), target = in.number();
    require(declaration < apk::manifest_activity_count && target < apk::manifest_activity_count,
            "Invalid encoded declaration/target indices");
    result.declaration = static_cast<std::size_t>(declaration); result.target = static_cast<std::size_t>(target);
    result.user_selected = in.boolean();
    result.policy.filters.relative_reference_groups = in.policy();
    result.policy.filters.target_sdk = in.word();
    result.policy.enforce_explicit_filters = in.policy(); result.policy.block_null_action = in.policy();
    result.intent.action = in.optional(); result.intent.package = in.optional(); result.intent.data = in.optional();
    result.intent.mime_type = in.optional(); result.intent.identifier = in.optional(); result.intent.resolved_mime_type = in.optional();
    if (in.boolean()) result.intent.component = apk::IntentComponentValue{in.wide(), in.wide()};
    if (in.boolean()) {
        const auto count = in.number();
        require(count <= 65536 && count <= in.remaining() / 8, "Too many or truncated encoded categories");
        result.intent.categories.emplace();
        result.intent.categories->reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index) result.intent.categories->push_back(in.optional());
    }
    result.intent.flags = in.word();
    const auto mime = in.number(); require(mime <= 1, "Unknown MIME resolution provenance");
    result.intent.mime_state = static_cast<apk::IntentMimeState>(mime);
    result.intent.default_only = in.boolean();
    if (in.boolean()) {
        host::DocumentInfo info;
        info.uri = in.text(host::document_uri_prefix.size() + 32);
        info.mime_type = in.text(255); info.display_name = in.text(255); info.size = in.number();
        result.read_document = std::move(info);
    }
    in.finish();
    result.validate();
    return result;
}
} // namespace aether::security
