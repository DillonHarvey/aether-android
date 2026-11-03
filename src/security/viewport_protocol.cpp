#include "aether/security/viewport_protocol.hpp"

namespace aether::security {
namespace {
static_assert(viewport_request_bytes <= maximum_payload && viewport_ack_bytes <= maximum_payload);

void require(bool value, const char *reason) {
    if (!value) throw ProtocolError(std::string("AETHER_VIEWPORT_PROTOCOL: ") + reason);
}

bool empty_viewport_identity(const android::ViewportIdentity &identity) noexcept {
    return identity.activity == 0 && identity.content == 0 &&
           identity.window_generation == 0 && identity.attachment_revision == 0;
}

bool complete_viewport_identity(const android::ViewportIdentity &identity) noexcept {
    return identity.activity != 0 && identity.content != 0 &&
           identity.window_generation != 0 && identity.attachment_revision != 0;
}

bool same_viewport_request(const android::ViewportRequest &left,
                           const android::ViewportRequest &right) noexcept {
    return left.phase == right.phase &&
           left.requested_orientation == right.requested_orientation &&
           left.geometry_revision == right.geometry_revision &&
           left.identity == right.identity;
}

void validate_viewport_request_fields(const android::ViewportRequest &request) {
    require(request.requested_orientation >= -1 && request.requested_orientation <= 1,
            "Unsupported viewport orientation request");
    switch (request.phase) {
    case android::ViewportPhase::launch_geometry:
        require(request.geometry_revision == 0 && empty_viewport_identity(request.identity),
                "Launch geometry request carries an existing tree or geometry lease");
        break;
    case android::ViewportPhase::bind_content:
        require(request.geometry_revision != 0 && complete_viewport_identity(request.identity),
                "Content binding requires the complete actual tree and admitted geometry lease");
        break;
    default:
        require(false, "Unknown viewport request phase");
    }
}

std::uint32_t viewport_word(std::span<const std::uint8_t> bytes, std::size_t offset) {
    require(offset <= bytes.size() && bytes.size() - offset >= 8,
            "Truncated viewport integer");
    const auto value = read_u64(bytes, offset);
    require(value <= UINT32_MAX, "Viewport integer exceeds its field width");
    return static_cast<std::uint32_t>(value);
}

std::int32_t viewport_orientation(std::span<const std::uint8_t> bytes, std::size_t offset) {
    require(offset <= bytes.size() && bytes.size() - offset >= 8,
            "Truncated viewport orientation");
    const auto value = read_u64(bytes, offset);
    require(value == UINT64_MAX || value <= 1,
            "Viewport orientation is not canonical sign-extended -1, zero or one");
    return value == UINT64_MAX ? -1 : static_cast<std::int32_t>(value);
}

void validate_viewport_extent(std::span<const std::uint8_t> bytes, std::size_t expected_size) {
    require(expected_size >= 8 && bytes.size() == expected_size,
            "Viewport message has an invalid extent");
    require(read_u64(bytes, 0) == viewport_schema, "Unsupported viewport message schema");
}

ViewportTransaction request_prefix(std::span<const std::uint8_t> bytes) {
    require(bytes.size() >= viewport_request_bytes, "Viewport request prefix is truncated");
    validate_viewport_extent(bytes.first(viewport_request_bytes), viewport_request_bytes);
    ViewportTransaction result;
    result.context = read_u64(bytes, 8);
    auto &request = result.request;
    request.phase = static_cast<android::ViewportPhase>(read_u64(bytes, 16));
    request.requested_orientation = viewport_orientation(bytes, 24);
    request.geometry_revision = read_u64(bytes, 32);
    request.identity.activity = read_u64(bytes, 40);
    request.identity.content = read_u64(bytes, 48);
    request.identity.window_generation = read_u64(bytes, 56);
    request.identity.attachment_revision = read_u64(bytes, 64);
    validate_viewport_request(request, result.context);
    return result;
}
} // namespace

void validate_viewport_request(const android::ViewportRequest &request, std::uint64_t context) {
    require(context != UINT64_MAX, "Viewport command context is reserved");
    validate_viewport_request_fields(request);
}

void validate_viewport_admission(const android::ViewportRequest &request,
                                 const android::ViewportAdmission &admission) {
    validate_viewport_request_fields(request);
    require(admission.geometry_revision != 0, "Viewport geometry lease is absent");
    if (request.phase == android::ViewportPhase::launch_geometry) {
        require(empty_viewport_identity(admission.identity),
                "Launch geometry acknowledgement invents an Activity or content tree");
    } else {
        require(admission.geometry_revision == request.geometry_revision &&
                    admission.identity == request.identity,
                "Viewport binding changed the admitted geometry or actual tree identity");
    }
    require(admission.width_px != 0 && admission.width_px <= 16384 &&
                admission.height_px != 0 && admission.height_px <= 16384 &&
                std::uint64_t(admission.width_px) * admission.height_px <= 16'777'216,
            "Viewport extent exceeds the existing host backing surface bounds");
    require(admission.host_dpi >= 48 && admission.host_dpi <= 960,
            "Viewport host DPI is unsupported");
    require(admission.configuration.valid(), "Viewport display configuration is invalid");
    require(admission.has_navigation_bar.has_value(),
            "Viewport navigation-bar policy has no authenticated source");
    const auto logical = [&](std::uint32_t pixels) {
        const auto rounded = (std::uint64_t(pixels) * 96 + admission.host_dpi / 2) /
                             admission.host_dpi;
        return static_cast<std::uint32_t>(rounded ? rounded : 1);
    };
    const auto width_dp = logical(admission.width_px);
    const auto height_dp = logical(admission.height_px);
    const auto density = static_cast<std::uint32_t>(
        (std::uint64_t(admission.host_dpi) * 160 + 48) / 96);
    const android::DisplayConfiguration expected{
        width_dp, height_dp, width_dp < height_dp ? width_dp : height_dp, density};
    require(admission.configuration == expected,
            "Viewport display configuration differs from the actual pixel extent and host DPI");
}

std::vector<std::uint8_t> encode_viewport_request(const android::ViewportRequest &request,
                                                std::uint64_t context) {
    validate_viewport_request(request, context);
    std::vector<std::uint8_t> bytes;
    bytes.reserve(viewport_request_bytes);
    for (const auto value : {viewport_schema, context, static_cast<std::uint64_t>(request.phase),
                             static_cast<std::uint64_t>(static_cast<std::int64_t>(request.requested_orientation)),
                             request.geometry_revision, request.identity.activity, request.identity.content,
                             request.identity.window_generation, request.identity.attachment_revision})
        append_u64(bytes, value);
    return bytes;
}

ViewportTransaction decode_viewport_request(std::span<const std::uint8_t> bytes) {
    validate_viewport_extent(bytes, viewport_request_bytes);
    return request_prefix(bytes);
}

std::vector<std::uint8_t> encode_viewport_ack(const android::ViewportRequest &request,
                                            const android::ViewportAdmission &admission,
                                            std::uint64_t context) {
    validate_viewport_request(request, context);
    validate_viewport_admission(request, admission);
    auto bytes = encode_viewport_request(request, context);
    bytes.reserve(viewport_ack_bytes);
    for (const auto value : {admission.geometry_revision, std::uint64_t{admission.width_px},
                             std::uint64_t{admission.height_px}, std::uint64_t{admission.host_dpi},
                             std::uint64_t{admission.configuration.screen_width_dp},
                             std::uint64_t{admission.configuration.screen_height_dp},
                             std::uint64_t{admission.configuration.smallest_screen_width_dp},
                             std::uint64_t{admission.configuration.density_dpi},
                             admission.identity.activity, admission.identity.content,
                             admission.identity.window_generation, admission.identity.attachment_revision})
        append_u64(bytes, value);
    append_u64(bytes, *admission.has_navigation_bar ? 2u : 1u);
    return bytes;
}

android::ViewportAdmission decode_viewport_ack(std::span<const std::uint8_t> bytes,
                                               const android::ViewportRequest &expected,
                                               std::uint64_t context) {
    validate_viewport_request(expected, context);
    validate_viewport_extent(bytes, viewport_ack_bytes);
    const auto echoed = request_prefix(bytes);
    require(echoed.context == context && same_viewport_request(echoed.request, expected),
            "Viewport acknowledgement does not echo the exact request");
    android::ViewportAdmission result;
    result.geometry_revision = read_u64(bytes, 72);
    result.width_px = viewport_word(bytes, 80);
    result.height_px = viewport_word(bytes, 88);
    result.host_dpi = viewport_word(bytes, 96);
    result.configuration = {viewport_word(bytes, 104), viewport_word(bytes, 112),
                            viewport_word(bytes, 120), viewport_word(bytes, 128)};
    result.identity = {read_u64(bytes, 136), read_u64(bytes, 144),
                       read_u64(bytes, 152), read_u64(bytes, 160)};
    const auto navigation = viewport_word(bytes, 168);
    require(navigation == 1 || navigation == 2,
            "Viewport navigation-bar policy is unknown or noncanonical");
    result.has_navigation_bar = navigation == 2;
    validate_viewport_admission(expected, result);
    return result;
}

void ViewportLease::commit(const android::ViewportRequest &request,
                            const android::ViewportAdmission &admission) {
    validate_viewport_admission(request, admission);
    const auto require_lease = [](bool ok, const char *why) {
        if (!ok) throw ProtocolError(std::string("AETHER_VIEWPORT_LEASE: ") + why);
    };
    if (request.phase == android::ViewportPhase::launch_geometry) {
        require_lease(!launch_, "Launch geometry was already admitted");
        launch_ = admission;
        orientation_ = request.requested_orientation;
        return;
    }
    require_lease(launch_.has_value(), "Content binding precedes launch geometry");
    require_lease(!pending_, "Previous content binding has no corroborating Activity state");
    require_lease(request.requested_orientation == orientation_,
                  "Content orientation differs from frozen launch geometry");
    const auto &frozen = *launch_;
    require_lease(request.geometry_revision == frozen.geometry_revision &&
                      admission.geometry_revision == frozen.geometry_revision &&
                      admission.width_px == frozen.width_px && admission.height_px == frozen.height_px &&
                      admission.host_dpi == frozen.host_dpi && admission.configuration == frozen.configuration &&
                      admission.has_navigation_bar == frozen.has_navigation_bar,
                  "Content binding changed immutable geometry or configuration");
    require_lease(request.identity.attachment_revision > last_attachment_revision_,
                  "Content attachment revision did not advance");
    pending_ = request.identity;
}

void ViewportLease::validate_binding(const android::ViewportIdentity &identity,
                                      std::uint64_t geometry_revision,
                                      const android::DisplayConfiguration &configuration) {
    const auto require_lease = [](bool ok, const char *why) {
        if (!ok) throw ProtocolError(std::string("AETHER_VIEWPORT_LEASE: ") + why);
    };
    require_lease(launch_.has_value(), "Activity state precedes launch geometry");
    require_lease(geometry_revision == launch_->geometry_revision && configuration == launch_->configuration,
                  "Activity state differs from frozen launch geometry");
    if (pending_) {
        require_lease(identity == *pending_, "Activity state does not corroborate pending content binding");
        committed_ = pending_;
        last_attachment_revision_ = identity.attachment_revision;
        pending_.reset();
        return;
    }
    require_lease(committed_ && identity == *committed_,
                  "Activity state has no matching committed content binding");
}
} // namespace aether::security
