#include "aether/security/native_surface_protocol.hpp"
#include "aether/graphics/shared_window.hpp"
#include <bit>

namespace aether::security {
namespace {
void require(bool value, const char *reason) {
    if (!value) throw ProtocolError(std::string("AETHER_NATIVE_SURFACE_PROTOCOL: ") + reason);
}
void validate(const android::NativeSurfaceRequest &request, std::uint64_t context) {
    using Action = android::NativeSurfaceRequest::Action;
    require(context != UINT64_MAX, "reserved command context");
    require(request.view && request.window_generation && request.root, "missing actual view, content root or window generation");
    require(request.action == Action::admit || request.action == Action::abandon, "unknown native surface action");
    require(request.action == Action::admit ? !request.producer : request.producer != 0,
            "producer identity does not match native surface action");
    require(request.requested_orientation >= -1 && request.requested_orientation <= 1,
            "unsupported requested orientation");
}
void validate(const android::NativeSurfaceRequest &request, const android::NativeSurfaceAdmission &admission) {
    if (!admission.producer) {
        require(request.action == android::NativeSurfaceRequest::Action::admit && !admission.backend_token &&
                    !admission.width && !admission.height && !admission.format,
                "deferred admission must have no producer, backing or geometry");
        return;
    }
    require(admission.producer != 0, "missing admitted producer identity");
    require(request.action != android::NativeSurfaceRequest::Action::abandon ||
                admission.producer == request.producer,
            "abandonment acknowledgement names another producer");
    require((admission.backend_token & 0xffff000000000000ULL) == graphics::SharedWindowGrant::token_prefix &&
                (admission.backend_token & 0x0000ffffffffffffULL) != 0,
            "invalid admitted renderer token");
    require(admission.width && admission.width <= 1024 && admission.height && admission.height <= 1024 &&
                admission.format > 0,
            "invalid actual native surface geometry");
}
bool same(const android::NativeSurfaceRequest &a, const android::NativeSurfaceRequest &b) {
    return a.action == b.action && a.view == b.view && a.window_generation == b.window_generation &&
           a.producer == b.producer && a.requested_orientation == b.requested_orientation && a.root == b.root;
}
NativeSurfaceTransaction request_prefix(std::span<const std::uint8_t> bytes) {
    require(bytes.size() >= native_surface_request_bytes, "truncated native surface request");
    require(read_u64(bytes, 0) == 3, "unknown native surface schema");
    const auto orientation = std::bit_cast<std::int64_t>(read_u64(bytes, 48));
    require(orientation >= -1 && orientation <= 1, "noncanonical native surface orientation");
    NativeSurfaceTransaction result;
    result.context = read_u64(bytes, 8);
    result.request.action = static_cast<android::NativeSurfaceRequest::Action>(read_u64(bytes, 16));
    result.request.view = read_u64(bytes, 24);
    result.request.window_generation = read_u64(bytes, 32);
    result.request.producer = read_u64(bytes, 40);
    result.request.requested_orientation = static_cast<std::int32_t>(orientation);
    result.request.root = read_u64(bytes, 56);
    validate(result.request, result.context);
    return result;
}
} // namespace

std::vector<std::uint8_t> encode_native_surface_request(const android::NativeSurfaceRequest &request,
                                                       std::uint64_t context) {
    validate(request, context);
    std::vector<std::uint8_t> bytes;
    bytes.reserve(native_surface_request_bytes);
    for (const auto value : {std::uint64_t{3}, context, static_cast<std::uint64_t>(request.action), request.view,
                             request.window_generation, request.producer,
                             static_cast<std::uint64_t>(static_cast<std::int64_t>(request.requested_orientation)), request.root})
        append_u64(bytes, value);
    return bytes;
}
NativeSurfaceTransaction decode_native_surface_request(std::span<const std::uint8_t> bytes) {
    require(bytes.size() == native_surface_request_bytes, "native surface request has an invalid extent");
    return request_prefix(bytes);
}
std::vector<std::uint8_t> encode_native_surface_ack(const android::NativeSurfaceRequest &request,
                                                   const android::NativeSurfaceAdmission &admission,
                                                   std::uint64_t context) {
    validate(request, context);
    validate(request, admission);
    auto bytes = encode_native_surface_request(request, context);
    bytes.reserve(native_surface_ack_bytes);
    for (const auto value : {admission.producer, admission.backend_token, std::uint64_t{admission.width},
                             std::uint64_t{admission.height}, static_cast<std::uint64_t>(admission.format)})
        append_u64(bytes, value);
    return bytes;
}
android::NativeSurfaceAdmission decode_native_surface_ack(std::span<const std::uint8_t> bytes,
                                                           const android::NativeSurfaceRequest &expected,
                                                           std::uint64_t context) {
    validate(expected, context);
    require(bytes.size() == native_surface_ack_bytes, "native surface acknowledgement has an invalid extent");
    const auto echoed = request_prefix(bytes);
    require(echoed.context == context && same(echoed.request, expected), "native surface acknowledgement echo differs");
    const auto width = read_u64(bytes, 80), height = read_u64(bytes, 88), format = read_u64(bytes, 96);
    require(width <= UINT32_MAX && height <= UINT32_MAX && format <= INT32_MAX,
            "native surface geometry exceeds its field width");
    android::NativeSurfaceAdmission result{read_u64(bytes, 64), read_u64(bytes, 72),
        static_cast<std::uint32_t>(width), static_cast<std::uint32_t>(height), static_cast<std::int32_t>(format)};
    validate(expected, result);
    return result;
}
} // namespace aether::security
