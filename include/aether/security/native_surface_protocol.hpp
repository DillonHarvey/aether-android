#pragma once
#include "aether/android/native_surface.hpp"
#include "aether/security/protocol.hpp"

namespace aether::security {
inline constexpr std::size_t native_surface_request_bytes = 64, native_surface_ack_bytes = 104;
struct NativeSurfaceTransaction {
    std::uint64_t context = 0;
    android::NativeSurfaceRequest request;
};
// Fixed little-endian schema3 records. Surface requests carry no host handle,
// pointer, filename or guest-selected dimensions. ACKs echo every request field.
// An all-zero admit result defers realization without creating a producer.
std::vector<std::uint8_t> encode_native_surface_request(const android::NativeSurfaceRequest &, std::uint64_t context);
NativeSurfaceTransaction decode_native_surface_request(std::span<const std::uint8_t>);
std::vector<std::uint8_t> encode_native_surface_ack(const android::NativeSurfaceRequest &,
                                                  const android::NativeSurfaceAdmission &, std::uint64_t context);
android::NativeSurfaceAdmission decode_native_surface_ack(std::span<const std::uint8_t>,
                                                          const android::NativeSurfaceRequest &expected,
                                                          std::uint64_t context);
} // namespace aether::security
