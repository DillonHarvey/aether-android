#pragma once
#include "aether/android/viewport.hpp"
#include "aether/security/protocol.hpp"
#include <optional>

namespace aether::security {
inline constexpr std::uint64_t viewport_schema = 2;
inline constexpr std::size_t viewport_request_bytes = 72, viewport_ack_bytes = 176;

struct ViewportTransaction {
    // Command context zero is startup/idle. The transport owns session/ordinal
    // validation; a geometry record carries no native handles or capabilities.
    std::uint64_t context = 0;
    android::ViewportRequest request;
};

void validate_viewport_request(const android::ViewportRequest &, std::uint64_t context);
void validate_viewport_admission(const android::ViewportRequest &, const android::ViewportAdmission &);
std::vector<std::uint8_t> encode_viewport_request(const android::ViewportRequest &, std::uint64_t context);
ViewportTransaction decode_viewport_request(std::span<const std::uint8_t>);
std::vector<std::uint8_t> encode_viewport_ack(const android::ViewportRequest &,
                                            const android::ViewportAdmission &, std::uint64_t context);
android::ViewportAdmission decode_viewport_ack(std::span<const std::uint8_t>,
                                               const android::ViewportRequest &expected,
                                               std::uint64_t context);

// One session owns one frozen physical geometry lease. Logical attachments are
// accepted only after their acknowledgement is corroborated by actual state.
class ViewportLease final {
  public:
    void commit(const android::ViewportRequest &, const android::ViewportAdmission &);
    void validate_binding(const android::ViewportIdentity &, std::uint64_t geometry_revision,
                          const android::DisplayConfiguration &);
    const android::ViewportAdmission *geometry() const noexcept { return launch_ ? &*launch_ : nullptr; }
    const android::ViewportIdentity *binding() const noexcept {
        return !pending_ && committed_ ? &*committed_ : nullptr;
    }
    bool binding_pending() const noexcept { return pending_.has_value(); }
    void retire_binding() noexcept { pending_.reset(); committed_.reset(); }

  private:
    std::optional<android::ViewportAdmission> launch_;
    std::optional<android::ViewportIdentity> pending_, committed_;
    std::int32_t orientation_ = -1;
    std::uint64_t last_attachment_revision_ = 0;
};
} // namespace aether::security
