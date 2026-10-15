#pragma once
#include "aether/security/protocol.hpp"
namespace aether::security {
// Optional trusted provider. The common broker does not link a graphics driver.
class GraphicsService {
  public:
    virtual ~GraphicsService() = default;
    virtual Frame dispatch(const Frame &request) = 0;
    virtual void revoke() noexcept = 0;
    virtual std::uint32_t last_operation() const noexcept { return UINT32_MAX; }
};
} // namespace aether::security
