#pragma once
#include "aether/apk/inspect.hpp"
#include <limits>

namespace aether::apk {
class View {
  public:
    explicit View(Bytes bytes, std::string phase) : bytes_(bytes), phase_(std::move(phase)) {}
    std::size_t size() const { return bytes_.size(); }
    Bytes slice(std::size_t offset, std::size_t size) const {
        if (offset > bytes_.size() || size > bytes_.size() - offset)
            throw InspectError("AETHER_PARSE_BOUNDS", phase_,
                               "A structure exceeds its containing byte range");
        return bytes_.subspan(offset, size);
    }
    std::uint8_t u8(std::size_t offset) const { return slice(offset, 1)[0]; }
    std::uint16_t u16(std::size_t offset) const {
        const auto b = slice(offset, 2);
        return static_cast<std::uint16_t>(b[0] | (static_cast<std::uint16_t>(b[1]) << 8));
    }
    std::uint32_t u32(std::size_t offset) const {
        const auto b = slice(offset, 4);
        return b[0] | (std::uint32_t{b[1]} << 8) | (std::uint32_t{b[2]} << 16) | (std::uint32_t{b[3]} << 24);
    }
    std::uint64_t u64(std::size_t offset) const {
        return u32(offset) | (std::uint64_t{u32(offset + 4)} << 32);
    }
    std::string string(std::size_t offset, std::size_t size) const {
        const auto b = slice(offset, size);
        return {reinterpret_cast<const char *>(b.data()), b.size()};
    }

  private:
    Bytes bytes_;
    std::string phase_;
};
} // namespace aether::apk
