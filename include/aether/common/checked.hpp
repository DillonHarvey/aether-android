#pragma once
#include <cstddef>
#include <limits>
#include <stdexcept>

namespace aether {
inline std::size_t checked_add(std::size_t left, std::size_t right) {
    if (right > (std::numeric_limits<std::size_t>::max)() - left)
        throw std::overflow_error("Size addition overflow");
    return left + right;
}
inline std::size_t checked_multiply(std::size_t left, std::size_t right) {
    if (left != 0 && right > (std::numeric_limits<std::size_t>::max)() / left)
        throw std::overflow_error("Size multiplication overflow");
    return left * right;
}
inline void require_range(std::size_t offset, std::size_t length, std::size_t total) {
    if (offset > total || length > total - offset)
        throw std::out_of_range("Byte range exceeds input");
}
} // namespace aether
