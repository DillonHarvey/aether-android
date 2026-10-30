#pragma once
#include "aether/dex/image.hpp"
#include <new>
#include <utility>

namespace aether::dex::detail {
// Call from the matching DexError handler, then immediately use bare throw if
// this returns. Optional context must never replace the active original error
// merely because formatting or constructing its decoration ran out of memory.
template<class ErrorContextFormatter>
void throw_dex_error_context(const DexError &error_context_original,
                             ErrorContextFormatter &&error_context_formatter) {
    try {
        throw DexError(error_context_original.code,
                       std::forward<ErrorContextFormatter>(error_context_formatter)()+error_context_original.what());
    } catch(const std::bad_alloc &) {
        return;
    }
}
} // namespace aether::dex::detail
