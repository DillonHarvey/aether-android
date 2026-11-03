#pragma once
#include "aether/apk/inspect.hpp"
#include <functional>

namespace aether::apk {
struct RuntimeBitmap {
    std::uint32_t width = 0, height = 0;
    // Source alpha channel/transparency capability, not premultiplied pixels.
    bool has_alpha = false;
    std::vector<std::uint8_t> rgba;
};
// Host-owned aggregate work debit. The callback must not reenter or yield;
// exceptions propagate unchanged after decoder scratch unwinds. Debit bounded
// attempted stage-byte work before each operation, and each output pixel before
// its conversion. Failed stages retain their debit; no refund or replay occurs.
using RuntimeBitmapWork = std::function<void(std::uint64_t)>;
// Original bounded PNG decoding into straight RGBA8. working_bytes includes
// input.size(), fixed decoder metadata, and all concurrently live buffers.
// The caller separately accounts any unused capacity in its input owner.
// Color-managed, animated and Android nine-patch semantics are unsupported.
// InspectError codes: AETHER_BITMAP_INVALID, _UNSUPPORTED, _LIMIT, or _STATE
// when the trusted caller has not supplied its required accounting callback.
// Host allocation failure propagates as bad_alloc; no fallback image is made.
// The caller separately admits its callback object and returned-value storage.
RuntimeBitmap decode_runtime_png(Bytes input, std::size_t working_bytes,
                                const RuntimeBitmapWork &charge_work);
} // namespace aether::apk
