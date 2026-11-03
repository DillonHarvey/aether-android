#include "aether/apk/runtime_bitmap.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>
#include <miniz.h>
#include <miniz_tinfl.h>

namespace aether::apk {
namespace {
[[noreturn]] void bad(const char *kind, const char *message) {
    throw InspectError(std::string("AETHER_BITMAP_") + kind, "runtime-bitmap", message);
}
std::size_t add(std::size_t a, std::size_t b) {
    if (b > std::numeric_limits<std::size_t>::max() - a)
        bad("LIMIT", "PNG storage extent overflows");
    return a + b;
}
std::size_t multiply(std::size_t a, std::size_t b) {
    if (a && b > std::numeric_limits<std::size_t>::max() / a)
        bad("LIMIT", "PNG storage product overflows");
    return a * b;
}
struct Budget {
    std::size_t limit, used = 0;
    void take(std::size_t bytes) {
        if (bytes > limit - used)
            bad("LIMIT", "PNG decoding exceeds its admitted working bytes");
        used += bytes;
    }
};
std::uint32_t big(Bytes bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4)
        bad("INVALID", "Truncated PNG integer");
    return (std::uint32_t(bytes[offset]) << 24) | (std::uint32_t(bytes[offset + 1]) << 16) |
           (std::uint32_t(bytes[offset + 2]) << 8) | bytes[offset + 3];
}
unsigned paeth(unsigned left, unsigned up, unsigned diagonal) noexcept {
    const auto p = static_cast<int>(left + up) - static_cast<int>(diagonal);
    const auto distance = [](int value) { return value < 0 ? -value : value; };
    const auto a = distance(p - static_cast<int>(left));
    const auto b = distance(p - static_cast<int>(up));
    const auto c = distance(p - static_cast<int>(diagonal));
    return a <= b && a <= c ? left : b <= c ? up : diagonal;
}
struct Pass {
    std::uint32_t x, y, dx, dy, width, height;
    std::size_t row;
};
struct Workspace {
    RuntimeBitmap bitmap;
    unsigned channels = 0, depth = 0, color_type = 0, interlace = 0;
    bool header = false, ended = false, have_data = false, after_data = false;
    bool have_palette = false, have_transparency = false;
    Bytes palette, transparency;
    std::array<Pass, 7> passes{};
    std::size_t pass_count = 0, compressed_size = 0, filtered_size = 0, maximum_row = 0;
    std::unique_ptr<std::uint8_t[]> compressed, filtered, rows;
    tinfl_decompressor inflater;
};
} // namespace

RuntimeBitmap decode_runtime_png(Bytes bytes, std::size_t working_bytes,
                                const RuntimeBitmapWork &charge_work) {
    if (!charge_work)
        bad("STATE", "Runtime PNG decoding requires host-owned work accounting");
    constexpr std::array<std::uint8_t, 8> signature{137, 80, 78, 71, 13, 10, 26, 10};
    if (bytes.size() < signature.size())
        bad("INVALID", "Truncated PNG signature");
    charge_work(signature.size());
    if (!std::equal(signature.begin(), signature.end(), bytes.begin()))
        bad("UNSUPPORTED", "Runtime bitmap source is not PNG");
    if (bytes.size() < 45)
        bad("INVALID", "PNG is too short for its required chunks");
    Budget budget{working_bytes};
    budget.take(bytes.size());
    budget.take(sizeof(Workspace));
    budget.take(sizeof(Budget) + sizeof(Bytes));
    Workspace state;
    // Each validated chunk advances by at least twelve bytes. No arbitrary
    // chunk-count allowance or dynamically growing chunk inventory is needed.
    for (std::size_t at = 8; at < bytes.size();) {
        if (bytes.size() - at < 12)
            bad("INVALID", "Truncated PNG chunk");
        charge_work(12); // One complete chunk-envelope visit.
        const auto length = big(bytes, at);
        if (length > static_cast<std::uint32_t>(INT32_MAX))
            bad("INVALID", "PNG chunk length exceeds the format's signed range");
        if (length > bytes.size() - at - 12)
            bad("INVALID", "PNG chunk exceeds the input extent");
        const std::string_view type(reinterpret_cast<const char *>(bytes.data() + at + 4), 4);
        if (!std::all_of(type.begin(), type.end(), [](char c) {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            }) || (type[2] >= 'a' && type[2] <= 'z'))
            bad("INVALID", "Invalid PNG chunk type");
        charge_work(static_cast<std::uint64_t>(length) + 4); // CRC's actual input.
        if (mz_crc32(0, bytes.data() + at + 4, static_cast<std::size_t>(length) + 4) !=
            big(bytes, at + 8 + length))
            bad("INVALID", "PNG chunk CRC mismatch");
        const auto data = bytes.subspan(at + 8, length);
        if (type == "IHDR") {
            if (state.header || at != 8 || length != 13)
                bad("INVALID", "Invalid or repeated PNG header");
            charge_work(8); // Dimensions, separately from their CRC.
            state.bitmap.width = big(data, 0);
            state.bitmap.height = big(data, 4);
            if (!state.bitmap.width || !state.bitmap.height)
                bad("INVALID", "PNG dimensions must be nonzero");
            if (state.bitmap.width > static_cast<std::uint32_t>(INT32_MAX) ||
                state.bitmap.height > static_cast<std::uint32_t>(INT32_MAX))
                bad("LIMIT", "PNG dimensions exceed Java bitmap representation");
            charge_work(5); // The remaining image-format fields.
            state.depth = data[8];
            state.color_type = data[9];
            state.interlace = data[12];
            if (data[10] || data[11] || state.interlace > 1 ||
                (state.depth != 1 && state.depth != 2 && state.depth != 4 && state.depth != 8 && state.depth != 16) ||
                (state.color_type != 0 && state.color_type != 2 && state.color_type != 3 &&
                 state.color_type != 4 && state.color_type != 6) ||
                (state.color_type == 3 && state.depth == 16) ||
                (state.color_type != 0 && state.color_type != 3 && state.depth < 8))
                bad("INVALID", "Invalid PNG color model, depth, compression or interlace");
            state.channels = state.color_type == 6 ? 4u : state.color_type == 2 ? 3u : state.color_type == 4 ? 2u : 1u;
            state.header = true;
        } else if (!state.header) {
            bad("INVALID", "PNG image header is missing");
        } else if (type == "IDAT") {
            if (state.after_data)
                bad("INVALID", "PNG data chunks are not contiguous");
            if (state.color_type == 3 && !state.have_palette)
                bad("INVALID", "Indexed PNG has no palette");
            state.compressed_size = add(state.compressed_size, length);
            state.have_data = true;
        } else if (type == "IEND") {
            if (length || !state.have_data || at + 12 != bytes.size())
                bad("INVALID", "Invalid PNG end chunk or trailing input");
            state.ended = true;
        } else {
            state.after_data = state.have_data;
            if (type == "acTL" || type == "fcTL" || type == "fdAT" ||
                type == "iCCP" || type == "gAMA" || type == "cHRM" || type == "sRGB" ||
                type == "npTc" || type == "npLb" || type == "npOl" ||
                (type[0] >= 'A' && type[0] <= 'Z' && type != "PLTE"))
                bad("UNSUPPORTED", "PNG requires unsupported animation, color-management or metadata semantics");
            if (type == "PLTE") {
                if (state.have_palette || state.have_data || state.have_transparency || !length ||
                    length > 768 || length % 3 || state.color_type == 0 || state.color_type == 4 ||
                    (state.color_type == 3 && length / 3 > (1u << state.depth)))
                    bad("INVALID", "Invalid or repeated PNG palette");
                state.have_palette = true;
                state.palette = data;
            } else if (type == "tRNS") {
                if (state.have_transparency || state.have_data ||
                    (state.color_type == 0 ? length != 2 : state.color_type == 2 ? length != 6 :
                     state.color_type == 3 ? (!state.have_palette || !length || length > state.palette.size() / 3) : true))
                    bad("INVALID", "Invalid PNG transparency chunk");
                state.have_transparency = true;
                state.transparency = data;
                if (state.color_type != 3) {
                    for (std::size_t i = 0; i < data.size(); i += 2) {
                        charge_work(2); // The exact transparent sample being checked.
                        if ((unsigned(data[i]) * 256 + data[i + 1]) >= (1u << state.depth))
                            bad("INVALID", "PNG transparent sample exceeds its bit depth");
                    }
                }
            }
        }
        at += static_cast<std::size_t>(length) + 12;
    }
    if (!state.ended || !state.compressed_size)
        bad("INVALID", "PNG is incomplete");
    constexpr unsigned adam7[7][4]{{0, 0, 8, 8}, {4, 0, 8, 8}, {0, 4, 4, 8}, {2, 0, 4, 4},
                                  {0, 2, 2, 4}, {1, 0, 2, 2}, {0, 1, 1, 2}};
    for (unsigned n = 0; n < (state.interlace ? 7u : 1u); ++n) {
        charge_work(1); // One actual pass-shape preparation, including empty passes.
        const auto x = state.interlace ? adam7[n][0] : 0u, y = state.interlace ? adam7[n][1] : 0u;
        const auto dx = state.interlace ? adam7[n][2] : 1u, dy = state.interlace ? adam7[n][3] : 1u;
        const auto width = state.bitmap.width > x ? (state.bitmap.width - x - 1) / dx + 1 : 0;
        const auto height = state.bitmap.height > y ? (state.bitmap.height - y - 1) / dy + 1 : 0;
        if (!width || !height) continue;
        const auto bits = multiply(multiply(width, state.channels), state.depth);
        const auto row = add(bits, 7) / 8;
        state.passes[state.pass_count++] = {x, y, dx, dy, width, height, row};
        state.filtered_size = add(state.filtered_size, multiply(add(row, 1), height));
        state.maximum_row = std::max(state.maximum_row, row);
    }
    const auto output_size = multiply(multiply(state.bitmap.width, state.bitmap.height), 4);
    const auto scratch_size = multiply(state.maximum_row, 2);
    if (output_size > state.bitmap.rgba.max_size())
        bad("LIMIT", "PNG output exceeds the host byte-vector representation");
    budget.take(state.compressed_size);
    budget.take(state.filtered_size);
    budget.take(output_size);
    budget.take(scratch_size);
    // Count construction avoids geometric growth and a second RGBA publication
    // buffer. The returned vector is moved, never copied from another image.
    charge_work(output_size); // Admit value-initialization before any output-byte writes.
    state.bitmap.rgba = std::vector<std::uint8_t>(output_size);
    budget.take(state.bitmap.rgba.capacity() - output_size);
    state.compressed.reset(new std::uint8_t[state.compressed_size]);
    state.filtered.reset(new std::uint8_t[state.filtered_size]);
    state.rows.reset(new std::uint8_t[scratch_size]);
    std::size_t copied = 0;
    for (std::size_t at = 8; at < bytes.size();) {
        charge_work(8); // Length and type revisited while gathering IDAT data.
        const auto length = big(bytes, at);
        if (std::memcmp(bytes.data() + at + 4, "IDAT", 4) == 0) {
            charge_work(length);
            std::copy_n(bytes.data() + at + 8, length, state.compressed.get() + copied);
            copied += length;
        }
        at += static_cast<std::size_t>(length) + 12;
    }
    tinfl_init(&state.inflater);
    auto input_size = state.compressed_size, decoded_size = state.filtered_size;
    // Admit this bounded attempt before entering the synchronous inflater. A
    // malformed stream may stop early; the attempted stage retains its debit.
    charge_work(add(input_size, decoded_size));
    const auto status = tinfl_decompress(&state.inflater, state.compressed.get(), &input_size,
        state.filtered.get(), state.filtered.get(), &decoded_size,
        TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (status != TINFL_STATUS_DONE || input_size != state.compressed_size || decoded_size != state.filtered_size)
        bad("INVALID", "PNG deflate stream has an invalid size, checksum or trailing input");
    std::size_t filtered_at = 0;
    for (std::size_t p = 0; p < state.pass_count; ++p) {
        const auto &pass = state.passes[p];
        auto *current = state.rows.get();
        auto *previous = current + pass.row;
        const auto distance = std::max(1u, (state.channels * state.depth + 7) / 8);
        for (std::uint32_t y = 0; y < pass.height; ++y) {
            charge_work(1); // The actual filter selector, even when invalid.
            const auto filter = state.filtered[filtered_at++];
            if (filter > 4) bad("INVALID", "Unknown PNG scanline filter");
            charge_work(pass.row); // Every byte of this validated row is visited.
            for (std::size_t x = 0; x < pass.row; ++x) {
                const auto left = x >= distance ? current[x - distance] : 0u;
                const auto up = y ? previous[x] : 0u;
                const auto diagonal = y && x >= distance ? previous[x - distance] : 0u;
                const auto prediction = filter == 1 ? left : filter == 2 ? up :
                    filter == 3 ? (left + up) / 2 : filter == 4 ? paeth(left, up, diagonal) : 0u;
                current[x] = static_cast<std::uint8_t>(state.filtered[filtered_at++] + prediction);
            }
            const auto sample = [&](std::size_t n) -> unsigned {
                const auto bit = n * state.depth;
                const auto offset = bit / 8;
                if (state.depth == 16) return unsigned(current[offset]) * 256 + current[offset + 1];
                return (current[offset] >> (8 - state.depth - bit % 8)) & ((1u << state.depth) - 1);
            };
            const auto maximum = (1u << state.depth) - 1;
            const auto scaled = [&](unsigned value) {
                return static_cast<std::uint8_t>((value * 255 + maximum / 2) / maximum);
            };
            for (std::uint32_t x = 0; x < pass.width; ++x) {
                charge_work(1); // Admit this real pixel before reading or writing it.
                const auto start = std::size_t(x) * state.channels;
                const auto output_y = pass.y + std::size_t(y) * pass.dy;
                const auto output_x = pass.x + std::size_t(x) * pass.dx;
                auto *out = state.bitmap.rgba.data() + (output_y * state.bitmap.width + output_x) * 4;
                out[3] = 255;
                if (state.color_type == 3) {
                    const auto index = sample(start);
                    if (index >= state.palette.size() / 3)
                        bad("INVALID", "PNG palette index exceeds its palette");
                    std::copy_n(state.palette.data() + index * 3, 3, out);
                    if (index < state.transparency.size()) out[3] = state.transparency[index];
                } else {
                    const bool gray = state.color_type == 0 || state.color_type == 4;
                    for (unsigned c = 0; c < 3; ++c) out[c] = scaled(sample(start + (gray ? 0 : c)));
                    if (state.color_type == 4 || state.color_type == 6)
                        out[3] = scaled(sample(start + state.channels - 1));
                    else if (state.have_transparency) {
                        bool transparent = true;
                        for (unsigned c = 0; c < (gray ? 1u : 3u); ++c)
                            transparent = transparent && sample(start + c) ==
                                unsigned(state.transparency[c * 2]) * 256 + state.transparency[c * 2 + 1];
                        if (transparent) out[3] = 0;
                    }
                }
            }
            std::swap(current, previous);
        }
    }
    state.bitmap.has_alpha = state.color_type == 4 || state.color_type == 6 || state.have_transparency;
    return std::move(state.bitmap);
}
} // namespace aether::apk
