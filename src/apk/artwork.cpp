#include "aether/apk/artwork.hpp"
#include "aether/apk/archive.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/package.hpp"
#include "aether/apk/resources.hpp"
#include "aether/common/text.hpp"
#include "drawable.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <miniz.h>

namespace aether::apk {
namespace {
[[noreturn]] void bad(const char *message, const char *kind = "INVALID") {
    throw InspectError(std::string("AETHER_ICON_") + kind, "apk-artwork", message);
}
std::uint32_t big(Bytes bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4)
        bad("Truncated PNG integer");
    return (std::uint32_t(bytes[offset]) << 24) | (std::uint32_t(bytes[offset + 1]) << 16) |
           (std::uint32_t(bytes[offset + 2]) << 8) | bytes[offset + 3];
}
void little(std::vector<std::uint8_t> &out, std::uint32_t value, unsigned width = 4) {
    for (unsigned i = 0; i < width; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
unsigned paeth(unsigned left, unsigned up, unsigned diagonal) {
    const auto p = static_cast<int>(left + up) - static_cast<int>(diagonal);
    const auto a = std::abs(p - static_cast<int>(left)), b = std::abs(p - static_cast<int>(up));
    const auto c = std::abs(p - static_cast<int>(diagonal));
    return a <= b && a <= c ? left : b <= c ? up : diagonal;
}
bool safe_entry(std::string_view path) {
    if (!path.starts_with("res/") || !path.ends_with(".png") || path.size() > 256)
        return false;
    for (std::size_t at = 0; at < path.size();) {
        const auto end = path.find('/', at);
        const auto part = path.substr(at, end == std::string_view::npos ? path.size() - at : end - at);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ')
            return false;
        if (end == std::string_view::npos)
            break;
        at = end + 1;
    }
    return std::all_of(path.begin(), path.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' ||
               c == '_' || c == '-' || c == '.';
    });
}
std::array<std::uint8_t, 4> resample(const IconBitmap &bitmap, unsigned x, unsigned y, unsigned width,
                                     unsigned height) {
    std::array<double, 4> sum{};
    double total = 0;
    const auto add = [&](unsigned sx, unsigned sy, double weight) {
        const auto *p = &bitmap.rgba[(std::size_t(sy) * bitmap.width + sx) * 4];
        for (unsigned c = 0; c < 3; ++c)
            sum[c] += weight * p[c] * p[3];
        sum[3] += weight * p[3];
        total += weight;
    };
    if (width > bitmap.width || height > bitmap.height) {
        const double sx = (x + .5) * bitmap.width / width - .5, sy = (y + .5) * bitmap.height / height - .5;
        const auto ix = static_cast<int>(std::floor(sx)), iy = static_cast<int>(std::floor(sy));
        for (int dy = 0; dy < 2; ++dy)
            for (int dx = 0; dx < 2; ++dx)
                add(static_cast<unsigned>(std::clamp(ix + dx, 0, static_cast<int>(bitmap.width) - 1)),
                    static_cast<unsigned>(std::clamp(iy + dy, 0, static_cast<int>(bitmap.height) - 1)),
                    (dx ? sx - ix : 1 - sx + ix) * (dy ? sy - iy : 1 - sy + iy));
    } else {
        const double left = double(x) * bitmap.width / width, right = double(x + 1) * bitmap.width / width;
        const double top = double(y) * bitmap.height / height,
                     bottom = double(y + 1) * bitmap.height / height;
        for (auto sy = static_cast<unsigned>(top); sy < static_cast<unsigned>(std::ceil(bottom)); ++sy)
            for (auto sx = static_cast<unsigned>(left); sx < static_cast<unsigned>(std::ceil(right)); ++sx)
                add(sx, sy,
                    (std::min(right, sx + 1.) - std::max(left, double(sx))) *
                        (std::min(bottom, sy + 1.) - std::max(top, double(sy))));
    }
    const auto color = [&](unsigned c) {
        return static_cast<std::uint8_t>(std::clamp(std::round(sum[3] ? sum[c] / sum[3] : 0.), 0., 255.));
    };
    return {color(2), color(1), color(0),
            static_cast<std::uint8_t>(std::clamp(std::round(sum[3] / total), 0., 255.))};
}
std::string bounded_utf8(const std::wstring &text, std::size_t maximum) {
    std::wstring chosen;
    for (std::size_t at = 0; at < text.size(); ++at) {
        auto next = chosen + text[at];
        if (text[at] >= 0xd800 && text[at] <= 0xdbff) {
            if (at + 1 >= text.size())
                break;
            next += text[++at];
        }
        if (utf8(next).size() > maximum)
            break;
        chosen = std::move(next);
    }
    return utf8(chosen);
}
} // namespace

IconBitmap decode_icon_png(Bytes bytes, bool expanded) {
    constexpr std::array<std::uint8_t, 8> signature{137, 80, 78, 71, 13, 10, 26, 10};
    if (bytes.size() < 45 || bytes.size() > 1024 * 1024)
        bad("PNG icon must be between 45 bytes and 1 MiB", "LIMIT");
    if (!std::equal(signature.begin(), signature.end(), bytes.begin()))
        bad("Icon is not a PNG image", "UNSUPPORTED");
    IconBitmap result;
    unsigned channels = 0, depth = 0, color_type = 0, interlace = 0;
    bool header = false, ended = false, have_data = false, after_data = false, palette = false;
    bool have_transparency = false;
    std::vector<std::uint8_t> compressed, colors, transparency;
    std::size_t chunks = 0;
    for (std::size_t at = 8; at < bytes.size();) {
        if (++chunks > 256)
            bad("PNG chunk count exceeds 256", "LIMIT");
        if (bytes.size() - at < 12)
            bad("Truncated PNG chunk");
        const auto length = big(bytes, at);
        if (length > bytes.size() - at - 12)
            bad("PNG chunk exceeds input");
        const std::string_view type(reinterpret_cast<const char *>(bytes.data() + at + 4), 4);
        if (!std::all_of(type.begin(), type.end(),
                         [](char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }) ||
            (type[2] >= 'a' && type[2] <= 'z'))
            bad("Invalid PNG chunk type");
        if (mz_crc32(0, bytes.data() + at + 4, static_cast<std::size_t>(length) + 4) !=
            big(bytes, at + 8 + length))
            bad("PNG chunk CRC mismatch");
        const auto data = bytes.subspan(at + 8, length);
        if (type == "IHDR") {
            if (header || at != 8 || length != 13)
                bad("Invalid or repeated PNG header");
            result.width = big(data, 0);
            result.height = big(data, 4);
            if (!result.width || !result.height || result.width > 512 || result.height > 512)
                bad("PNG icon dimensions must be 1 through 512", "LIMIT");
            if (!expanded &&
                (data[8] != 8 || (data[9] != 2 && data[9] != 6) || data[10] || data[11] || data[12]))
                bad("Only noninterlaced RGB/RGBA 8-bit PNG icons are supported", "UNSUPPORTED");
            depth = data[8];
            color_type = data[9];
            interlace = data[12];
            if (data[10] || data[11] || interlace > 1 ||
                (depth != 1 && depth != 2 && depth != 4 && depth != 8 && depth != 16) ||
                (color_type != 0 && color_type != 2 && color_type != 3 && color_type != 4 &&
                 color_type != 6) ||
                (color_type == 3 && depth == 16) || (color_type != 0 && color_type != 3 && depth < 8))
                bad("Invalid PNG color model, depth, compression or interlace");
            channels = color_type == 6 ? 4 : color_type == 2 ? 3 : color_type == 4 ? 2 : 1;
            header = true;
        } else if (!header)
            bad("PNG image header is missing");
        else if (type == "IDAT") {
            if (after_data)
                bad("PNG data chunks are not contiguous");
            if (color_type == 3 && !palette)
                bad("Indexed PNG is missing its palette");
            compressed.insert(compressed.end(), data.begin(), data.end());
            have_data = true;
        } else if (type == "IEND") {
            if (length || !have_data || at + 12 != bytes.size())
                bad("Invalid PNG end chunk or trailing input");
            ended = true;
        } else {
            after_data = have_data;
            // Color profiles do not affect the bounded RGBA output. Animation is
            // deliberately unsupported rather than rendering an arbitrary frame.
            if ((!expanded && type == "tRNS") || type == "acTL" || type == "fcTL" || type == "fdAT" ||
                (type[0] >= 'A' && type[0] <= 'Z' && type != "PLTE"))
                bad("PNG icon uses an unsupported image feature", "UNSUPPORTED");
            if (type == "PLTE") {
                if (palette || have_data || have_transparency || !length || length > 768 || length % 3 ||
                    color_type == 0 || color_type == 4 || (color_type == 3 && length / 3 > (1u << depth)))
                    bad("Invalid or repeated optional PNG palette");
                palette = true;
                colors.assign(data.begin(), data.end());
            } else if (type == "tRNS") {
                if (have_transparency || have_data ||
                    (color_type == 0   ? length != 2
                     : color_type == 2 ? length != 6
                     : color_type == 3 ? (!palette || !length || length > colors.size() / 3)
                                       : true))
                    bad("Invalid PNG transparency chunk");
                have_transparency = true;
                transparency.assign(data.begin(), data.end());
                if (color_type != 3)
                    for (std::size_t i = 0; i < transparency.size(); i += 2)
                        if ((unsigned(transparency[i]) * 256 + transparency[i + 1]) >= (1u << depth))
                            bad("PNG transparent sample exceeds the bit depth");
            }
        }
        at += static_cast<std::size_t>(length) + 12;
    }
    if (!ended || compressed.empty())
        bad("PNG is incomplete");
    struct Pass {
        unsigned x, y, dx, dy, width, height;
    };
    constexpr unsigned adam7[7][4]{{0, 0, 8, 8}, {4, 0, 8, 8}, {0, 4, 4, 8}, {2, 0, 4, 4},
                                   {0, 2, 2, 4}, {1, 0, 2, 2}, {0, 1, 1, 2}};
    std::vector<Pass> passes;
    std::size_t expected = 0;
    for (unsigned n = 0; n < (interlace ? 7u : 1u); ++n) {
        const auto x = interlace ? adam7[n][0] : 0, y = interlace ? adam7[n][1] : 0;
        const auto dx = interlace ? adam7[n][2] : 1, dy = interlace ? adam7[n][3] : 1;
        const auto w = result.width > x ? (result.width - x + dx - 1) / dx : 0;
        const auto h = result.height > y ? (result.height - y + dy - 1) / dy : 0;
        if (w && h) {
            passes.push_back({x, y, dx, dy, w, h});
            expected += ((std::size_t(w) * channels * depth + 7) / 8 + 1) * h;
        }
    }
    std::vector<std::uint8_t> filtered(expected);
    auto output_size = static_cast<mz_ulong>(filtered.size());
    auto input_size = static_cast<mz_ulong>(compressed.size());
    if (mz_uncompress2(filtered.data(), &output_size, compressed.data(), &input_size) != MZ_OK ||
        output_size != filtered.size() || input_size != compressed.size())
        bad("PNG deflate stream has an invalid size, checksum or trailing input");
    result.rgba.resize(std::size_t(result.width) * result.height * 4);
    std::size_t at = 0;
    for (const auto &pass : passes) {
        const auto row = (std::size_t(pass.width) * channels * depth + 7) / 8;
        const auto distance = std::max(1u, (channels * depth + 7) / 8);
        std::vector<std::uint8_t> pixels(row * pass.height);
        for (std::size_t y = 0; y < pass.height; ++y) {
            const auto filter = filtered[at++];
            if (filter > 4)
                bad("Unknown PNG scanline filter");
            for (std::size_t x = 0; x < row; ++x) {
                const auto left = x >= distance ? pixels[y * row + x - distance] : 0u;
                const auto up = y ? pixels[(y - 1) * row + x] : 0u;
                const auto diagonal = y && x >= distance ? pixels[(y - 1) * row + x - distance] : 0u;
                const auto prediction = filter == 1   ? left
                                        : filter == 2 ? up
                                        : filter == 3 ? (left + up) / 2
                                        : filter == 4 ? paeth(left, up, diagonal)
                                                      : 0u;
                pixels[y * row + x] = static_cast<std::uint8_t>(filtered[at++] + prediction);
            }
            const auto sample = [&](std::size_t n) -> unsigned {
                const auto offset = y * row + n * depth / 8;
                if (depth == 16)
                    return unsigned(pixels[offset]) * 256 + pixels[offset + 1];
                return (pixels[offset] >> (8 - depth - n * depth % 8)) & ((1u << depth) - 1);
            };
            const auto maximum = (1u << depth) - 1;
            const auto scaled = [&](unsigned v) {
                return static_cast<std::uint8_t>((v * 255 + maximum / 2) / maximum);
            };
            for (unsigned x = 0; x < pass.width; ++x) {
                const auto start = std::size_t(x) * channels;
                auto *out = &result.rgba[((pass.y + y * pass.dy) * result.width + pass.x + x * pass.dx) * 4];
                out[3] = 255;
                if (color_type == 3) {
                    const auto index = sample(start);
                    if (index >= colors.size() / 3)
                        bad("PNG palette index exceeds its palette");
                    std::copy_n(colors.data() + index * 3, 3, out);
                    if (index < transparency.size())
                        out[3] = transparency[index];
                } else {
                    const bool gray = color_type == 0 || color_type == 4;
                    for (unsigned c = 0; c < 3; ++c)
                        out[c] = scaled(sample(start + (gray ? 0 : c)));
                    if (color_type == 4 || color_type == 6)
                        out[3] = scaled(sample(start + channels - 1));
                    else if (have_transparency) {
                        bool transparent = true;
                        for (unsigned c = 0; c < (gray ? 1u : 3u); ++c)
                            transparent &= sample(start + c) ==
                                           unsigned(transparency[c * 2]) * 256 + transparency[c * 2 + 1];
                        if (transparent)
                            out[3] = 0;
                    }
                }
            }
        }
    }
    return result;
}

std::string clean_display_name(std::string_view value, std::string_view fallback) {
    std::wstring clean;
    for (const auto c : utf16(value)) {
        if ((c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c == 0x200e || c == 0x200f ||
            c == 0x061c)
            continue;
        const auto printable = c < 32 || (c >= 0x7f && c <= 0x9f) || c == 0x2028 || c == 0x2029 ? L' ' : c;
        if (printable != L' ' || (!clean.empty() && clean.back() != L' '))
            clean += printable;
    }
    while (!clean.empty() && clean.back() == L' ')
        clean.pop_back();
    const auto result = bounded_utf8(clean, 128);
    return result.empty() ? std::string(fallback) : result;
}
std::string shortcut_stem(std::string_view name) {
    auto value = utf16(clean_display_name(name, "Aether app"));
    for (auto &c : value)
        if (std::wstring_view(L"<>:\"/\\|?*").find(c) != std::wstring_view::npos)
            c = L'_';
    auto bounded = utf16(bounded_utf8(value, 80));
    while (!bounded.empty() && (bounded.back() == L'.' || bounded.back() == L' '))
        bounded.pop_back();
    if (bounded.empty() || bounded.front() == L'.')
        bounded = L"App " + bounded;
    auto device = bounded.substr(0, bounded.find(L'.'));
    while (!device.empty() && device.back() == L' ')
        device.pop_back();
    std::transform(device.begin(), device.end(), device.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(c >= L'a' && c <= L'z' ? c - L'a' + L'A' : c);
    });
    if (device == L"CON" || device == L"PRN" || device == L"AUX" || device == L"NUL" ||
        (device.size() == 4 && (device.starts_with(L"COM") || device.starts_with(L"LPT")) &&
         ((device[3] >= L'0' && device[3] <= L'9') || device[3] == 0xb9 || device[3] == 0xb2 ||
          device[3] == 0xb3)))
        bounded = L"App " + bounded;
    return utf8(bounded);
}

IconBitmap fallback_icon() {
    static const IconBitmap original = [] {
        IconBitmap bitmap{256, 256, std::vector<std::uint8_t>(256 * 256 * 4)};
        // Original geometric Aether mark. Four coverage samples per pixel keep
        // the orbital arc and rounded tile smooth; no artwork or font is imported.
        for (unsigned y = 0; y < 256; ++y)
            for (unsigned x = 0; x < 256; ++x) {
                std::array<unsigned, 4> sum{};
                for (unsigned sample = 0; sample < 4; ++sample) {
                    const double px = (x + (sample % 2 + 0.5) / 2) / 4;
                    const double py = (y + (sample / 2 + 0.5) / 2) / 4;
                    const auto dx = std::max(0.0, std::abs(px - 32) - 19);
                    const auto dy = std::max(0.0, std::abs(py - 32) - 19);
                    if (dx * dx + dy * dy > 121)
                        continue;
                    std::array<unsigned, 3> color{18, 35, 55};
                    const auto radius2 = (px - 32) * (px - 32) + (py - 32) * (py - 32);
                    if (radius2 >= 529 && radius2 < 676 && !(px < 26 && py > 34))
                        color = {43, 209, 204};
                    if (py >= 15 && py <= 49) {
                        const auto half = (py - 15) * 0.42, distance = std::abs(px - 32);
                        if (distance <= half && (distance >= half - 5 || (py >= 36 && py <= 41)))
                            color = {237, 249, 255};
                    }
                    for (unsigned channel = 0; channel < 3; ++channel)
                        sum[channel] += color[channel];
                    ++sum[3];
                }
                const auto at = (y * 256 + x) * 4;
                if (sum[3]) {
                    for (unsigned channel = 0; channel < 3; ++channel)
                        bitmap.rgba[at + channel] = static_cast<std::uint8_t>(sum[channel] / sum[3]);
                    bitmap.rgba[at + 3] = static_cast<std::uint8_t>((sum[3] * 255 + 2) / 4);
                }
            }
        return bitmap;
    }();
    return original;
}
std::vector<std::uint8_t> icon_file(const IconBitmap &bitmap, std::uint32_t renderer_version) {
    if (!bitmap.width || !bitmap.height || bitmap.width > 512 || bitmap.height > 512 ||
        bitmap.rgba.size() != std::size_t(bitmap.width) * bitmap.height * 4)
        bad("Invalid icon bitmap dimensions");
    constexpr std::array<unsigned, 4> legacy_sizes{16, 32, 48, 256};
    constexpr std::array<unsigned, 7> current_sizes{16, 24, 32, 48, 64, 128, 256};
    if (renderer_version != 1 && renderer_version != 2)
        bad("Unknown icon renderer version", "UNSUPPORTED");
    const auto sizes = renderer_version == 1 ? std::span<const unsigned>(legacy_sizes)
                                             : std::span<const unsigned>(current_sizes);
    std::vector<std::uint8_t> out;
    little(out, 0, 2);
    little(out, 1, 2);
    little(out, static_cast<unsigned>(sizes.size()), 2);
    std::uint32_t offset = 6 + static_cast<std::uint32_t>(sizes.size()) * 16;
    for (auto size : sizes) {
        const auto bytes = 40 + size * size * 4 + ((size + 31) / 32) * 4 * size;
        out.insert(out.end(), {static_cast<std::uint8_t>(size), static_cast<std::uint8_t>(size), 0, 0});
        little(out, 1, 2);
        little(out, 32, 2);
        little(out, bytes);
        little(out, offset);
        offset += bytes;
    }
    for (auto size : sizes) {
        little(out, 40);
        little(out, size);
        little(out, size * 2);
        little(out, 1, 2);
        little(out, 32, 2);
        little(out, 0);
        little(out, size * size * 4);
        for (unsigned i = 0; i < 4; ++i)
            little(out, 0);
        const auto extent = std::max(bitmap.width, bitmap.height);
        const auto width = std::max(1u, bitmap.width * size / extent);
        const auto height = std::max(1u, bitmap.height * size / extent);
        for (unsigned row = 0; row < size; ++row)
            for (unsigned x = 0; x < size; ++x) {
                const auto y = size - row - 1;
                if (x < (size - width) / 2 || x >= (size - width) / 2 + width || y < (size - height) / 2 ||
                    y >= (size - height) / 2 + height) {
                    out.insert(out.end(), 4, 0);
                    continue;
                }
                if (renderer_version == 2) {
                    const auto pixel =
                        resample(bitmap, x - (size - width) / 2, y - (size - height) / 2, width, height);
                    out.insert(out.end(), pixel.begin(), pixel.end());
                    continue;
                }
                const auto left = (x - (size - width) / 2) * bitmap.width / width;
                const auto top = (y - (size - height) / 2) * bitmap.height / height;
                const auto right = std::max(left + 1, (x - (size - width) / 2 + 1) * bitmap.width / width);
                const auto bottom = std::max(top + 1, (y - (size - height) / 2 + 1) * bitmap.height / height);
                std::array<std::uint64_t, 4> sum{};
                for (auto sy = top; sy < bottom; ++sy)
                    for (auto sx = left; sx < right; ++sx) {
                        const auto at = (std::size_t(sy) * bitmap.width + sx) * 4;
                        const auto alpha = bitmap.rgba[at + 3];
                        for (unsigned channel = 0; channel < 3; ++channel)
                            sum[channel] += std::uint64_t(bitmap.rgba[at + channel]) * alpha;
                        sum[3] += alpha;
                    }
                const auto count = (right - left) * (bottom - top);
                const auto color = [&](unsigned channel) {
                    return static_cast<std::uint8_t>(sum[3] ? (sum[channel] + sum[3] / 2) / sum[3] : 0);
                };
                out.insert(out.end(), {color(2), color(1), color(0),
                                       static_cast<std::uint8_t>((sum[3] + count / 2) / count)});
            }
        const auto pixels = out.size() - size * size * 4;
        const auto mask = out.size();
        const auto stride = ((size + 31) / 32) * 4;
        out.insert(out.end(), stride * size, 0);
        for (unsigned row = 0; row < size; ++row)
            for (unsigned x = 0; x < size; ++x)
                if (!out[pixels + (row * size + x) * 4 + 3])
                    out[mask + row * stride + x / 8] |= static_cast<std::uint8_t>(0x80u >> (x % 8));
    }
    return out;
}

Artwork artwork(Bytes package, const ManifestInfo &manifest) {
    try {
        return artwork(open_package(package), manifest);
    } catch (const InspectError &error) {
        Artwork result;
        result.label = clean_display_name(manifest.package_id, "Aether app");
        result.bitmap = fallback_icon();
        result.icon_status = "invalid";
        result.icon_error = error.diagnostic.code;
        result.diagnostics.push_back(error.diagnostic.code + ": " + error.what());
        return result;
    }
}
Artwork artwork(const PackageView &package, const ManifestInfo &manifest, std::string_view launcher_container,
                const ArtworkOptions &options) {
    Artwork result;
    result.renderer_version = options.modern ? 2 : 1;
    result.label = clean_display_name(manifest.package_id, "Aether app");
    result.bitmap = fallback_icon();
    auto label = manifest.label, icon = manifest.icon;
    auto icon_container = package.parts.empty() ? std::string_view{} : package.parts.front().path;
    std::string label_owner = "application", icon_owner = "application";
    const auto selection = select_launcher(manifest);
    const auto *launcher = selection.activity ? &manifest.activities[*selection.activity] : nullptr;
    if (options.modern && selection.status == LauncherStatus::ambiguous) {
        // Presentation has a deterministic choice without changing the stricter
        // execution requirement for one unambiguous launcher.
        for (const auto &candidate : manifest.activities)
            if (candidate.launcher && (candidate.enabled.type != 0x12 || candidate.enabled.data) &&
                (candidate.exported.type != 0x12 || candidate.exported.data) &&
                (!launcher || candidate.name < launcher->name))
                launcher = &candidate;
        result.diagnostics.push_back("Multiple launchers: presentation selects the first eligible component "
                                     "by name; execution selection is unchanged.");
    }
    if (!launcher && selection.declared)
        result.diagnostics.push_back(selection.reason + " Using application presentation.");
    if (launcher) {
        if (launcher->label.type) {
            label = launcher->label;
            label_owner = "launcher";
        }
        if (launcher->icon.type) {
            icon = launcher->icon;
            icon_owner = "launcher";
            if (!launcher_container.empty())
                icon_container = launcher_container;
        }
    }
    try {
        std::optional<ResourceTable> resources;
        auto resolve = [&](const DisplayValue &value) {
            if (value.type == 3)
                return value.literal;
            if (value.type != 1 || !value.reference)
                throw InspectError("AETHER_ARTWORK_UNSUPPORTED", "apk-artwork",
                                   "Unsupported presentation attribute type");
            if (!resources) {
                const ResourceConfiguration selection{
                    static_cast<std::uint16_t>(
                        std::clamp(std::max(options.size_px * 160 / 48, options.dpi * 160 / 96), 1u, 65533u)),
                    options.sdk};
                resources = ResourceTable::compose(
                    package, manifest.package_id, options.modern ? &selection : nullptr,
                    {options.metadata_preview ? ResourceNamePolicy::compiled : ResourceNamePolicy::legacy,
                     false, options.metadata_preview});
                if (resources->package_name().empty())
                    throw InspectError("AETHER_ARTWORK_RESOURCE", "apk-artwork",
                                       "No supported bounded resource table is available");
            }
            if (resources->package_name() != manifest.package_id)
                throw InspectError("AETHER_ARTWORK_RESOURCE", "apk-artwork",
                                   "Resource package identity differs from manifest");
            const auto text = resources->text(value.reference);
            return utf8(std::wstring(text.begin(), text.end()));
        };
        if (label.type) {
            try {
                const auto raw = resolve(label);
                const auto clean = clean_display_name(raw, "");
                if (!clean.empty())
                    result.label = clean;
                result.label_source = clean.empty()
                                          ? "package-fallback"
                                          : label_owner + (label.type == 3 ? "-literal" : "-resource");
                if (result.label != raw)
                    result.diagnostics.push_back(
                        "Label controls, whitespace or length were normalized for Windows display.");
            } catch (const InspectError &error) {
                result.diagnostics.push_back(error.diagnostic.code + ": " + error.what());
            }
        }
        if (options.modern) {
            const auto attempt = [&](const DisplayValue &candidate, std::string_view owner,
                                     std::string_view origin, std::uint16_t sdk) {
                if (!candidate.type)
                    return false;
                try {
                    const ResourceConfiguration configuration{
                        static_cast<std::uint16_t>(std::clamp(
                            std::max(options.size_px * 160 / 48, options.dpi * 160 / 96), 1u, 65533u)),
                        sdk};
                    std::optional<ResourceTable> alternative;
                    auto &selected = options.metadata_preview && sdk == options.sdk ? resources : alternative;
                    if (!selected)
                        selected =
                            ResourceTable::compose(package, manifest.package_id, &configuration,
                                                   {options.metadata_preview ? ResourceNamePolicy::compiled
                                                                             : ResourceNamePolicy::legacy,
                                                    false, options.metadata_preview});
                    std::string source, entry;
                    auto bitmap = render_drawable(package, *selected, candidate, origin, source, entry);
                    result.bitmap = std::move(bitmap);
                    result.icon_source = std::string(owner) + "-" + source;
                    result.icon_entry = std::move(entry);
                    result.icon_status = "extracted";
                    result.icon_error.clear();
                    return true;
                } catch (const InspectError &error) {
                    if (result.icon_error.empty()) {
                        result.icon_status = error.diagnostic.code.find("UNSUPPORTED") != std::string::npos
                                                 ? "unsupported"
                                                 : "invalid";
                        result.icon_error = error.diagnostic.code;
                    }
                    result.diagnostics.push_back(error.diagnostic.code + ": " + error.what());
                    return false;
                }
            };
            if (!attempt(icon, icon_owner, icon_container, options.sdk)) {
                bool extracted = false;
                // Only a declared legacy resource variant is an alternative; no
                // filename heuristic can select an advertisement or other image.
                if ((icon.type == 1 || (icon.type == 3 && icon.literal.starts_with('@'))) &&
                    options.sdk >= 26)
                    extracted = attempt(icon, icon_owner + "-legacy", icon_container, 25);
                if (!extracted && manifest.round_icon.type)
                    extracted = attempt(manifest.round_icon, "application-round", package.parts.front().path,
                                        options.sdk);
                if (!extracted && icon_owner == "launcher")
                    (void)attempt(manifest.icon, "application-fallback", package.parts.front().path,
                                  options.sdk);
            }
            if (!icon.type && !manifest.round_icon.type)
                result.diagnostics.push_back("No APK icon declared; using the original Aether fallback.");
        } else if (icon.type) {
            try {
                const auto path = resolve(icon);
                auto &archive =
                    *package.part(icon.type == 1 ? resources->container(icon.reference) : icon_container)
                         .archive;
                if (!safe_entry(path))
                    throw InspectError("AETHER_ICON_UNSUPPORTED", "apk-artwork",
                                       "Icon must resolve to a bounded res/ PNG archive entry; "
                                       "vector/adaptive and qualified resources are not supported");
                const auto &entries = archive.entries();
                const auto found = std::find_if(entries.begin(), entries.end(),
                                                [&](const auto &entry) { return entry.path == path; });
                if (found == entries.end() || found->directory || found->bytes > 1024 * 1024)
                    bad("Icon entry is absent or exceeds 1 MiB", "LIMIT");
                result.bitmap =
                    decode_icon_png(archive.read(static_cast<std::size_t>(found - entries.begin())));
                result.icon_source = icon_owner + "-png";
                result.icon_status = "extracted";
                const auto origin = icon.type == 1 ? resources->container(icon.reference) : icon_container;
                result.icon_entry = origin.empty() ? path : std::string(origin) + "!/" + path;
            } catch (const InspectError &error) {
                result.icon_status = error.diagnostic.code.find("UNSUPPORTED") != std::string::npos
                                         ? "unsupported"
                                         : "invalid";
                result.icon_error = error.diagnostic.code;
                result.diagnostics.push_back(error.diagnostic.code + ": " + error.what());
            }
        } else
            result.diagnostics.push_back("No APK icon declared; using the original Aether fallback.");
    } catch (const InspectError &error) {
        result.diagnostics.push_back(error.diagnostic.code + ": " + error.what());
    }
    return result;
}
std::string Artwork::json() const {
    std::string out =
        "{\"label\":" + json_quote(label) + ",\"labelSource\":" + json_quote(label_source) +
        ",\"iconSource\":" + json_quote(icon_source) + ",\"iconEntry\":" + json_quote(icon_entry) +
        ",\"iconStatus\":" + json_quote(icon_status) + ",\"iconError\":" + json_quote(icon_error) +
        ",\"width\":" + std::to_string(bitmap.width) + ",\"height\":" + std::to_string(bitmap.height) +
        ",\"rendererVersion\":" + std::to_string(renderer_version) +
        ",\"iconSha256\":" + json_quote(sha256(icon_file(bitmap, renderer_version))) +
        ",\"rgbaSha256\":" + json_quote(sha256(bitmap.rgba)) +
        ",\"shortcutStem\":" + json_quote(shortcut_stem(label)) + ",\"diagnostics\":[";
    for (std::size_t index = 0; index < diagnostics.size(); ++index) {
        if (index)
            out += ',';
        out += json_quote(diagnostics[index]);
    }
    return out + "]}";
}
} // namespace aether::apk
