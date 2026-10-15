#include "preview_toc.hpp"
#include "aether/common/text.hpp"
#include "preview_container.hpp"
#include <algorithm>
#include <set>

namespace aether::apk {
namespace {
[[noreturn]] void bad(std::string message) {
    throw InspectError("AETHER_ICON_TOC_INVALID", "package-preview", std::move(message));
}
struct Field {
    unsigned number, wire;
    std::uint64_t integer = 0;
    Bytes bytes;
};
class Reader {
    std::size_t fields_ = 0;

  public:
    std::vector<Field> message(Bytes bytes) {
        std::size_t at = 0;
        const auto varint = [&]() {
            std::uint64_t result = 0;
            for (unsigned n = 0; n < 10; ++n) {
                if (at == bytes.size())
                    bad("Truncated protobuf integer");
                const auto c = bytes[at++];
                if (n == 9 && c > 1)
                    bad("Protobuf integer overflow");
                result |= std::uint64_t(c & 127) << (7 * n);
                if (!(c & 128))
                    return result;
            }
            bad("Unterminated protobuf integer");
        };
        std::vector<Field> result;
        while (at < bytes.size()) {
            if (++fields_ > 65536)
                bad("Protobuf metadata exceeds 65,536 fields");
            const auto tag = varint();
            if (!(tag >> 3) || tag >> 3 > 0x1fffffff)
                bad("Invalid protobuf field number");
            Field field{static_cast<unsigned>(tag >> 3), static_cast<unsigned>(tag & 7), 0, {}};
            if (field.wire == 0)
                field.integer = varint();
            else {
                const auto size = field.wire == 2   ? varint()
                                  : field.wire == 1 ? 8
                                  : field.wire == 5 ? 4
                                                    : UINT64_MAX;
                if (size > bytes.size() - at)
                    bad("Invalid protobuf wire type or field extent");
                field.bytes = bytes.subspan(at, static_cast<std::size_t>(size));
                at += static_cast<std::size_t>(size);
            }
            result.push_back(field);
        }
        return result;
    }
};
const Field *one(const std::vector<Field> &fields, unsigned number, unsigned wire) {
    const Field *found = nullptr;
    for (const auto &field : fields)
        if (field.number == number) {
            if (found || field.wire != wire)
                bad("Repeated or mistyped selection field in toc.pb");
            found = &field;
        }
    return found;
}
std::string text(const Field *field) {
    if (!field)
        return {};
    if (field->bytes.size() > 511)
        bad("Protobuf selection string exceeds 511 bytes");
    std::string result(reinterpret_cast<const char *>(field->bytes.data()), field->bytes.size());
    try {
        (void)utf16(result);
    } catch (const std::invalid_argument &) {
        bad("Invalid UTF-8 selection string");
    }
    if (result.find('\0') != std::string::npos)
        bad("Embedded NUL selection string");
    return result;
}
} // namespace
PreviewToc preview_toc(Bytes bytes) {
    if (bytes.empty() || bytes.size() > 1024 * 1024)
        bad("toc.pb must contain 1 byte through 1 MiB");
    Reader reader;
    const auto root = reader.message(bytes);
    PreviewToc result{text(one(root, 4, 2)), {}};
    struct Candidate {
        std::string path;
        std::uint32_t variant;
        bool standalone;
    };
    std::vector<Candidate> candidates;
    std::set<std::uint32_t> variants;
    for (const auto &v : root) {
        if (v.number != 1)
            continue; // Asset slices are never traversed.
        if (v.wire != 2 || variants.size() >= 64)
            bad("Invalid or excessive APK variants");
        const auto variant = reader.message(v.bytes);
        const auto number = one(variant, 3, 0);
        if (number && number->integer > UINT32_MAX)
            bad("Variant number overflow");
        const auto id = number ? static_cast<std::uint32_t>(number->integer) : 0;
        if (!variants.insert(id).second)
            bad("Duplicate bundletool variant number");
        bool have_base = false;
        unsigned masters = 0;
        for (const auto &s : variant) {
            if (s.number != 2)
                continue;
            if (s.wire != 2)
                bad("Invalid APK set");
            const auto set = reader.message(s.bytes);
            const auto meta = one(set, 1, 2);
            if (!meta)
                bad("APK set has no module metadata");
            const auto module = reader.message(meta->bytes);
            if (text(one(module, 1, 2)) != "base")
                continue;
            if (have_base)
                bad("Repeated base module in one variant");
            have_base = true;
            if (const auto instant = one(module, 3, 0); instant && instant->integer)
                continue;
            for (const auto &a : set) {
                if (a.number != 2)
                    continue;
                if (a.wire != 2)
                    bad("Invalid APK description");
                const auto apk = reader.message(a.bytes);
                const auto split = one(apk, 3, 2), standalone = one(apk, 4, 2);
                unsigned choices = 0;
                for (unsigned i = 3; i <= 9; ++i)
                    choices += one(apk, i, 2) ? 1 : 0;
                if (choices != 1)
                    bad("Ambiguous or absent APK metadata kind");
                bool accepted = false;
                if (split) {
                    const auto details = reader.message(split->bytes);
                    const auto master = one(details, 2, 0);
                    if (master && master->integer > 1)
                        bad("Invalid master-split boolean");
                    accepted = master && master->integer == 1;
                    if (accepted && ++masters > 1)
                        bad("Multiple base master APKs in one variant");
                } else if (standalone) {
                    const auto details = reader.message(standalone->bytes);
                    accepted = text(one(details, 3, 2)).empty();
                }
                if (accepted) {
                    auto path = text(one(apk, 2, 2));
                    validate_preview_member_path(path);
                    if (path.empty() || candidates.size() >= 128)
                        bad("Missing or excessive preview candidates");
                    candidates.push_back({std::move(path), id, standalone != nullptr});
                }
            }
        }
    }
    if (candidates.empty())
        throw InspectError("AETHER_ICON_NO_BASE", "package-preview",
                           "toc.pb contains no base master or standalone application APK");
    // Icons do not select an install device. Prefer a split base, then newest
    // variant number, with lexical path order for equivalent standalones.
    std::sort(candidates.begin(), candidates.end(), [](const auto &a, const auto &b) {
        if (a.standalone != b.standalone)
            return !a.standalone;
        if (a.variant != b.variant)
            return a.variant > b.variant;
        return a.path < b.path;
    });
    result.base = candidates.front().path;
    return result;
}
} // namespace aether::apk
