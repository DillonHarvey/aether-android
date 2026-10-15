// Original bounded DEX metadata validation; no annotation value is evaluated.
#include "annotations.hpp"
#include "aether/apk/bytes.hpp"
#include <map>
#include <set>

namespace aether::dex {
namespace {
constexpr std::uint32_t maximum_records = 65536, maximum_steps = 262144, maximum_depth = 32;
[[noreturn]] void bad(std::string_view kind, const char *message) {
    throw DexError("AETHER_DEX_ANNOTATION_" + std::string(kind), message);
}
struct Region {
    std::uint32_t begin, end, count;
};
class Validator {
  public:
    Validator(apk::Bytes bytes, const DexImage &image) : view_(bytes, "dex-annotations"), image_(image) {
        // The inventory has already validated the map, uniqueness, counts and ordering.
        const auto map = view_.u32(52), count = view_.u32(map);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto at = map + 4 + i * 12;
            regions_.emplace(view_.u16(at), Region{view_.u32(at + 8),
                                                   i + 1 == count ? static_cast<std::uint32_t>(bytes.size())
                                                                  : view_.u32(at + 20),
                                                   view_.u32(at + 4)});
        }
    }
    void run() {
        each(0x2004, 1, [&](std::uint32_t &at) {
            const auto start = at;
            range(at, 1, 0x2004);
            if (view_.u8(at++) > 2)
                bad("VALUE", "Invalid annotation visibility");
            items_.emplace(start, annotation(at, 0));
        });
        each(0x1003, 4, [&](std::uint32_t &at) {
            const auto start = at, count = table(at, 4, 0x1003, maximum_records);
            Index previous = 0;
            for (std::uint32_t i = 0; i < count; ++i, at += 4) {
                const auto found = items_.find(view_.u32(at));
                if (found == items_.end())
                    bad("REFERENCE", "Annotation set offset does not name a complete annotation item");
                if (i && found->second <= previous)
                    bad("ORDER", "Annotation types are not strictly sorted in their set");
                previous = found->second;
            }
            sets_.insert(start);
        });
        each(0x1002, 4, [&](std::uint32_t &at) {
            const auto start = at, count = table(at, 4, 0x1002, 255);
            for (std::uint32_t i = 0; i < count; ++i, at += 4)
                set(view_.u32(at), true);
            parameter_lists_.emplace(start, count);
        });
        each(0x2006, 4, [&](std::uint32_t &at) {
            const auto start = at;
            range(at, 16, 0x2006);
            set(view_.u32(at), true);
            const auto fields = view_.u32(at + 4), methods = view_.u32(at + 8),
                       parameters = view_.u32(at + 12);
            if (fields > image_.fields.size() || methods > image_.methods.size() ||
                parameters > image_.methods.size())
                bad("LIMIT", "Annotation directory counts exceed identifier tables");
            const auto count = std::uint64_t{fields} + methods + parameters;
            consume(count);
            at += 16;
            range(at, count * 8, 0x2006);
            Index owner = no_index;
            const auto bind = [&](Index candidate) {
                if (owner != no_index && candidate != owner)
                    bad("OWNER", "Annotation directory contains members from different classes");
                owner = candidate;
            };
            for (unsigned group = 0; group < 3; ++group) {
                const auto size = group == 0 ? fields : group == 1 ? methods : parameters;
                Index previous = 0;
                for (std::uint32_t i = 0; i < size; ++i, at += 8) {
                    const auto index = view_.u32(at), offset = view_.u32(at + 4);
                    if (i && index <= previous)
                        bad("ORDER", "Annotated member indexes are not strictly sorted");
                    previous = index;
                    if (group == 0) {
                        if (index >= image_.fields.size() || !image_.fields[index].declared)
                            bad("REFERENCE", "Annotated field is not a defined field");
                        bind(image_.fields[index].owner);
                    } else {
                        if (index >= image_.methods.size() || !image_.methods[index].declared)
                            bad("REFERENCE", "Annotated method is not a defined method");
                        bind(image_.methods[index].owner);
                    }
                    if (group != 2)
                        set(offset, false);
                    else {
                        const auto list = parameter_lists_.find(offset);
                        if (list == parameter_lists_.end())
                            bad("REFERENCE", "Parameter annotations do not name a complete reference list");
                        const auto &method = image_.methods[index];
                        if (list->second > image_.prototypes[method.prototype].parameters.size())
                            bad("REFERENCE", "Parameter annotation list exceeds the method signature");
                    }
                }
            }
            directories_.emplace(start, owner);
        });
        const auto count = view_.u32(96), table_at = view_.u32(100);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto at = table_at + i * 32, offset = view_.u32(at + 20);
            if (!offset)
                continue;
            const auto directory = directories_.find(offset);
            if (directory == directories_.end())
                bad("REFERENCE", "Class annotations do not name a complete directory");
            if (directory->second != no_index && directory->second != view_.u32(at))
                bad("OWNER", "Annotation directory members belong to another class");
        }
    }

  private:
    void range(std::uint32_t at, std::uint64_t size, std::uint16_t kind) const {
        const auto found = regions_.find(kind);
        if (found == regions_.end() || at < found->second.begin || at > found->second.end ||
            size > found->second.end - at)
            bad("BOUNDS", "Annotation item exceeds its declared map section");
    }
    void consume(std::uint64_t count) {
        if (count > maximum_steps - steps_)
            bad("LIMIT", "Annotation validation work budget exceeded");
        steps_ += static_cast<std::uint32_t>(count);
    }
    std::uint32_t leb(std::uint32_t &at) const {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 5; ++i) {
            range(at, 1, 0x2004);
            const auto b = view_.u8(at++);
            if (i == 4 && (b & 0xf0))
                bad("VALUE", "Annotation ULEB128 exceeds 32 bits");
            value |= std::uint32_t{b & 0x7fu} << (i * 7);
            if (!(b & 0x80))
                return value;
        }
        bad("VALUE", "Unterminated annotation ULEB128");
    }
    Index annotation(std::uint32_t &at, unsigned depth) {
        if (depth > maximum_depth)
            bad("LIMIT", "Annotation nesting exceeds 32");
        const auto type = leb(at), count = leb(at);
        if (type >= image_.types.size() || image_.types[type].front() != 'L')
            bad("REFERENCE", "Annotation type is not a class descriptor");
        if (count > image_.strings.size())
            bad("LIMIT", "Annotation element count exceeds the string table");
        consume(count);
        Index previous = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto name = leb(at);
            if (name >= image_.strings.size() || image_.strings[name].empty())
                bad("REFERENCE", "Annotation element name is not a nonempty string");
            if (i && name <= previous)
                bad("ORDER", "Annotation element names are not strictly sorted");
            previous = name;
            value(at, depth);
        }
        return type;
    }
    void value(std::uint32_t &at, unsigned depth) {
        consume(1);
        range(at, 1, 0x2004);
        const auto header = view_.u8(at++);
        const auto kind = static_cast<unsigned>(header & 31), arg = unsigned(header >> 5);
        if (kind == 0x1c || kind == 0x1d) {
            if (arg)
                bad("VALUE", "Nested annotation value has a nonzero argument");
            if (depth >= maximum_depth)
                bad("LIMIT", "Annotation nesting exceeds 32");
            if (kind == 0x1d)
                (void)annotation(at, depth + 1);
            else {
                const auto count = leb(at);
                if (count > maximum_steps - steps_)
                    bad("LIMIT", "Annotation array exceeds the remaining work budget");
                for (std::uint32_t i = 0; i < count; ++i)
                    value(at, depth + 1);
            }
            return;
        }
        if (kind == 0x1e || kind == 0x1f) {
            if (arg > (kind == 0x1f ? 1u : 0u))
                bad("VALUE", "Invalid encoded null or boolean annotation");
            return;
        }
        const unsigned width = kind == 0                                                       ? 1
                               : (kind == 2 || kind == 3)                                      ? 2
                               : (kind == 4 || kind == 0x10 || (kind >= 0x17 && kind <= 0x1b)) ? 4
                               : (kind == 6 || kind == 0x11)                                   ? 8
                                                                                               : 0;
        if (!width)
            bad("UNSUPPORTED", "Unsupported DEX 035 annotation value type");
        if (arg >= width)
            bad("VALUE", "Annotation scalar width exceeds its value type");
        range(at, arg + 1, 0x2004);
        std::uint64_t bits = 0;
        for (unsigned i = 0; i <= arg; ++i)
            bits |= std::uint64_t{view_.u8(at++)} << (i * 8);
        if ((kind == 0x17 && bits >= image_.strings.size()) ||
            (kind == 0x18 && bits >= image_.types.size()) ||
            ((kind == 0x19 || kind == 0x1b) && bits >= image_.fields.size()) ||
            (kind == 0x1a && bits >= image_.methods.size()))
            bad("REFERENCE", "Annotation value reference is out of range");
    }
    std::uint32_t table(std::uint32_t &at, std::uint32_t width, std::uint16_t kind, std::uint32_t maximum) {
        range(at, 4, kind);
        const auto count = view_.u32(at);
        if (count > maximum)
            bad("LIMIT", "Annotation table count exceeds its limit");
        consume(count);
        at += 4;
        range(at, std::uint64_t{count} * width, kind);
        return count;
    }
    void set(std::uint32_t offset, bool optional) const {
        if ((offset || !optional) && !sets_.contains(offset))
            bad("REFERENCE", "Annotation reference does not name a complete set");
    }
    template <class F> void each(std::uint16_t kind, unsigned alignment, F parse) {
        const auto found = regions_.find(kind);
        if (found == regions_.end())
            return;
        const auto &region = found->second;
        if (region.begin % alignment)
            bad("ALIGNMENT", "Misaligned annotation section");
        if (region.count > maximum_records - records_)
            bad("LIMIT", "Annotation record count exceeds 65536");
        records_ += region.count;
        auto at = region.begin;
        for (std::uint32_t i = 0; i < region.count; ++i) {
            parse(at);
            // All variable-sized annotation containers have a four-byte multiple size;
            // annotation_item alone is byte aligned. No implicit gaps between records.
            if (at % alignment)
                bad("ALIGNMENT", "Misaligned annotation record end");
        }
        range(at, 0, kind);
        if (region.end - at > 3)
            bad("BOUNDS", "Annotation map count leaves unparsed section data");
        while (at < region.end)
            if (view_.u8(at++))
                bad("VALUE", "Nonzero annotation section padding");
    }
    apk::View view_;
    const DexImage &image_;
    std::map<std::uint16_t, Region> regions_;
    std::map<std::uint32_t, Index> items_, directories_;
    std::set<std::uint32_t> sets_;
    std::map<std::uint32_t, std::uint32_t> parameter_lists_;
    std::uint32_t steps_ = 0, records_ = 0;
};
} // namespace
void validate_annotations(std::span<const std::uint8_t> bytes, const DexImage &image) {
    Validator(bytes, image).run();
}
} // namespace aether::dex
