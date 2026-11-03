#include "aether/apk/runtime_xml.hpp"
#include <algorithm>
#include <limits>
#include <utility>

namespace aether::apk {
namespace {
[[noreturn]] void fail(const char *kind, const char *message) {
    throw InspectError(std::string("AETHER_AXML_") + kind, "runtime-xml", message);
}
std::size_t add(std::size_t a, std::size_t b) {
    if (b > std::numeric_limits<std::size_t>::max() - a)
        fail("LIMIT", "Runtime XML storage extent overflows");
    return a + b;
}
std::size_t product(std::size_t a, std::size_t b) {
    if (a && b > std::numeric_limits<std::size_t>::max() / a)
        fail("LIMIT", "Runtime XML storage product overflows");
    return a * b;
}
template <class T> std::size_t bytes(const std::vector<T> &values) noexcept {
    return values.capacity() * sizeof(T);
}
struct Counts {
    std::size_t pool_offset = 0, pool_size = 0, string_end = 0, string_start = 0;
    std::size_t offsets = 0, text_bytes = 0, nodes = 0, attributes = 0, resource_ids = 0;
    std::uint32_t strings = 0, flags = 0;
};
class Decoder {
    Bytes input_;
    std::size_t limit_, used_, peak_;
    const std::function<void(std::uint64_t)> &charge_;
    RuntimeXmlDocument &out_;
    Counts counts_;

    void work(std::uint64_t count) const {
        if (count) charge_(count);
    }
    void range(std::size_t at, std::size_t count, std::size_t end) const {
        if (at > end || count > end - at)
            fail("INVALID", "A runtime XML structure exceeds its containing extent");
    }
    std::uint8_t u8(std::size_t at, std::size_t end) const {
        range(at, 1, end);
        work(1);
        return input_[at];
    }
    std::uint16_t u16(std::size_t at, std::size_t end) const {
        range(at, 2, end);
        work(2);
        return static_cast<std::uint16_t>(input_[at] | (std::uint16_t(input_[at + 1]) << 8));
    }
    std::uint32_t u32(std::size_t at, std::size_t end) const {
        range(at, 4, end);
        work(4);
        return input_[at] | (std::uint32_t(input_[at + 1]) << 8) |
               (std::uint32_t(input_[at + 2]) << 16) | (std::uint32_t(input_[at + 3]) << 24);
    }
    void take(std::size_t count) {
        if (count > limit_ - used_)
            fail("LIMIT", "Runtime XML exceeds its admitted working bytes");
        used_ += count;
        peak_ = std::max(peak_, used_);
    }
    template <class T> void allocate(std::vector<T> &target, std::size_t count) {
        if (count > target.max_size())
            fail("LIMIT", "Runtime XML count exceeds the host vector representation");
        const auto required = product(count, sizeof(T));
        take(required);
        // Every destination is initially empty, and each is constructed once at
        // its final size. No geometric growth or old/new allocation pair occurs.
        work(count);
        target = std::vector<T>(count);
        const auto actual = bytes(target);
        if (actual < required)
            fail("INVALID", "Runtime XML vector capacity is inconsistent");
        take(actual - required);
    }
    void pool_header(std::size_t offset, std::size_t size) {
        const auto end = offset + size;
        if (size < 28)
            fail("INVALID", "Runtime XML string-pool header is truncated");
        const auto header = u16(offset + 2, end);
        if (header < 28 || (header & 3) || header > size)
            fail("INVALID", "Runtime XML string-pool header is invalid");
        counts_.strings = u32(offset + 8, end);
        const auto styles = u32(offset + 12, end);
        counts_.flags = u32(offset + 16, end);
        const auto start = u32(offset + 20, end);
        const auto style_start = u32(offset + 24, end);
        if (styles > counts_.strings)
            fail("INVALID", "Runtime XML string-style count exceeds its strings");
        if (counts_.flags & ~0x101u)
            fail("UNSUPPORTED", "Runtime XML string-pool flags are unsupported");
        if (styles)
            fail("UNSUPPORTED", "Styled runtime XML strings require unsupported span semantics");
        if (style_start || header + std::uint64_t(counts_.strings) * 4 > start || start > size)
            fail("INVALID", "Runtime XML string-pool regions are invalid");
        counts_.pool_offset = offset;
        counts_.pool_size = size;
        counts_.offsets = offset + header;
        counts_.string_start = offset + start;
        counts_.string_end = end;
    }
    void inventory() {
        if (input_.size() < 8)
            fail("INVALID", "Runtime XML document header is truncated");
        if (u16(0, input_.size()) != 3)
            fail("UNSUPPORTED", "Expected Android binary XML");
        if (u16(2, input_.size()) != 8 || u32(4, input_.size()) != input_.size())
            fail("INVALID", "Runtime XML document header or length is invalid");
        bool pool = false, map = false, saw_node = false;
        for (std::size_t at = 8; at < input_.size();) {
            range(at, 8, input_.size());
            const auto type = u16(at, input_.size()), header = u16(at + 2, input_.size());
            const auto size = u32(at + 4, input_.size());
            if (header < 8 || size < header || (size & 3))
                fail("INVALID", "Runtime XML chunk header or size is invalid");
            range(at, size, input_.size());
            const auto end = at + size;
            if (type == 1) {
                if (pool || map || saw_node)
                    fail("INVALID", "Runtime XML string pool is repeated or misplaced");
                pool_header(at, size);
                pool = true;
            } else {
                if (!pool)
                    fail("INVALID", "Runtime XML content precedes its string pool");
                if (type == 0x180) {
                    if (map || saw_node || header != 8 || (size - 8) / 4 > counts_.strings)
                        fail("INVALID", "Runtime XML resource map is repeated, misplaced or invalid");
                    counts_.resource_ids = (size - 8) / 4;
                    map = true;
                } else if (type >= 0x100 && type <= 0x104) {
                    if (header < 16)
                        fail("INVALID", "Runtime XML node header is truncated");
                    if (header > 16)
                        fail("UNSUPPORTED", "Runtime XML node-header extensions are unsupported");
                    if ((type == 0x100 || type == 0x101 || type == 0x103) && size != 24)
                        fail("INVALID", "Runtime XML namespace/end-element node has an invalid extent");
                    if (type == 0x104 && size != 28)
                        fail("INVALID", "Runtime XML text node has an invalid extent");
                    if (type == 0x102) {
                        if (size < 36)
                            fail("INVALID", "Runtime XML start-element node is truncated");
                        const auto start = u16(at + 24, end), width = u16(at + 26, end);
                        const auto count = u16(at + 28, end);
                        if (start < 20 || width < 20 || 16ull + start + std::uint64_t(count) * width > size)
                            fail("INVALID", "Runtime XML attribute region is invalid");
                        if (width != 20)
                            fail("UNSUPPORTED", "Extended runtime XML attributes are unsupported");
                        counts_.attributes = add(counts_.attributes, count);
                    }
                    counts_.nodes = add(counts_.nodes, 1);
                    if (counts_.nodes >= runtime_xml_absent)
                        fail("LIMIT", "Runtime XML nodes exceed their index representation");
                    saw_node = true;
                } else
                    fail("UNSUPPORTED", "Runtime XML chunk type is unsupported");
            }
            at = end;
        }
        if (!pool)
            fail("INVALID", "Runtime XML string pool is missing");
    }
    std::uint32_t utf8_scalar(std::size_t &at, std::size_t end) const {
        const auto first = u8(at++, end);
        std::uint32_t scalar = first, minimum = 0;
        unsigned tail = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            scalar &= 31u; tail = 1; minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            scalar &= 15u; tail = 2; minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            scalar &= 7u; tail = 3; minimum = 0x10000;
        } else if (first >= 0x80)
            fail("INVALID", "Invalid runtime XML UTF-8 leading byte");
        for (unsigned n = 0; n < tail; ++n) {
            const auto next = u8(at++, end);
            if ((next & 0xc0) != 0x80)
                fail("INVALID", "Invalid runtime XML UTF-8 continuation byte");
            scalar = (scalar << 6) | (next & 63u);
        }
        if (!scalar || scalar < minimum || scalar > 0x10ffff)
            fail("INVALID", "Invalid runtime XML UTF-8 scalar");
        return scalar;
    }
    std::size_t decode_string(std::uint32_t index, char *output, std::size_t capacity) const {
        const auto relative = u32(counts_.offsets + std::size_t(index) * 4, counts_.string_end);
        if (relative >= counts_.string_end - counts_.string_start)
            fail("INVALID", "Runtime XML string offset exceeds its pool");
        std::size_t at = counts_.string_start + relative;
        std::size_t written = 0;
        const auto emit = [&](std::uint32_t scalar) {
            const unsigned count = scalar < 0x80 ? 1 : scalar < 0x800 ? 2 : scalar < 0x10000 ? 3 : 4;
            if (output) {
                if (written > capacity || count > capacity - written)
                    fail("INVALID", "Runtime XML normalized string extent changed during decoding");
                work(count);
                if (count == 1) output[written] = static_cast<char>(scalar);
                else {
                    output[written] = static_cast<char>((count == 2 ? 0xc0u : count == 3 ? 0xe0u : 0xf0u) |
                                                       (scalar >> (6 * (count - 1))));
                    for (unsigned n = 1; n < count; ++n)
                        output[written + n] = static_cast<char>(0x80u | ((scalar >> (6 * (count - 1 - n))) & 63u));
                }
            }
            written = add(written, count);
        };
        if (counts_.flags & 0x100u) {
            const auto length = [&]() -> std::uint32_t {
                const auto first = u8(at++, counts_.string_end);
                return first & 0x80u ? ((std::uint32_t(first & 127u) << 8) | u8(at++, counts_.string_end)) : first;
            };
            const auto expected_utf16 = length(), encoded_bytes = length();
            range(at, std::size_t(encoded_bytes) + 1, counts_.string_end);
            const auto end = at + encoded_bytes;
            std::size_t utf16 = 0;
            while (at < end) {
                auto scalar = utf8_scalar(at, end);
                if (scalar >= 0xd800 && scalar <= 0xdbff) {
                    const auto low = utf8_scalar(at, end);
                    if (low < 0xdc00 || low > 0xdfff)
                        fail("INVALID", "Unpaired runtime XML CESU-8 high surrogate");
                    scalar = 0x10000u + ((scalar - 0xd800u) << 10) + low - 0xdc00u;
                } else if (scalar >= 0xdc00 && scalar <= 0xdfff)
                    fail("INVALID", "Unpaired runtime XML CESU-8 low surrogate");
                utf16 += scalar > 0xffff ? 2u : 1u;
                emit(scalar);
            }
            if (utf16 != expected_utf16 || u8(end, counts_.string_end))
                fail("INVALID", "Runtime XML UTF-8 lengths or terminator are invalid");
        } else {
            auto length = std::uint32_t(u16(at, counts_.string_end)); at += 2;
            if (length & 0x8000u) {
                length = ((length & 0x7fffu) << 16) | u16(at, counts_.string_end); at += 2;
            }
            if (at & 1)
                fail("INVALID", "Runtime XML UTF-16 string is not word-aligned");
            range(at, add(product(length, 2), 2), counts_.string_end);
            for (std::uint32_t n = 0; n < length; ++n) {
                std::uint32_t scalar = u16(at, counts_.string_end); at += 2;
                if (!scalar)
                    fail("INVALID", "Embedded NUL in runtime XML UTF-16 string");
                if (scalar >= 0xd800 && scalar <= 0xdbff) {
                    if (++n >= length)
                        fail("INVALID", "Unpaired runtime XML UTF-16 high surrogate");
                    const auto low = u16(at, counts_.string_end); at += 2;
                    if (low < 0xdc00 || low > 0xdfff)
                        fail("INVALID", "Unpaired runtime XML UTF-16 high surrogate");
                    scalar = 0x10000u + ((scalar - 0xd800u) << 10) + low - 0xdc00u;
                } else if (scalar >= 0xdc00 && scalar <= 0xdfff)
                    fail("INVALID", "Unpaired runtime XML UTF-16 low surrogate");
                emit(scalar);
            }
            if (u16(at, counts_.string_end))
                fail("INVALID", "Runtime XML UTF-16 string is unterminated");
        }
        return written;
    }
    void strings() {
        for (std::uint32_t n = 0; n < counts_.strings; ++n) {
            counts_.text_bytes = add(counts_.text_bytes, decode_string(n, nullptr, 0));
            if (counts_.text_bytes > limit_ - used_)
                fail("LIMIT", "Runtime XML decoded strings exceed admitted working bytes");
        }
        const auto arrays = add(add(product(counts_.strings, sizeof(RuntimeXmlString)), counts_.text_bytes),
                                add(add(product(counts_.resource_ids, sizeof(std::uint32_t)),
                                        product(counts_.nodes, sizeof(RuntimeXmlNode))),
                                    product(counts_.attributes, sizeof(RuntimeXmlAttribute))));
        if (arrays > limit_ - used_)
            fail("LIMIT", "Runtime XML document storage exceeds admitted working bytes");
        allocate(out_.strings, counts_.strings);
        allocate(out_.utf8, counts_.text_bytes);
        allocate(out_.resource_map, counts_.resource_ids);
        allocate(out_.nodes, counts_.nodes);
        allocate(out_.attributes, counts_.attributes);
        std::size_t offset = 0;
        for (std::uint32_t n = 0; n < counts_.strings; ++n) {
            // Empty pools/strings need no null-pointer arithmetic.
            auto *destination = out_.utf8.empty() ? nullptr : out_.utf8.data() + offset;
            const auto length = decode_string(n, destination, out_.utf8.size() - offset);
            out_.strings[n] = {offset, length};
            offset += length;
        }
        if (offset != out_.utf8.size())
            fail("INVALID", "Runtime XML string inventory changed during decoding");
    }
    void index(std::uint32_t value, bool optional = false) const {
        if (!(optional && value == runtime_xml_absent) && value >= out_.strings.size())
            fail("INVALID", "Runtime XML string reference is out of bounds");
    }
    bool same(std::uint32_t a, std::uint32_t b) const {
        if (a == b) { work(1); return true; }
        const auto first = out_.optional_string(a), second = out_.optional_string(b);
        work(1);
        if (first.size() != second.size()) return false;
        for (std::size_t at = 0; at < first.size(); ++at) {
            work(1);
            if (first[at] != second[at]) return false;
        }
        return true;
    }
    bool namespace_active(std::uint32_t value, std::uint32_t top) const {
        if (out_.optional_string(value).empty()) return true;
        const auto newest = top;
        while (top != runtime_xml_absent) {
            work(1);
            const auto &node = out_.nodes[top];
            if (same(value, node.namespace_index)) {
                bool shadowed = false;
                for (auto recent = newest; recent != top; recent = out_.nodes[recent].previous_namespace) {
                    work(1);
                    if (same(out_.nodes[recent].name_index, node.name_index)) {
                        shadowed = true;
                        break;
                    }
                }
                if (!shadowed) return true;
            }
            top = node.previous_namespace;
        }
        return false;
    }
    void typed(std::size_t at, std::size_t end, std::uint8_t &type, std::uint32_t &data) const {
        if (u16(at, end) != 8 || u8(at + 2, end))
            fail("INVALID", "Runtime XML typed value has an invalid header");
        type = u8(at + 3, end); data = u32(at + 4, end);
        if (type == 3) index(data);
    }
    void nodes() {
        std::uint32_t element_top = runtime_xml_absent, namespace_top = runtime_xml_absent;
        std::uint32_t depth = 0;
        std::size_t next_node = 0, next_attribute = 0;
        bool root = false, closed = false;
        for (std::size_t at = 8; at < input_.size();) {
            const auto type = u16(at, input_.size());
            const auto size = u32(at + 4, input_.size());
            const auto end = at + size;
            if (type == 0x180) {
                for (std::size_t n = 0; n < out_.resource_map.size(); ++n)
                    out_.resource_map[n] = u32(at + 8 + n * 4, end);
            } else if (type >= 0x100 && type <= 0x104) {
                const auto this_index = static_cast<std::uint32_t>(next_node++);
                auto &node = out_.nodes[this_index];
                node.source_offset = at; node.line = u32(at + 8, end);
                node.comment_index = u32(at + 12, end); index(node.comment_index, true);
                node.parent = element_top; node.depth = depth;
                if (type == 0x100 || type == 0x101) {
                    node.kind = type == 0x100 ? RuntimeXmlNodeKind::namespace_start : RuntimeXmlNodeKind::namespace_end;
                    // A default namespace may have the absent prefix index.
                    node.name_index = u32(at + 16, end); index(node.name_index, true);
                    node.namespace_index = u32(at + 20, end); index(node.namespace_index);
                    if (type == 0x100) {
                        if (closed)
                            fail("INVALID", "Runtime XML namespace begins after its root closes");
                        for (auto previous = namespace_top; previous != runtime_xml_absent;) {
                            const auto &other = out_.nodes[previous];
                            if (other.depth != depth) break;
                            if (same(other.name_index, node.name_index))
                                fail("INVALID", "Runtime XML repeats a namespace prefix in one scope");
                            previous = other.previous_namespace;
                        }
                        node.previous_namespace = namespace_top; namespace_top = this_index;
                    } else {
                        if (namespace_top == runtime_xml_absent)
                            fail("INVALID", "Runtime XML namespace end has no matching start");
                        auto &start = out_.nodes[namespace_top];
                        if (start.depth != depth || !same(start.name_index, node.name_index) ||
                            !same(start.namespace_index, node.namespace_index))
                            fail("INVALID", "Runtime XML namespace nodes are unbalanced");
                        start.matching = this_index; node.matching = namespace_top;
                        namespace_top = start.previous_namespace;
                    }
                } else if (type == 0x102) {
                    if (closed)
                        fail("INVALID", "Runtime XML contains multiple root elements");
                    node.kind = RuntimeXmlNodeKind::element_start;
                    node.namespace_index = u32(at + 16, end); index(node.namespace_index, true);
                    node.name_index = u32(at + 20, end); index(node.name_index);
                    if (out_.string(node.name_index).empty() || !namespace_active(node.namespace_index, namespace_top))
                        fail("INVALID", "Runtime XML element has an empty name or undeclared namespace");
                    const auto first = u16(at + 24, end);
                    node.attribute_begin = next_attribute; node.attribute_count = u16(at + 28, end);
                    node.id_index = u16(at + 30, end); node.class_index = u16(at + 32, end); node.style_index = u16(at + 34, end);
                    if (node.id_index > node.attribute_count || node.class_index > node.attribute_count ||
                        node.style_index > node.attribute_count)
                        fail("INVALID", "Runtime XML special attribute index exceeds its attribute count");
                    for (std::uint16_t n = 0; n < node.attribute_count; ++n) {
                        auto &attribute = out_.attributes[next_attribute++];
                        const auto start = at + 16 + first + std::size_t(n) * 20;
                        attribute.source_offset = start;
                        attribute.namespace_index = u32(start, end); index(attribute.namespace_index, true);
                        attribute.name_index = u32(start + 4, end); index(attribute.name_index);
                        attribute.raw_value_index = u32(start + 8, end); index(attribute.raw_value_index, true);
                        if (out_.string(attribute.name_index).empty() || !namespace_active(attribute.namespace_index, namespace_top))
                            fail("INVALID", "Runtime XML attribute has an empty name or undeclared namespace");
                        attribute.resource_id = attribute.name_index < out_.resource_map.size() ?
                                                out_.resource_map[attribute.name_index] : 0;
                        typed(start + 12, end, attribute.type, attribute.data);
                        for (std::uint16_t previous = 0; previous < n; ++previous) {
                            const auto &other = out_.attributes[node.attribute_begin + previous];
                            if (same(other.namespace_index, attribute.namespace_index) && same(other.name_index, attribute.name_index))
                                fail("INVALID", "Runtime XML repeats an element attribute");
                        }
                    }
                    root = true; element_top = this_index; ++depth;
                } else if (type == 0x103) {
                    node.kind = RuntimeXmlNodeKind::element_end;
                    node.namespace_index = u32(at + 16, end); index(node.namespace_index, true);
                    node.name_index = u32(at + 20, end); index(node.name_index);
                    if (element_top == runtime_xml_absent)
                        fail("INVALID", "Runtime XML end element has no matching start");
                    auto &start = out_.nodes[element_top];
                    if (!same(start.namespace_index, node.namespace_index) || !same(start.name_index, node.name_index))
                        fail("INVALID", "Runtime XML element close does not match its start");
                    // Namespace declarations introduced inside this element
                    // must close before the enclosing element can close.
                    if (namespace_top != runtime_xml_absent && out_.nodes[namespace_top].depth >= depth)
                        fail("INVALID", "Runtime XML namespace scope crosses its enclosing element close");
                    --depth; node.depth = depth; node.parent = start.parent;
                    start.matching = this_index; node.matching = element_top; element_top = start.parent;
                    if (!depth) closed = true;
                } else {
                    node.kind = RuntimeXmlNodeKind::text;
                    if (element_top == runtime_xml_absent)
                        fail("INVALID", "Runtime XML text occurs outside its root element");
                    node.name_index = u32(at + 16, end); index(node.name_index);
                    typed(at + 20, end, node.type, node.data);
                }
            }
            at = end;
        }
        if (!root || !closed || element_top != runtime_xml_absent || namespace_top != runtime_xml_absent ||
            next_node != out_.nodes.size() || next_attribute != out_.attributes.size())
            fail("INVALID", "Runtime XML document is incomplete or unbalanced");
    }

  public:
    Decoder(Bytes input, std::size_t limit, const std::function<void(std::uint64_t)> &charge,
            RuntimeXmlDocument &output)
        : input_(input), limit_(limit), used_(0), peak_(0), charge_(charge), out_(output) {
        if (!charge_) fail("INVALID", "Runtime XML requires its host-owned work accounting callback");
        take(input.size());
        take(sizeof(RuntimeXmlDocument));
        take(sizeof(Decoder));
    }
    void decode() {
        inventory(); strings(); nodes();
        out_.peak_storage_bytes = peak_;
    }
};
} // namespace

std::size_t RuntimeXmlDocument::storage_bytes() const noexcept {
    return sizeof(*this) + bytes(strings) + bytes(utf8) + bytes(resource_map) + bytes(nodes) + bytes(attributes);
}
std::string_view RuntimeXmlDocument::string(std::uint32_t index) const {
    if (index >= strings.size()) fail("INVALID", "Runtime XML string access is out of bounds");
    const auto &value = strings[index];
    if (value.offset > utf8.size() || value.length > utf8.size() - value.offset)
        fail("INVALID", "Runtime XML string storage is inconsistent");
    if (!value.length) return {};
    return {utf8.data() + value.offset, value.length};
}
std::string_view RuntimeXmlDocument::optional_string(std::uint32_t index) const {
    return index == runtime_xml_absent ? std::string_view{} : string(index);
}
std::span<const RuntimeXmlAttribute> RuntimeXmlDocument::node_attributes(const RuntimeXmlNode &node) const {
    if (node.kind != RuntimeXmlNodeKind::element_start || node.attribute_begin > attributes.size() ||
        node.attribute_count > attributes.size() - node.attribute_begin)
        fail("INVALID", "Runtime XML node attributes are out of bounds");
    return std::span<const RuntimeXmlAttribute>(attributes).subspan(node.attribute_begin, node.attribute_count);
}
RuntimeXmlDocument decode_runtime_xml(Bytes input, std::size_t working_bytes,
                                     const std::function<void(std::uint64_t)> &charge_work) {
    RuntimeXmlDocument output;
    Decoder decoder(input, working_bytes, charge_work, output);
    decoder.decode();
    return output;
}
} // namespace aether::apk
