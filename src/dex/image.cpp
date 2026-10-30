#include "aether/dex/image.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/dex/limits.hpp"
#include "annotations.hpp"
#include "error_context.hpp"
#include "load_diagnostics.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <map>
#include <set>
#include <tuple>

namespace aether::dex {
bool reference_type(std::string_view descriptor) noexcept {
    return !descriptor.empty() && (descriptor.front() == 'L' || descriptor.front() == '[');
}
std::uint32_t type_words(std::string_view descriptor) noexcept {
    return descriptor == "V" ? 0 : (descriptor == "J" || descriptor == "D" ? 2 : 1);
}
namespace {
[[noreturn]] void bad(std::string_view kind, const std::string &message) {
    throw DexError("AETHER_DEX_" + std::string(kind), message);
}
std::string ascii(std::u16string_view value) {
    std::string out;
    if (value.empty() || value.size() > 1024)
        bad("NAME", "Empty or oversized identifier");
    out.reserve(value.size());
    for (const auto c : value) {
        if (c < 0x21 || c > 0x7e)
            bad("NAME_UNSUPPORTED", "Non-ASCII identifiers are not yet supported");
        out.push_back(static_cast<char>(c));
    }
    return out;
}
void descriptor(std::string_view value, bool allow_void = true) {
    std::size_t dimensions = 0;
    while (!value.empty() && value.front() == '[') {
        ++dimensions;
        value.remove_prefix(1);
    }
    if (dimensions > 255 || value.empty())
        bad("DESCRIPTOR", "Invalid array descriptor");
    if (value.size() == 1 && std::string_view("ZBSCIJFDV").find(value.front()) != std::string_view::npos) {
        if (value == "V" && (dimensions || !allow_void))
            bad("DESCRIPTOR", "Void is not a value type");
        return;
    }
    if (value.size() < 3 || value.front() != 'L' || value.back() != ';')
        bad("DESCRIPTOR", "Invalid class descriptor");
    value.remove_prefix(1);
    value.remove_suffix(1);
    if (value.front() == '/' || value.back() == '/' || value.find("//") != std::string_view::npos)
        bad("DESCRIPTOR", "Empty class-name component");
    for (const auto c : value)
        if (!(c == '/' || c == '$' || c == '-' || c == '_' || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
            bad("DESCRIPTOR", "Unsupported character in class descriptor");
}
struct Parser {
    apk::View view;
    DexImage image;
    std::map<std::uint16_t, std::pair<std::uint32_t, std::uint32_t>> sections;
    std::uint64_t decoded_characters = 0, code_units = 0, metadata_bytes = 0;
    // Numeric locations identify malformed metadata without echoing untrusted
    // strings or retaining a copy of the input. Formatting occurs only on failure.
    std::string_view record_kind;
    Index record_index = 0;
    std::uint32_t record_offset = 0;
    explicit Parser(apk::Bytes bytes) : view(bytes, "dex-load") {}
    void record(std::string_view kind, Index index, std::uint32_t offset) noexcept {
        record_kind = kind;
        record_index = index;
        record_offset = offset;
    }
    std::string context() const {
        if (record_kind.empty())
            return {};
        return std::string(record_kind) + "[" + std::to_string(record_index) +
               "] offset=" + std::to_string(record_offset) + ": ";
    }
    void charge(std::uint64_t bytes) {
        if (bytes > decoded_file_bytes - metadata_bytes)
            bad("LIMIT", "Decoded DEX metadata exceeds the 48 MiB per-file budget");
        metadata_bytes += bytes;
    }
    void range(std::uint32_t at, std::size_t size, std::uint16_t type) const {
        const auto it = sections.find(type);
        if (it == sections.end() || at < it->second.first || at > it->second.second ||
            size > it->second.second - at)
            bad("BOUNDS", "DEX item exceeds its declared map section");
    }
    std::uint32_t leb(std::uint32_t &at, std::uint16_t type) const {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 5; ++i) {
            range(at, 1, type);
            const auto b = view.u8(at++);
            if (i == 4 && (b & 0xf0))
                bad("LEB128", "ULEB128 exceeds 32 bits");
            value |= std::uint32_t{b & 0x7fu} << (i * 7);
            if (!(b & 0x80))
                return value;
        }
        bad("LEB128", "Unterminated ULEB128");
    }
    std::int32_t sleb(std::uint32_t &at, std::uint16_t type) const {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 5; ++i) {
            range(at, 1, type);
            const auto b = view.u8(at++);
            if (i == 4 && (b & 0xf8) != 0 && (b & 0xf8) != 0x78)
                bad("LEB128", "SLEB128 exceeds 32 bits");
            value |= std::uint32_t{b & 0x7fu} << (i * 7);
            if (!(b & 0x80)) {
                if (i < 4 && (b & 0x40))
                    value |= ~std::uint32_t{0} << ((i + 1) * 7);
                return std::bit_cast<std::int32_t>(value);
            }
        }
        bad("LEB128", "Unterminated SLEB128");
    }
    void map() {
        try {
        const auto at = view.u32(52), count = view.u32(at);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto p = std::size_t{at} + 4 + std::size_t{i} * 12;
            const auto type = view.u16(p);
            if (type == 0x0007 || type == 0x0008)
                bad("FEATURE_UNSUPPORTED", std::string(type == 0x0007 ? "call_site_id" : "method_handle") +
                                               " map[" + std::to_string(i) +
                                               "] offset=" + std::to_string(view.u32(p + 8)) +
                                               ": Dynamic calls and method handles are not implemented");
            const auto begin = view.u32(p + 8),
                       end = i + 1 == count ? static_cast<std::uint32_t>(view.size()) : view.u32(p + 20);
            sections.emplace(type, std::pair{begin, end});
        }
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::parse_map);throw;
        }
    }
    void strings() {
        try {
        const auto count = view.u32(56), table = view.u32(60);
        if (count > 1'048'576)
            bad("LIMIT", "More than 1048576 DEX strings");
        charge(std::uint64_t{count} * sizeof(std::u16string));
        auto duplicate_id=no_index;
        {
            // inspect_dex has already bounded the entire immutable ID table.
            // Keep this flat scratch only until the earliest repeated ID is
            // known, before any decoded string storage is constructed.
            struct Offset {std::uint32_t raw,id;};
            static_assert(sizeof(Offset)==8);
            std::vector<Offset> offsets;
            offsets.reserve(count);
            for(std::uint32_t i=0;i<count;++i)
                offsets.push_back({view.u32(table+i*4),i});
            std::sort(offsets.begin(),offsets.end(),[](const auto &left,const auto &right) {
                return std::tie(left.raw,left.id)<std::tie(right.raw,right.id);
            });
            for(std::size_t i=1;i<offsets.size();++i)
                if(offsets[i-1].raw==offsets[i].raw)
                    duplicate_id=(std::min)(duplicate_id,offsets[i].id);
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            record("string_id", i, table + i * 4);
            auto at = view.u32(table + i * 4);
            if (i==duplicate_id)
                bad("STRING", "Duplicate string-data offset");
            const auto length = leb(at, 0x2002);
            if (length > 1024 * 1024 || length > 8 * 1024 * 1024 - decoded_characters)
                bad("LIMIT", "DEX decoded strings exceed their budget");
            decoded_characters += length;
            charge(std::uint64_t{length} * sizeof(char16_t));
            std::u16string value;
            value.reserve(length);
            for (std::uint32_t j = 0; j < length; ++j) {
                range(at, 1, 0x2002);
                const auto first = view.u8(at++);
                std::uint16_t c = first;
                if (!first)
                    bad("STRING", "Modified UTF-8 terminates before its UTF-16 length");
                if ((first & 0xe0) == 0xc0) {
                    range(at, 1, 0x2002);
                    const auto second = view.u8(at++);
                    if ((second & 0xc0) != 0x80)
                        bad("STRING", "Invalid modified UTF-8 continuation");
                    c = static_cast<std::uint16_t>(((first & 31) << 6) | (second & 63));
                    if (c && c < 0x80)
                        bad("STRING", "Overlong modified UTF-8 sequence");
                } else if ((first & 0xf0) == 0xe0) {
                    range(at, 2, 0x2002);
                    const auto second = view.u8(at++), third = view.u8(at++);
                    if ((second & 0xc0) != 0x80 || (third & 0xc0) != 0x80)
                        bad("STRING", "Invalid modified UTF-8 continuation");
                    c = static_cast<std::uint16_t>(((first & 15) << 12) | ((second & 63) << 6) |
                                                   (third & 63));
                    if (c < 0x800)
                        bad("STRING", "Overlong modified UTF-8 sequence");
                } else if (first >= 0x80)
                    bad("STRING", "DEX strings require modified UTF-8, not four-byte UTF-8");
                value.push_back(static_cast<char16_t>(c));
            }
            range(at, 1, 0x2002);
            if (view.u8(at))
                bad("STRING", "Modified UTF-8 exceeds declared UTF-16 length");
            if (!image.strings.empty() && image.strings.back() >= value)
                bad("STRING", "String identifiers are not strictly sorted");
            image.strings.push_back(std::move(value));
        }
        record_kind = {};
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::parse_strings);throw;
        }
    }
    std::string name(Index index) const {
        if (index >= image.strings.size())
            bad("INDEX", "String index is out of range");
        return ascii(image.strings[index]);
    }
    const std::string &type(Index index) const {
        if (index >= image.types.size())
            bad("INDEX", "Type index is out of range");
        return image.types[index];
    }
    std::vector<Index> type_list(std::uint32_t at) {
        if (!at)
            return {};
        if (at % 4)
            bad("ALIGNMENT", "Misaligned type list");
        range(at, 4, 0x1001);
        const auto count = view.u32(at);
        if (count > 255)
            bad("LIMIT", "Type list exceeds 255 entries");
        charge(std::uint64_t{count} * sizeof(Index));
        range(at, 4 + std::size_t{count} * 2, 0x1001);
        std::vector<Index> result;
        result.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto index = view.u16(at + 4 + i * 2);
            descriptor(type(index), false);
            result.push_back(index);
        }
        return result;
    }
    void identifiers() {
        auto allocation_phase=ClassLoadAllocationPhase::parse_types;
        try {
        const auto types = view.u32(64), type_table = view.u32(68);
        if (types > 65535)
            bad("LIMIT", "Too many DEX types");
        charge(std::uint64_t{types} * sizeof(std::string));
        Index previous = 0;
        for (Index i = 0; i < types; ++i) {
            record("type_id", i, type_table + i * 4);
            const auto index = view.u32(type_table + i * 4);
            if (i && index <= previous)
                bad("INDEX", "Type identifiers are not strictly sorted");
            auto value = name(index);
            descriptor(value);
            charge(value.size());
            image.types.push_back(std::move(value));
            previous = index;
        }
        record_kind = {};
        allocation_phase=ClassLoadAllocationPhase::parse_prototypes;
        const auto protos = view.u32(72), proto_table = view.u32(76);
        if (protos > 65535)
            bad("LIMIT", "Too many DEX prototypes");
        charge(std::uint64_t{protos} * sizeof(Prototype));
        for (Index i = 0; i < protos; ++i) {
            const auto at = proto_table + i * 12;
            record("proto_id", i, at);
            Prototype p;
            const auto shorty = name(view.u32(at));
            p.return_type = view.u32(at + 4);
            type(p.return_type);
            p.parameters = type_list(view.u32(at + 8));
            // Types are already validated and limited to 1024 bytes, and the
            // parameter list to 255 entries: this sum is at most 262146 bytes.
            std::size_t descriptor_size=2+type(p.return_type).size();
            for(const auto index:p.parameters)descriptor_size+=type(index).size();
            std::string expected(1, reference_type(type(p.return_type)) ? 'L' : type(p.return_type).front());
            p.descriptor = "(";
            p.descriptor.reserve(descriptor_size);
            expected.reserve(p.parameters.size()+1);
            for (const auto index : p.parameters) {
                p.descriptor += type(index);
                p.argument_words += type_words(type(index));
                expected += reference_type(type(index)) ? 'L' : type(index).front();
            }
            p.descriptor.push_back(')');
            p.descriptor += type(p.return_type);
            charge(p.descriptor.size());
            if (p.argument_words > 255 || shorty != expected)
                bad("PROTOTYPE", "Invalid shorty or argument word count");
            if (!image.prototypes.empty()) {
                const auto &last = image.prototypes.back();
                if (std::tie(last.return_type, last.parameters) >= std::tie(p.return_type, p.parameters))
                    bad("PROTOTYPE", "Prototype identifiers are not strictly sorted");
            }
            image.prototypes.push_back(std::move(p));
        }
        record_kind = {};
        allocation_phase=ClassLoadAllocationPhase::parse_fields;
        const auto fields = view.u32(80), field_table = view.u32(84);
        if (fields > 65535)
            bad("LIMIT", "Too many DEX fields");
        charge(std::uint64_t{fields} * sizeof(Field));
        std::tuple<Index, Index, Index> last_field{};
        for (Index i = 0; i < fields; ++i) {
            const auto at = field_table + i * 8;
            record("field_id", i, at);
            Field f;
            f.owner = view.u16(at);
            f.type = view.u16(at + 2);
            const auto name_id = view.u32(at + 4);
            if (type(f.owner).front() != 'L' || type(f.type) == "V")
                bad("FIELD", "Invalid field owner or value type");
            f.name = name(name_id);
            charge(f.name.size());
            const auto key = std::tuple{f.owner, name_id, f.type};
            if (i && key <= last_field)
                bad("FIELD", "Field identifiers are not strictly sorted");
            last_field = key;
            image.fields.push_back(std::move(f));
        }
        record_kind = {};
        allocation_phase=ClassLoadAllocationPhase::parse_methods;
        const auto methods = view.u32(88), method_table = view.u32(92);
        if (methods > 65535)
            bad("LIMIT", "Too many DEX methods");
        charge(std::uint64_t{methods} * method_metadata_charge);
        std::tuple<Index, Index, Index> last_method{};
        for (Index i = 0; i < methods; ++i) {
            const auto at = method_table + i * 8;
            record("method_id", i, at);
            Method m;
            m.owner = view.u16(at);
            m.prototype = view.u16(at + 2);
            const auto name_id = view.u32(at + 4);
            if (!reference_type(type(m.owner)))
                bad("METHOD", "Method owner must be a class or array type");
            if (m.prototype >= image.prototypes.size())
                bad("METHOD", "Method prototype index is out of range");
            m.name = name(name_id);
            charge(m.name.size());
            const auto key = std::tuple{m.owner, name_id, m.prototype};
            if (i && key <= last_method)
                bad("METHOD", "Method identifiers are not strictly sorted");
            last_method = key;
            image.methods.push_back(std::move(m));
        }
        record_kind = {};
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(allocation_phase);throw;
        }
    }
    Code code(std::uint32_t start, const Method &method) {
        try {
        if (start % 4)
            bad("ALIGNMENT", "Misaligned code item");
        range(start, 16, 0x2001);
        Code result;
        result.file_offset = start;
        result.registers = view.u16(start);
        result.incoming = view.u16(start + 2);
        result.outgoing = view.u16(start + 4);
        const auto tries = view.u16(start + 6);
        const auto debug = view.u32(start + 8), count = view.u32(start + 12);
        if (result.registers > 256 || result.incoming > result.registers || result.outgoing > 256)
            bad("LIMIT", "Code item exceeds the 256-register frame/call bound");
        if (!count || count > 65536 || count > 4 * 1024 * 1024 - code_units)
            bad("LIMIT", "Code item exceeds the 65536-unit method or 4 Mi-unit file bound");
        if (tries > 4096)
            bad("LIMIT", "Code item exceeds 4096 exception regions");
        code_units += count;
        charge(std::uint64_t{count} * sizeof(std::uint16_t) + std::uint64_t{tries} * sizeof(TryBlock));
        if (result.incoming !=
            image.prototypes[method.prototype].argument_words + ((method.flags & 8) ? 0u : 1u))
            bad("CODE", "Incoming register count does not match method prototype");
        if (debug)
            range(debug, 1, 0x2003); // Debug metadata is not executed.
        range(start, 16 + std::size_t{count} * 2, 0x2001);
        try { result.units.reserve(count); }
        catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::code_units);throw;
        }
        for (std::uint32_t i = 0; i < count; ++i)
            result.units.push_back(view.u16(start + 16 + i * 2));
        if (!tries)
            return result;
        auto at = start + 16 + count * 2;
        if (count & 1) {
            range(at, 2, 0x2001);
            if (view.u16(at))
                bad("CODE", "Nonzero try-table padding");
            at += 2;
        }
        range(at, std::size_t{tries} * 8, 0x2001);
        const auto try_start = at, handlers_start = at + std::uint32_t{tries} * 8;
        at = handlers_start;
        const auto handlers_count = leb(at, 0x2001);
        if (!handlers_count || handlers_count > 4096)
            bad("LIMIT", "Code item requires 1 through 4096 catch-handler lists");
        auto handlers=[] {
            try { return std::map<std::uint32_t,std::vector<CatchHandler>>{}; }
            catch(const std::bad_alloc &) {
                detail::note_class_load_allocation(ClassLoadAllocationPhase::code_handler_index);throw;
            }
        }();
        std::uint32_t handler_items = 0;
        for (std::uint32_t i = 0; i < handlers_count; ++i) {
            const auto offset = at - handlers_start;
            const auto signed_count = sleb(at, 0x2001);
            if (signed_count < -256 || signed_count > 256)
                bad("LIMIT", "Oversized catch handler");
            const auto typed = static_cast<std::uint32_t>(signed_count < 0 ? -signed_count : signed_count);
            const auto items = typed + (signed_count <= 0 ? 1u : 0u);
            if (items > 65536 - handler_items)
                bad("LIMIT", "Code item exceeds 65536 temporary catch-handler entries");
            handler_items += items;
            auto list=[] {
                try { return std::vector<CatchHandler>{}; }
                catch(const std::bad_alloc &) {
                    detail::note_class_load_allocation(ClassLoadAllocationPhase::code_handler_list);throw;
                }
            }();
            try { list.reserve(items); }
            catch(const std::bad_alloc &) {
                detail::note_class_load_allocation(ClassLoadAllocationPhase::code_handler_list);throw;
            }
            auto catch_types=[] {
                try { return std::set<Index>{}; }
                catch(const std::bad_alloc &) {
                    detail::note_class_load_allocation(ClassLoadAllocationPhase::code_handler_types);throw;
                }
            }();
            for (std::uint32_t j = 0; j < typed; ++j) {
                const auto index = leb(at, 0x2001), target = leb(at, 0x2001);
                if (type(index).front() != 'L' || target >= count || ![&] {
                        try { return catch_types.insert(index).second; }
                        catch(const std::bad_alloc &) {
                            detail::note_class_load_allocation(ClassLoadAllocationPhase::code_handler_types);throw;
                        }
                    }())
                    bad("CODE", "Invalid catch type or target");
                list.push_back({index, target});
            }
            if (signed_count <= 0) {
                const auto target = leb(at, 0x2001);
                if (target >= count)
                    bad("CODE", "Invalid catch-all target");
                list.push_back({no_index, target});
            }
            try { handlers.emplace(offset, std::move(list)); }
            catch(const std::bad_alloc &) {
                detail::note_class_load_allocation(ClassLoadAllocationPhase::code_handler_index);throw;
            }
        }
        std::uint32_t previous_end = 0;
        try { result.tries.reserve(tries); }
        catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::code_try_regions);throw;
        }
        for (std::uint32_t i = 0; i < tries; ++i) {
            const auto p = try_start + i * 8;
            const auto begin = view.u32(p);
            const auto length = view.u16(p + 4), handler = view.u16(p + 6);
            if (begin >= count || !length || length > count - begin || (i && begin < previous_end) ||
                !handlers.contains(handler))
                bad("CODE", "Invalid, overlapping or unbound try region");
            charge(handlers.at(handler).size() * sizeof(CatchHandler));
            try { result.tries.push_back({begin, length, handlers.at(handler)}); }
            catch(const std::bad_alloc &) {
                detail::note_class_load_allocation(ClassLoadAllocationPhase::code_try_publish);throw;
            }
            previous_end = begin + length;
        }
        return result;
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::parse_code);throw;
        }
    }
    EncodedValue value(std::uint32_t &at) const {
        range(at, 1, 0x2005);
        const auto header = view.u8(at++), kind = static_cast<std::uint8_t>(header & 31);
        const auto arg = static_cast<unsigned>(header >> 5);
        EncodedValue result{kind, 0};
        if (kind == 0x1e) {
            if (arg)
                bad("VALUE", "Invalid encoded null");
            return result;
        }
        if (kind == 0x1f) {
            if (arg > 1)
                bad("VALUE", "Invalid encoded boolean");
            result.bits = arg;
            return result;
        }
        const unsigned width =
            kind == 0 ? 1
                      : (kind == 2 || kind == 3 ? 2
                                                : (kind == 4 || kind == 0x10 || kind == 0x17 || kind == 0x18
                                                       ? 4
                                                       : (kind == 6 || kind == 0x11 ? 8 : 0)));
        if (!width || arg >= width)
            bad("VALUE_UNSUPPORTED", "Unsupported or malformed encoded static value");
        range(at, arg + 1, 0x2005);
        for (unsigned i = 0; i <= arg; ++i)
            result.bits |= std::uint64_t{view.u8(at++)} << (i * 8);
        if (kind == 0x10 || kind == 0x11)
            result.bits <<= (width - arg - 1) * 8;
        else if ((kind == 0 || kind == 2 || kind == 4 || kind == 6) && arg < 7 &&
                 (result.bits & (std::uint64_t{0x80} << (arg * 8))))
            result.bits |= ~std::uint64_t{0} << ((arg + 1) * 8);
        if ((kind == 0x17 && result.bits >= image.strings.size()) ||
            (kind == 0x18 && result.bits >= image.types.size()))
            bad("INDEX", "Encoded static reference index is out of range");
        return result;
    }
    void classes() {
        try {
        const auto count = view.u32(96), table = view.u32(100);
        if (count > 16384)
            bad("LIMIT", "Too many class definitions");
        charge(std::uint64_t{count} * sizeof(Class));
        std::set<Index> defined;
        for (Index i = 0; i < count; ++i) {
            const auto p = table + i * 32;
            Class c;
            c.type = view.u32(p);
            c.flags = view.u32(p + 4);
            c.superclass = view.u32(p + 8);
            if (type(c.type).front() != 'L' || !defined.insert(c.type).second ||
                (c.superclass != no_index && (type(c.superclass).front() != 'L' || c.superclass == c.type)))
                bad("CLASS", "Invalid class definition or superclass");
            c.interfaces = type_list(view.u32(p + 12));
            std::set<Index> interfaces;
            for (auto index : c.interfaces)
                if (type(index).front() != 'L' || !interfaces.insert(index).second)
                    bad("CLASS", "Invalid interface list");
            const auto source = view.u32(p + 16), annotations = view.u32(p + 20);
            if (source != no_index && source >= image.strings.size())
                bad("INDEX", "Invalid source-file index");
            if (annotations)
                range(annotations, 16, 0x2006); // Full typed validation follows class declarations.
            auto at = view.u32(p + 24);
            if (at) {
                const auto statics = leb(at, 0x2000), instances = leb(at, 0x2000), direct = leb(at, 0x2000),
                           virtuals = leb(at, 0x2000);
                if (statics > image.fields.size() || instances > image.fields.size() ||
                    direct > image.methods.size() || virtuals > image.methods.size())
                    bad("LIMIT", "Class-data item counts exceed identifier tables");
                charge((std::uint64_t{statics} + instances + direct + virtuals) * sizeof(Index));
                const auto fields = [&](std::uint32_t n, bool is_static, std::vector<Index> &out) {
                    out.reserve(n);
                    Index index = 0;
                    for (Index j = 0; j < n; ++j) {
                        const auto delta = leb(at, 0x2000), flags = leb(at, 0x2000);
                        if ((j && !delta) || delta > image.fields.size() ||
                            index > image.fields.size() - delta || index + delta >= image.fields.size())
                            bad("INDEX", "Invalid encoded field index");
                        index += delta;
                        auto &f = image.fields[index];
                        if (f.declared || f.owner != c.type || ((flags & 8) != 0) != is_static)
                            bad("FIELD", "Field declaration does not match its class/category");
                        f.declared = true;
                        f.flags = flags;
                        out.push_back(index);
                    }
                };
                fields(statics, true, c.static_fields);
                fields(instances, false, c.instance_fields);
                const auto methods = [&](std::uint32_t n, bool is_direct, std::vector<Index> &out) {
                    out.reserve(n);
                    Index index = 0;
                    for (Index j = 0; j < n; ++j) {
                        const auto delta = leb(at, 0x2000), flags = leb(at, 0x2000),
                                   code_offset = leb(at, 0x2000);
                        if ((j && !delta) || delta > image.methods.size() ||
                            index > image.methods.size() - delta || index + delta >= image.methods.size())
                            bad("INDEX", "Invalid encoded method index");
                        index += delta;
                        auto &m = image.methods[index];
                        if (m.declared || m.owner != c.type ||
                            ((flags & (0x100 | 0x400)) != 0) != (code_offset == 0))
                            bad("METHOD", "Invalid method definition or missing code");
                        if (is_direct != ((flags & (8 | 2 | 0x10000)) != 0))
                            bad("METHOD", "Method belongs in a different dispatch category");
                        if (image.version < 37 && (c.flags & 0x200) && code_offset && m.name != "<clinit>")
                            bad("VERSION_UNSUPPORTED", "Interface method bodies require DEX 037");
                        m.declared = true;
                        m.direct = is_direct;
                        m.flags = flags;
                        if (code_offset) {
                            record("code_item", index, code_offset);
                            try {
                                m.code = code(code_offset, m);
                            } catch(const std::bad_alloc &) {
                                detail::note_class_load_allocation(ClassLoadAllocationPhase::code_storage_publish);throw;
                            }
                            record_kind = {};
                        }
                        out.push_back(index);
                    }
                };
                methods(direct, true, c.direct_methods);
                methods(virtuals, false, c.virtual_methods);
            }
            auto values = view.u32(p + 28);
            if (values) {
                const auto n = leb(values, 0x2005);
                if (n > c.static_fields.size())
                    bad("VALUE", "More static values than static fields");
                charge(std::uint64_t{n} * sizeof(EncodedValue));
                c.static_values.reserve(n);
                for (std::uint32_t j = 0; j < n; ++j)
                    c.static_values.push_back(value(values));
            }
            image.classes.push_back(std::move(c));
        }
        // A bounded graph check rejects inheritance cycles before any runtime class initialization.
        std::map<Index, std::size_t> definitions;
        for (std::size_t i = 0; i < image.classes.size(); ++i)
            definitions.emplace(image.classes[i].type, i);
        for (const auto &c : image.classes) {
            std::set<Index> visited;
            auto index = c.type;
            while (definitions.contains(index)) {
                if (visited.size() >= 256 || !visited.insert(index).second)
                    bad("CLASS", "Cyclic or excessively deep superclass chain");
                index = image.classes[definitions.at(index)].superclass;
            }
        }
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::parse_classes);throw;
        }
    }
};
} // namespace
DexImage parse(std::span<const std::uint8_t> bytes) {
    auto allocation_phase=ClassLoadAllocationPhase::parse_header;
    try {
    if (bytes.size() > source_file_bytes)
        bad("LIMIT", "DEX input exceeds 64 MiB");
    Parser p(bytes);
    try {
        const auto inventory = apk::inspect_dex(bytes);
        if (inventory.version != "035" && inventory.version != "037" && inventory.version != "038")
            bad("VERSION_UNSUPPORTED", "Executable DEX loading supports versions 035, 037 and 038");
        p.image.version = inventory.version == "038" ? 38 : (inventory.version == "037" ? 37 : 35);
        allocation_phase=ClassLoadAllocationPhase::parse_map;
        p.map();
        allocation_phase=ClassLoadAllocationPhase::parse_strings;
        p.strings();
        allocation_phase=ClassLoadAllocationPhase::parse_types;
        p.identifiers();
        allocation_phase=ClassLoadAllocationPhase::parse_classes;
        p.classes();
        allocation_phase=ClassLoadAllocationPhase::parse_annotations;
        validate_annotations(bytes, p.image);
        allocation_phase=ClassLoadAllocationPhase::archive_hash;
        p.image.sha256 = apk::sha256(bytes);
        return std::move(p.image);
    } catch(const std::bad_alloc &) {
        detail::note_class_load_allocation(allocation_phase);throw;
    } catch (const DexError &error) {
        if (p.record_kind.empty())
            throw;
        detail::throw_dex_error_context(error,[&] { return p.context(); });
        throw;
    } catch (const apk::InspectError &error) {
        throw DexError(error.diagnostic.code, p.context() + error.what());
    }
    } catch(const std::bad_alloc &) {
        detail::note_class_load_allocation(allocation_phase);throw;
    }
}
Index DexImage::method(std::string_view owner, std::string_view name, std::string_view signature) const {
    for (Index i = 0; i < methods.size(); ++i)
        if (types[methods[i].owner] == owner && methods[i].name == name &&
            prototypes[methods[i].prototype].descriptor == signature)
            return i;
    bad("METHOD_NOT_FOUND",
        "Method not found: " + std::string(owner) + "." + std::string(name) + std::string(signature));
}
const Class *DexImage::definition(std::string_view descriptor) const noexcept {
    for (const auto &c : classes)
        if (types[c.type] == descriptor)
            return &c;
    return nullptr;
}
} // namespace aether::dex
