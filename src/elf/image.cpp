#include "aether/elf/guest_loader.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <set>

namespace aether::elf {
ElfError::ElfError(std::string code_, std::string message)
    : std::runtime_error(std::move(message)), code(std::move(code_)) {}
namespace {
constexpr std::uint64_t maximum_bytes = 64 * 1024 * 1024, maximum_symbols = 65536;
[[noreturn]] void fail(std::string_view kind, const std::string &message) {
    throw ElfError("AETHER_ELF_" + std::string(kind), message);
}
class View {
  public:
    explicit View(Bytes bytes) : bytes_(bytes), size_(bytes.size()) {}
    explicit View(ModuleSource &source) : source_(&source), size_(source.size()) {}
    void bounds(std::uint64_t offset, std::uint64_t size) const {
        if (offset > size_ || size > size_ - offset)
            fail("BOUNDS", "ELF structure exceeds its file-backed range");
    }
    Bytes range(std::uint64_t offset, std::uint64_t size) const {
        bounds(offset, size);
        if (!source_)
            return bytes_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(size));
        for (const auto &[begin, bytes] : cache_)
            if (offset >= begin && offset - begin <= bytes.size() && size <= bytes.size() - (offset - begin))
                return Bytes(bytes).subspan(static_cast<std::size_t>(offset - begin),
                                            static_cast<std::size_t>(size));
        // Reuse a bounded read-ahead window for nearby symbol/relocation records.
        // Validate-only extents never call this function or allocate their length.
        constexpr std::uint64_t window = 2ULL * 1024 * 1024, maximum = 16ULL * 1024 * 1024;
        const auto begin = offset / window * window;
        const auto count = (std::min)(size_ - begin, (std::max)(window, offset - begin + size));
        if (count > maximum - retained_ || cache_.size() >= 16)
            fail("LIMIT", "Native metadata exceeds 16 MiB of retained read windows");
        auto bytes = source_->read(begin, static_cast<std::size_t>(count));
        if (bytes.size() != count)
            fail("SOURCE", "Native metadata source returned an incomplete range");
        retained_ += count;
        cache_.emplace_back(begin, std::move(bytes));
        return Bytes(cache_.back().second)
            .subspan(static_cast<std::size_t>(offset - begin), static_cast<std::size_t>(size));
    }
    std::uint8_t u8(std::uint64_t p) const { return range(p, 1)[0]; }
    std::uint16_t u16(std::uint64_t p) const {
        const auto b = range(p, 2);
        return static_cast<std::uint16_t>(b[0] | (std::uint16_t{b[1]} << 8));
    }
    std::uint32_t u32(std::uint64_t p) const {
        const auto b = range(p, 4);
        return b[0] | (std::uint32_t{b[1]} << 8) | (std::uint32_t{b[2]} << 16) | (std::uint32_t{b[3]} << 24);
    }
    std::uint64_t u64(std::uint64_t p) const {
        range(p, 8);
        return u32(p) | (std::uint64_t{u32(p + 4)} << 32);
    }

  private:
    Bytes bytes_;
    ModuleSource *source_ = nullptr;
    std::uint64_t size_;
    mutable std::uint64_t retained_ = 0;
    mutable std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> cache_;
};
std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        fail("BOUNDS", "ELF integer addition overflows");
    return a + b;
}
std::uint64_t page_down(std::uint64_t n) { return n & ~std::uint64_t{4095}; }
std::uint64_t page_up(std::uint64_t n) { return page_down(add(n, 4095)); }
bool contained(std::uint64_t p, std::uint64_t n, std::uint64_t start, std::uint64_t size) {
    return p >= start && p - start <= size && n <= size - (p - start);
}
bool library_name(std::string_view s) {
    return !s.empty() && s.size() <= 127 && s.ends_with(".so") &&
           std::all_of(s.begin(), s.end(),
                       [](unsigned char c) {
                           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '+';
                       }) &&
           s.find("..") == std::string_view::npos;
}
struct Parser {
    View file;
    ElfImage image;
    std::map<std::uint64_t, std::uint64_t> dynamic;
    std::vector<std::uint64_t> needed;
    std::uint64_t dynamic_offset = 0, dynamic_address = 0, dynamic_size = 0;
    std::uint64_t string_offset = 0, string_size = 0;
    mutable std::size_t decoded_string_bytes = 0;
    explicit Parser(Bytes bytes) : file(bytes) {}
    explicit Parser(ModuleSource &source)
        : file(source), span_limit(streamed_native_bytes), relocation_limit(1'048'576) {}
    std::uint64_t span_limit = maximum_bytes, relocation_limit = maximum_symbols;
    std::uint64_t offset(std::uint64_t address, std::uint64_t size) const {
        for (const auto &s : image.segments)
            if (contained(address, size, s.address, s.file_size))
                return s.offset + address - s.address;
        fail("BOUNDS", "Dynamic address is not wholly file-backed by one PT_LOAD");
    }
    const Segment &segment(std::uint64_t address, std::uint64_t size) const {
        for (const auto &s : image.segments)
            if (contained(address, size, s.address, s.memory_size))
                return s;
        fail("BOUNDS", "ELF address is outside loadable memory");
    }
    std::string string(std::uint64_t index) const {
        if (index >= string_size)
            fail("STRING", "ELF string index exceeds DT_STRSZ");
        const auto bytes =
            file.range(string_offset + index, std::min<std::uint64_t>(string_size - index, 4097));
        const auto end = std::find(bytes.begin(), bytes.end(), 0);
        if (end == bytes.end())
            fail("STRING", "Unterminated or oversized ELF string");
        const auto length = static_cast<std::size_t>(end - bytes.begin());
        if (length > 8 * 1024 * 1024 - decoded_string_bytes)
            fail("LIMIT", "Expanded dynamic names exceed 8 MiB");
        decoded_string_bytes += length;
        for (auto i = bytes.begin(); i != end; ++i)
            if (*i < 32 || *i > 126)
                fail("STRING", "Non-ASCII dynamic names are unsupported");
        return {bytes.begin(), end};
    }
    std::uint64_t get(std::uint64_t tag) const {
        const auto it = dynamic.find(tag);
        return it == dynamic.end() ? 0 : it->second;
    }
    bool has(std::uint64_t tag) const { return dynamic.contains(tag); }
    void headers() {
        file.bounds(0, 64);
        if (file.u32(0) != 0x464c457f || file.u8(4) != 2 || file.u8(5) != 1 || file.u8(6) != 1 ||
            file.u8(7) != 0 || file.u8(8) != 0 || file.u16(16) != 3 || file.u16(18) != 183 ||
            file.u32(20) != 1 || file.u32(48) != 0 || file.u16(52) != 64 || file.u16(54) != 56)
            fail("ABI", "Expected little-endian ELF64 AArch64 Android ET_DYN with standard headers");
        const auto ph = file.u64(32);
        const auto count = file.u16(56);
        if (!count || count > 128 || ph < 64 || ph % 8)
            fail("HEADER", "Invalid or oversized ELF program-header table");
        file.bounds(ph, std::uint64_t{count} * 56);
        bool relro_seen = false;
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto p = ph + i * 56;
            const auto type = file.u32(p), flags = file.u32(p + 4);
            const auto off = file.u64(p + 8), address = file.u64(p + 16);
            const auto filesz = file.u64(p + 32), memsz = file.u64(p + 40), align = file.u64(p + 48);
            file.bounds(off, filesz);
            add(address, memsz);
            if (type == 7)
                fail("TLS_UNSUPPORTED", "PT_TLS requires a guest TLS implementation");
            if (type == 3)
                fail("ABI", "PT_INTERP is not accepted for shared library loading");
            if (type == 0x6474e551 && (flags & 1))
                fail("PERMISSION", "Executable guest stacks are prohibited");
            if (type == 1) {
                if (!memsz || filesz > memsz || memsz > span_limit || address >= span_limit ||
                    memsz > span_limit - address ||
                    (align > 1 &&
                     (!std::has_single_bit(align) || align > 65536 || off % align != address % align)) ||
                    (flags & ~7u) || !(flags & 4) || (flags & 3) == 3)
                    fail("SEGMENT", "Invalid, oversized or incompatible PT_LOAD permissions/alignment");
                for (const auto &old : image.segments)
                    if (page_down(address) < page_up(old.address + old.memory_size) &&
                        page_down(old.address) < page_up(address + memsz))
                        fail("SEGMENT_OVERLAP", "Overlapping guest load pages are unsupported");
                auto permissions = a64::Permission::read;
                if (flags & 2)
                    permissions = permissions | a64::Permission::write;
                if (flags & 1)
                    permissions = permissions | a64::Permission::execute;
                image.segments.push_back({off, address, filesz, memsz, permissions});
                image.span = std::max(image.span, page_up(address + memsz));
            } else if (type == 2) {
                if (dynamic_size || !filesz || filesz != memsz || filesz % 16 || filesz > 65536)
                    fail("DYNAMIC", "Invalid or duplicate PT_DYNAMIC");
                dynamic_offset = off;
                dynamic_address = address;
                dynamic_size = filesz;
            } else if (type == 0x6474e552) {
                if (relro_seen || !memsz)
                    fail("RELRO", "Invalid or duplicate PT_GNU_RELRO");
                relro_seen = true;
                image.relro_begin = address;
                image.relro_end = address + memsz;
            } else if (type != 0 && type != 4 && type != 6 && type != 0x6474e550 && type != 0x6474e551 &&
                       type != 0x6474e553) {
                fail("PROGRAM_HEADER_UNSUPPORTED", "Unsupported program-header type " + std::to_string(type));
            }
        }
        if (image.segments.empty() || !dynamic_size ||
            offset(dynamic_address, dynamic_size) != dynamic_offset)
            fail("DYNAMIC", "PT_DYNAMIC must be uniquely backed by loadable file bytes");
        if (relro_seen) {
            // Linkers may include the owning LOAD's final mapped-page padding.
            // The raw start must still name actual segment memory; other dynamic
            // metadata continues to use exact segment extents through segment().
            const auto &s = segment(image.relro_begin, 1);
            if (!a64::has(s.permissions, a64::Permission::write) ||
                image.relro_end > page_up(s.address + s.memory_size))
                fail("RELRO", "GNU RELRO must stay within its owning writable load mapping");
            image.relro_begin = page_down(image.relro_begin);
            image.relro_end = page_up(image.relro_end);
        }
    }
    void dynamics() {
        bool terminated = false;
        for (std::uint64_t i = 0; i < dynamic_size; i += 16) {
            const auto tag = file.u64(dynamic_offset + i), value = file.u64(dynamic_offset + i + 8);
            if (!tag) {
                terminated = true;
                break;
            }
            if (tag == 1) {
                if (needed.size() >= 64)
                    fail("LIMIT", "Too many ELF dependencies");
                needed.push_back(value);
                continue;
            }
            switch (tag) {
            case 17:
            case 18:
            case 19:
            case 35:
            case 36:
            case 37:
            case 0x6000000f:
            case 0x60000010:
            case 0x60000011:
            case 0x60000012:
            case 0x6fffe000:
            case 0x6fffe001:
            case 0x6fffe003:
                fail("RELOCATION_FORMAT_UNSUPPORTED",
                     "Unsupported dynamic relocation tag " + std::to_string(tag));
            case 22:
                fail("TEXT_RELOCATION", "Text relocations are prohibited");
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 20:
            case 21:
            case 23:
            case 25:
            case 26:
            case 27:
            case 28:
            case 30:
            case 0x6ffffef5:
            case 0x6ffffff0:
            case 0x6ffffff9:
            case 0x6ffffffb:
            case 0x6ffffffc:
            case 0x6ffffffd:
            case 0x6ffffffe:
            case 0x6fffffff:
                break;
            default:
                fail("DYNAMIC_UNSUPPORTED", "Unsupported dynamic tag " + std::to_string(tag));
            }
            if (!dynamic.emplace(tag, value).second)
                fail("DYNAMIC", "Duplicate dynamic tag " + std::to_string(tag));
        }
        if (!terminated || !has(5) || !has(10) || !get(10) || get(10) > 4 * 1024 * 1024 || !has(6) ||
            get(11) != 24 || (!has(4) && !has(0x6ffffef5)))
            fail("DYNAMIC", "Missing dynamic terminator, symbol/hash/string table or invalid entry size");
        if ((get(30) & ~std::uint64_t{8}) || (get(0x6ffffffb) & ~std::uint64_t{1}))
            fail("DYNAMIC_UNSUPPORTED", "Only BIND_NOW dynamic flags are currently supported");
        string_size = get(10);
        string_offset = offset(get(5), string_size);
        if (file.u8(string_offset) || file.u8(string_offset + string_size - 1))
            fail("STRING", "Dynamic string table requires leading and trailing NUL bytes");
        if (!has(14) || !library_name(image.soname = string(get(14))))
            fail("SONAME", "A safe, explicit DT_SONAME is required");
        for (const auto name : needed) {
            auto dependency = string(name);
            if (!library_name(dependency))
                fail("DEPENDENCY", "Invalid DT_NEEDED basename in " + image.soname);
            if (dependency == image.soname)
                fail("DEPENDENCY", "Self-referencing DT_NEEDED in " + image.soname);
            if (std::find(image.needed.begin(), image.needed.end(), dependency) != image.needed.end())
                fail("DEPENDENCY", "Duplicate DT_NEEDED " + dependency + " in " + image.soname);
            image.needed.push_back(std::move(dependency));
        }
    }
    std::uint64_t symbol_count() const {
        std::uint64_t count = 0;
        if (has(4)) {
            const auto p = offset(get(4), 8);
            const auto buckets = file.u32(p), chains = file.u32(p + 4);
            if (!buckets || buckets > maximum_symbols || !chains || chains > maximum_symbols)
                fail("HASH", "Invalid SysV hash counts");
            const auto table = offset(get(4), 8 + (std::uint64_t{buckets} + chains) * 4);
            for (std::uint64_t i = 0; i < std::uint64_t{buckets} + chains; ++i)
                if (file.u32(table + 8 + i * 4) >= chains)
                    fail("HASH", "SysV hash references an invalid dynamic symbol");
            count = chains;
        }
        if (has(0x6ffffef5)) {
            const auto address = get(0x6ffffef5), p = offset(address, 16);
            const auto buckets = file.u32(p), first = file.u32(p + 4), bloom = file.u32(p + 8);
            if (!buckets || buckets > maximum_symbols || !first || first > maximum_symbols || !bloom ||
                bloom > 16384 || !std::has_single_bit(bloom) || file.u32(p + 12) >= 64)
                fail("HASH", "Invalid GNU hash header");
            const auto bucket_address = add(address, 16 + std::uint64_t{bloom} * 8);
            const auto bucket_offset = offset(bucket_address, std::uint64_t{buckets} * 4);
            const auto chain_address = add(bucket_address, std::uint64_t{buckets} * 4);
            std::uint64_t last = first, visits = 0;
            for (std::uint64_t i = 0; i < buckets; ++i) {
                auto index = std::uint64_t{file.u32(bucket_offset + i * 4)};
                if (!index)
                    continue;
                if (index < first || index >= maximum_symbols)
                    fail("HASH", "GNU hash bucket is outside the supported symbol range");
                for (;;) {
                    if (index >= maximum_symbols || ++visits > maximum_symbols * 2)
                        fail("HASH", "GNU hash chain is unterminated or exceeds its work budget");
                    const auto value = file.u32(offset(add(chain_address, (index - first) * 4), 4));
                    last = std::max(last, index + 1);
                    if (value & 1)
                        break;
                    ++index;
                }
            }
            if (count && count != last)
                fail("HASH", "GNU and SysV symbol counts disagree");
            count = last;
        }
        return count;
    }
    void symbols() {
        const auto count = symbol_count(), p = offset(get(6), count * 24);
        image.symbols.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto at = p + i * 24;
            Symbol s;
            s.name = string(file.u32(at));
            const auto info = file.u8(at + 4), other = file.u8(at + 5);
            const auto section = file.u16(at + 6);
            s.binding = info >> 4;
            s.type = info & 15;
            s.visibility = other & 3;
            s.value = file.u64(at + 8);
            s.size = file.u64(at + 16);
            s.defined = section != 0;
            s.absolute = section == 0xfff1;
            if (s.type == 6)
                fail("TLS_UNSUPPORTED", "STT_TLS symbol " + s.name);
            if (s.type == 10)
                fail("IFUNC_UNSUPPORTED", "GNU indirect function " + s.name);
            if (s.binding > 2 || s.type > 3 || (other & ~3u) || (section >= 0xff00 && !s.absolute) ||
                (!s.defined && s.value) || (i && !s.defined && (s.binding == 0 || s.visibility != 0)) ||
                (!i && (!s.name.empty() || info || other || section || s.value || s.size)))
                fail("SYMBOL", "Unsupported or malformed dynamic symbol " + s.name);
            if (s.defined && !s.absolute) {
                const auto &load = segment(s.value, std::max<std::uint64_t>(s.size, 1));
                if (s.type == 2 && (s.value % 4 || !a64::has(load.permissions, a64::Permission::execute)))
                    fail("SYMBOL", "Function symbol is outside aligned executable memory: " + s.name);
            }
            image.symbols.push_back(std::move(s));
        }
    }
    void versions() {
        struct Version {
            std::string name, library;
            bool definition = false;
        };
        std::map<std::uint16_t, Version> versions;
        if (has(0x6ffffffe) != has(0x6fffffff) || has(0x6ffffffc) != has(0x6ffffffd))
            fail("VERSION", "Incomplete symbol version table");
        const auto need_count = get(0x6fffffff), def_count = get(0x6ffffffd);
        if (need_count > 64 || def_count > 256)
            fail("LIMIT", "Oversized version table");
        auto address = get(0x6ffffffe);
        for (std::uint64_t i = 0; i < need_count; ++i) {
            const auto p = offset(address, 16);
            const auto count = file.u16(p + 2);
            const auto library = string(file.u32(p + 4));
            if (file.u16(p) != 1 || !count || count > 256 || file.u32(p + 8) < 16 ||
                std::find(image.needed.begin(), image.needed.end(), library) == image.needed.end())
                fail("VERSION", "Invalid version dependency record");
            auto aux = add(address, file.u32(p + 8));
            for (std::uint64_t j = 0; j < count; ++j) {
                const auto a = offset(aux, 16);
                const auto index = file.u16(a + 6), flags = file.u16(a + 4);
                const auto name = string(file.u32(a + 8));
                if (index < 2 || index >= 0x8000 || flags || name.empty() ||
                    !versions.emplace(index, Version{name, library, false}).second)
                    fail("VERSION", "Invalid or duplicate version requirement");
                const auto next = file.u32(a + 12);
                if ((j + 1 < count && next < 16) || (j + 1 == count && next))
                    fail("VERSION", "Invalid version requirement chain");
                aux = add(aux, next);
            }
            const auto next = file.u32(p + 12);
            if ((i + 1 < need_count && next < 16) || (i + 1 == need_count && next))
                fail("VERSION", "Invalid version dependency chain");
            address = add(address, next);
        }
        address = get(0x6ffffffc);
        for (std::uint64_t i = 0; i < def_count; ++i) {
            const auto p = offset(address, 20);
            const auto index = file.u16(p + 4), count = file.u16(p + 6);
            if (file.u16(p) != 1 || !index || index >= 0x8000 || !count || count > 64 ||
                file.u16(p + 2) > 1 || file.u32(p + 12) < 20)
                fail("VERSION", "Invalid version definition record");
            auto aux = add(address, file.u32(p + 12));
            std::string name;
            for (std::uint64_t j = 0; j < count; ++j) {
                const auto a = offset(aux, 8);
                auto item = string(file.u32(a));
                if (item.empty())
                    fail("VERSION", "Empty version definition name");
                if (!j)
                    name = std::move(item);
                const auto next = file.u32(a + 4);
                if ((j + 1 < count && next < 8) || (j + 1 == count && next))
                    fail("VERSION", "Invalid version definition auxiliary chain");
                aux = add(aux, next);
            }
            if (!versions.emplace(index, Version{name, image.soname, true}).second)
                fail("VERSION", "Duplicate version definition index");
            const auto next = file.u32(p + 16);
            if ((i + 1 < def_count && next < 20) || (i + 1 == def_count && next))
                fail("VERSION", "Invalid version definition chain");
            address = add(address, next);
        }
        if (!has(0x6ffffff0)) {
            if (need_count || def_count)
                fail("VERSION", "Version records require DT_VERSYM");
            return;
        }
        const auto p = offset(get(0x6ffffff0), image.symbols.size() * 2);
        for (std::size_t i = 0; i < image.symbols.size(); ++i) {
            auto &s = image.symbols[i];
            const auto raw = file.u16(p + i * 2), index = static_cast<std::uint16_t>(raw & 0x7fff);
            s.version_hidden = (raw & 0x8000) != 0;
            if (index < 2) {
                // Undefined references use index 0 or 1 for no version constraint.
                // This does not turn an STB_WEAK/STB_GLOBAL import into STB_LOCAL.
                if (s.version_hidden || (index == 0 && s.binding != 0 && s.defined))
                    fail("VERSION", "Invalid local/global symbol version");
                continue;
            }
            const auto it = versions.find(index);
            if (it == versions.end() || it->second.definition != s.defined)
                fail("VERSION", "Unknown or inconsistent dynamic symbol version");
            s.version = it->second.name;
            s.version_library = it->second.library;
        }
    }
    void relocations() {
        std::vector<std::uint64_t> targets;
        auto table = [&](std::uint64_t address, std::uint64_t size, bool plt) {
            if (size % 24 || size / 24 > relocation_limit ||
                image.relocations.size() + size / 24 > relocation_limit)
                fail("LIMIT", "Oversized or misaligned RELA table");
            const auto p = offset(address, size);
            image.relocations.reserve(image.relocations.size() + static_cast<std::size_t>(size / 24));
            targets.reserve(image.relocations.capacity());
            for (std::uint64_t i = 0; i < size; i += 24) {
                Relocation r;
                r.offset = file.u64(p + i);
                const auto info = file.u64(p + i + 8);
                r.type = static_cast<std::uint32_t>(info);
                r.symbol = static_cast<std::uint32_t>(info >> 32);
                r.addend = std::bit_cast<std::int64_t>(file.u64(p + i + 16));
                if (r.type != 1027 && r.type != 1025 && r.type != 1026 && r.type != 257)
                    fail("RELOCATION_UNSUPPORTED",
                         "Unsupported AArch64 relocation type " + std::to_string(r.type));
                if (r.symbol >= image.symbols.size() || (r.type == 1027 && r.symbol) ||
                    (r.type != 1027 && !r.symbol) || (plt && r.type != 1026) || r.offset % 8)
                    fail("RELOCATION", "Invalid relocation symbol, PLT type or target alignment");
                const auto &s = segment(r.offset, 8);
                if (!a64::has(s.permissions, a64::Permission::write))
                    fail("TEXT_RELOCATION", "Relocations must target writable data segments");
                targets.push_back(r.offset);
                image.relocations.push_back(r);
            }
        };
        if (has(7) != has(8) || ((has(7) || has(9)) && get(9) != 24))
            fail("RELOCATION", "Incomplete or invalid DT_RELA metadata");
        if (has(7))
            table(get(7), get(8), false);
        if (get(0x6ffffff9) > image.relocations.size())
            fail("RELOCATION", "DT_RELACOUNT exceeds relocation table");
        for (std::uint64_t i = 0; i < get(0x6ffffff9); ++i)
            if (image.relocations[static_cast<std::size_t>(i)].type != 1027)
                fail("RELOCATION", "DT_RELACOUNT includes a non-relative relocation");
        if (has(23) != has(2) || has(23) != has(20) || (has(23) && get(20) != 7))
            fail("RELOCATION", "Incomplete or unsupported PLT relocation metadata");
        if (has(23))
            table(get(23), get(2), true);
        std::sort(targets.begin(), targets.end());
        if (std::adjacent_find(targets.begin(), targets.end()) != targets.end())
            fail("RELOCATION", "Duplicate relocation target");
    }
    void initializers() {
        auto function = [&](std::uint64_t tag) {
            const auto value = get(tag);
            if (value && (value % 4 || !a64::has(segment(value, 4).permissions, a64::Permission::execute)))
                fail("INITIALIZER", "Initializer or finalizer is not executable/aligned");
            return value;
        };
        image.init = function(12);
        image.fini = function(13);
        auto array = [&](std::uint64_t tag, std::uint64_t size_tag, std::uint64_t &at, std::uint64_t &count) {
            if (has(tag) != has(size_tag) || get(size_tag) % 8 || get(size_tag) > 4096 * 8 || get(tag) % 8)
                fail("INITIALIZER", "Invalid initializer/finalizer array");
            at = get(tag);
            count = get(size_tag) / 8;
            if (count)
                segment(at, count * 8);
        };
        array(25, 27, image.init_array, image.init_count);
        array(26, 28, image.fini_array, image.fini_count);
    }
};
} // namespace
ElfImage parse(Bytes bytes) {
    if (bytes.size() > maximum_bytes)
        fail("LIMIT", "ELF input exceeds 64 MiB");
    Parser p(bytes);
    p.headers();
    p.dynamics();
    p.symbols();
    p.versions();
    p.relocations();
    p.initializers();
    p.image.bytes.assign(bytes.begin(), bytes.end());
    return std::move(p.image);
}
ElfImage parse(ModuleSource &source) {
    if (!source.size() || source.size() > streamed_native_bytes)
        fail("LIMIT", "Streamed ELF input exceeds 128 MiB or is empty");
    Parser p(source);
    p.headers();
    p.dynamics();
    p.symbols();
    p.versions();
    p.relocations();
    p.initializers();
    return std::move(p.image);
}
} // namespace aether::elf
