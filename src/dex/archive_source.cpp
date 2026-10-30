#include "aether/dex/archive_source.hpp"
#include "load_diagnostics.hpp"
#include "aether/apk/bytes.hpp"
#include <algorithm>
#include <set>

namespace aether::dex {
namespace {
constexpr std::size_t maximum_classes = 1'048'576, maximum_names = 32 * 1024 * 1024;
[[noreturn]] void bad(std::string message) { throw DexError("AETHER_DEX_SOURCE_INDEX", std::move(message)); }
// Decode only a class descriptor. Indexing validates string extents and MUTF-8;
// the complete selected DEX still undergoes the ordinary structural parser.
std::string class_name(const apk::View &view, std::uint32_t at, std::uint32_t begin, std::uint32_t end) {
    const auto byte = [&]() {
        if (at < begin || at >= end)
            bad("Class descriptor exceeds the string-data section");
        return view.u8(at++);
    };
    std::uint32_t length = 0;
    for (unsigned n = 0;; ++n) {
        const auto b = byte();
        if (n == 4 && (b & 0xf0))
            bad("Class descriptor length exceeds 32 bits");
        length |= std::uint32_t(b & 127) << (n * 7);
        if (!(b & 128))
            break;
        if (n == 4)
            bad("Unterminated class descriptor length");
    }
    if (length < 3 || length > 1024)
        bad("Class descriptor exceeds the 1024-code-unit identifier bound");
    std::string value;
    for (std::uint32_t n = 0; n < length; ++n) {
        const auto first = byte();
        if (!first)
            bad("Class descriptor terminates before its declared length");
        value.push_back(static_cast<char>(first));
        std::uint16_t c = first;
        if ((first & 0xe0) == 0xc0) {
            const auto second = byte();
            c = static_cast<std::uint16_t>(((first & 31) << 6) | (second & 63));
            if ((second & 0xc0) != 0x80 || c < 0x80)
                bad("Invalid modified UTF-8 class descriptor");
            value.push_back(static_cast<char>(second));
        } else if ((first & 0xf0) == 0xe0) {
            const auto second = byte(), third = byte();
            c = static_cast<std::uint16_t>(((first & 15) << 12) | ((second & 63) << 6) | (third & 63));
            if ((second & 0xc0) != 0x80 || (third & 0xc0) != 0x80 || c < 0x800)
                bad("Invalid modified UTF-8 class descriptor");
            value.push_back(static_cast<char>(second));
            value.push_back(static_cast<char>(third));
        } else if (first >= 0x80)
            bad("Class descriptor requires modified UTF-8");
    }
    if (byte() || value.front() != 'L' || value.back() != ';')
        bad("Invalid class descriptor terminator or category");
    return value;
}
} // namespace
struct ArchiveSource::Impl {
    struct File {
        std::shared_ptr<apk::Archive> archive;
        std::size_t entry;
        std::string hash, name;
    };
    struct Entry {
        std::uint32_t offset, length, file;
    };
    std::vector<File> files;
    std::vector<Entry> entries;
    std::string names;
    std::string_view name(const Entry &entry) const {
        return std::string_view(names).substr(entry.offset, entry.length);
    }
    std::vector<std::uint8_t> read(std::size_t file) const {
        try {
        if (file >= files.size())
            bad("Unknown DEX source index");
        auto bytes = files[file].archive->read(files[file].entry);
        try {
            if (apk::sha256(bytes) != files[file].hash)
                bad("DEX source differs from its inspected immutable identity");
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::archive_hash);throw;
        }
        return bytes;
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::archive_read);throw;
        }
    }
    explicit Impl(std::span<const ArchiveDexInput> inputs, ArchiveIndexPolicy policy) {
        if (policy != ArchiveIndexPolicy::inspected && policy != ArchiveIndexPolicy::directory)
            bad("Unknown class inventory validation policy");
        if (inputs.empty() || inputs.size() > 64)
            bad("Class inventory requires 1 through 64 DEX sources");
        std::uint64_t total = 0, classes = 0;
        std::set<std::string> unique;
        for (const auto &source : inputs) {
            const auto &input = source.file;
            if (policy == ArchiveIndexPolicy::directory &&
                (!input.file.sha256.empty() || !input.version.empty() || input.strings || input.methods ||
                 input.classes))
                bad("Directory inventory must not claim previously inspected DEX content");
            const auto name = input.file.container.empty() ? input.file.path
                                                           : input.file.container + "!/" + input.file.path;
            if (!source.archive || !unique.insert(name).second || input.file.bytes > source_file_bytes ||
                input.file.bytes > source_encoded_bytes - total || input.classes > maximum_classes - classes)
                bad("DEX class inventory exceeds its source or class-count bounds");
            total += input.file.bytes;
            classes += input.classes;
            const auto &all = source.archive->entries();
            const auto found = std::find_if(all.begin(), all.end(),
                                            [&](const auto &item) { return item.path == input.file.path; });
            if (found == all.end() || found->directory || found->bytes != input.file.bytes ||
                found->compressed_bytes != input.file.compressed_bytes)
                bad("DEX source is absent or disagrees with inspected size");
            files.push_back(
                {source.archive, static_cast<std::size_t>(found - all.begin()), input.file.sha256, name});
        }
        entries.reserve(static_cast<std::size_t>(classes));
        for (std::size_t file = 0; file < files.size(); ++file) {
            // The runtime's directory path combines its first content check
            // with class indexing. Already inspected callers retain their
            // exact identity/count cross-checks. Selected loads recheck the
            // retained hash in either case.
            const auto bytes = policy == ArchiveIndexPolicy::inspected
                                   ? read(file)
                                   : files[file].archive->read(files[file].entry);
            const auto inventory = apk::inspect_dex(bytes);
            if ((inventory.version != "035" && inventory.version != "037" && inventory.version != "038") ||
                (policy == ArchiveIndexPolicy::inspected && inventory.classes != inputs[file].file.classes))
                bad("Unsupported or inconsistent DEX class inventory");
            if (policy == ArchiveIndexPolicy::directory) {
                if (inventory.classes > maximum_classes - classes)
                    bad("DEX class inventory exceeds its class-count bound");
                classes += inventory.classes;
                entries.reserve(static_cast<std::size_t>(classes));
                files[file].hash = apk::sha256(bytes);
            }
            apk::View view(bytes, "dex-class-index");
            const auto map = view.u32(52), count = view.u32(map);
            std::uint32_t begin = 0, end = 0;
            for (std::uint32_t n = 0; n < count; ++n) {
                const auto at = std::size_t{map} + 4 + std::size_t{n} * 12;
                if (view.u16(at) == 0x2002) {
                    begin = view.u32(at + 8);
                    end = n + 1 == count ? static_cast<std::uint32_t>(bytes.size()) : view.u32(at + 20);
                }
            }
            const auto table = view.u32(100), type_table = view.u32(68), string_table = view.u32(60);
            for (std::uint32_t n = 0; n < inventory.classes; ++n) {
                const auto type = view.u32(std::size_t{table} + std::size_t{n} * 32);
                if (type >= view.u32(64))
                    bad("Class inventory type index is outside its source table");
                const auto string = view.u32(std::size_t{type_table} + std::size_t{type} * 4);
                if (string >= inventory.strings)
                    bad("Class inventory string index is outside its source table");
                const auto descriptor = class_name(
                    view, view.u32(std::size_t{string_table} + std::size_t{string} * 4), begin, end);
                if (descriptor.size() > maximum_names - names.size())
                    bad("Class inventory names exceed 32 MiB");
                entries.push_back({static_cast<std::uint32_t>(names.size()),
                                   static_cast<std::uint32_t>(descriptor.size()),
                                   static_cast<std::uint32_t>(file)});
                names += descriptor;
            }
        }
        names.shrink_to_fit();
        std::sort(entries.begin(), entries.end(),
                  [&](const auto &a, const auto &b) { return name(a) < name(b); });
        for (std::size_t n = 1; n < entries.size(); ++n)
            if (name(entries[n - 1]) == name(entries[n]))
                bad("Duplicate class definition across the immutable DEX inventory");
    }
};
ArchiveSource::ArchiveSource(std::shared_ptr<apk::Archive> archive, std::span<const apk::DexInfo> files)
    : impl_([&] {
          std::vector<ArchiveDexInput> inputs;
          inputs.reserve(files.size());
          for (const auto &file : files)
              inputs.push_back({archive, file});
          return std::make_unique<Impl>(inputs, ArchiveIndexPolicy::inspected);
      }()) {}
ArchiveSource::ArchiveSource(std::span<const ArchiveDexInput> files, ArchiveIndexPolicy policy)
    : impl_(std::make_unique<Impl>(files, policy)) {}
ArchiveSource::~ArchiveSource() = default;
std::optional<std::size_t> ArchiveSource::source_for(std::string_view descriptor) const {
    const auto &p = *impl_;
    const auto at = std::lower_bound(p.entries.begin(), p.entries.end(), descriptor,
                                     [&](const auto &entry, auto key) { return p.name(entry) < key; });
    if (at == p.entries.end() || p.name(*at) != descriptor)
        return {};
    return at->file;
}
std::string_view ArchiveSource::source_name(std::size_t index) const {
    if (index >= impl_->files.size())
        bad("Unknown DEX source index");
    return impl_->files[index].name;
}
DexImage ArchiveSource::load(std::size_t index) {
    try { return parse(impl_->read(index)); }
    catch(const std::bad_alloc &) {
        detail::note_class_load_allocation(ClassLoadAllocationPhase::source);throw;
    }
}
std::size_t ArchiveSource::indexed_classes() const noexcept { return impl_->entries.size(); }
std::size_t ArchiveSource::index_bytes() const noexcept {
    return impl_->names.capacity() + impl_->entries.capacity() * sizeof(Impl::Entry);
}
} // namespace aether::dex
