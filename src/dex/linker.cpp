#include "aether/dex/linker.hpp"
#include "load_diagnostics.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <string_view>
#include <tuple>

namespace aether::dex {
namespace {
[[noreturn]] void bad(std::string_view kind, const std::string &message) {
    throw DexError("AETHER_DEX_LINK_" + std::string(kind), message);
}
Index mapped(const std::vector<Index> &map, std::uint64_t index) {
    if (index >= map.size())
        bad("INDEX", "Metadata reference exceeds its source DEX table");
    return map[static_cast<std::size_t>(index)];
}
template <class T> Index next(const T &values) {
    if (values.size() >= 1'048'576)
        bad("LIMIT", "Linked identifier table exceeds 1048576 entries");
    return static_cast<Index>(values.size());
}
bool provider_name_character(char value) noexcept {
    return value == '$' || value == '-' || value == '_' ||
           (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9');
}
// Consume one complete canonical type without allocating or trusting a DEX
// parser's prior validation: these references did not come from a DEX file.
std::string_view provider_type(std::string_view text, std::size_t &position, bool allow_void) {
    const auto begin = position;
    std::size_t dimensions = 0;
    while (position < text.size() && text[position] == '[') {
        ++position;
        if (++dimensions > 255)
            bad("DESCRIPTOR", "Provider array type exceeds 255 dimensions");
    }
    if (position == text.size())
        bad("DESCRIPTOR", "Incomplete provider type descriptor");
    const auto kind = text[position++];
    if (kind == 'L') {
        bool component = false;
        for (;;) {
            if (position == text.size())
                bad("DESCRIPTOR", "Unterminated provider class descriptor");
            const auto value = text[position++];
            if (value == ';') {
                if (!component)
                    bad("DESCRIPTOR", "Empty provider class-name component");
                break;
            }
            if (value == '/') {
                if (!component)
                    bad("DESCRIPTOR", "Empty provider class-name component");
                component = false;
            } else {
                if (!provider_name_character(value))
                    bad("DESCRIPTOR", "Unsupported provider class-name character");
                component = true;
            }
        }
    } else if (std::string_view("ZBSCIJFDV").find(kind) == std::string_view::npos ||
               (kind == 'V' && (dimensions || !allow_void))) {
        bad("DESCRIPTOR", "Invalid provider value type");
    }
    return text.substr(begin, position - begin);
}
} // namespace
struct Linker::Impl {
    LinkLimits limits;
    DexImage owned_image;
    DexImage &image;
    bool failed = false, finished = false;
    std::uint64_t accounted = 0;
    // Keys borrow immutable identities in the append-only stable tables, never
    // the consumed input. Declaration upgrades preserve these identity fields.
    // These indexes are destroyed before owned_image (or the caller's target).
    std::map<std::u16string_view, Index> strings;
    std::map<std::string_view, Index> types, prototypes;
    using Member = std::tuple<Index, std::string_view, Index>;
    std::map<Member, Index> fields, methods;
    std::map<Index, std::size_t> classes;
    std::set<std::string> names;
    explicit Impl(LinkLimits limits, DexImage *target = nullptr)
        : limits(limits), image(target ? *target : owned_image) {
        if (!limits.files || limits.files > 64 || !limits.metadata_bytes ||
            limits.metadata_bytes > 96ULL * 1024 * 1024)
            bad("LIMIT", "Invalid DEX link limits");
        if (!image.strings.empty() || !image.types.empty() || !image.prototypes.empty() ||
            !image.fields.empty() || !image.methods.empty() || !image.classes.empty() ||
            !image.sources.empty())
            bad("STATE", "An incremental DEX link target must begin empty");
    }
    void ready() const {
        if (failed || finished)
            bad("STATE", "DEX linker is failed or already finalized");
    }
    void charge(std::uint64_t bytes) {
        if (bytes > limits.metadata_bytes - accounted)
            bad("LIMIT", "Aggregate decoded DEX metadata exceeds its link budget");
        accounted += bytes;
    }
    template <class T> void table(const T &values, bool remap = false) {
        charge(values.size() * (sizeof(typename T::value_type) + (remap ? sizeof(Index) : 0)));
    }
    void account(const DexImage &input) {
        table(input.strings, true);
        for (const auto &value : input.strings)
            charge(value.size() * sizeof(char16_t));
        table(input.types, true);
        for (const auto &value : input.types)
            charge(value.size());
        table(input.prototypes);
        for (const auto &value : input.prototypes) {
            table(value.parameters);
            charge(value.descriptor.size());
        }
        table(input.fields, true);
        for (const auto &value : input.fields)
            charge(value.name.size());
        // Preserve the legacy inline-body charge for every method identifier.
        // That floor already includes one Code object, even when absent.
        charge(input.methods.size() * (method_metadata_charge + sizeof(Index)));
        for (const auto &value : input.methods) {
            charge(value.name.size());
            if (value.code) {
                table(value.code->units);
                table(value.code->tries);
                for (const auto &block : value.code->tries)
                    table(block.handlers);
            }
        }
        table(input.classes);
        for (const auto &value : input.classes) {
            table(value.interfaces);
            table(value.static_fields);
            table(value.instance_fields);
            table(value.direct_methods);
            table(value.virtual_methods);
            table(value.static_values);
        }
    }
    Index intern_provider_method(std::string_view owner, std::string_view name,
                                 std::string_view descriptor) {
        ready();
        failed = true;
        if (owner.empty() || owner.front() != 'L')
            bad("METHOD", "Provider method owner must be a class descriptor");
        std::size_t position = 0;
        (void)provider_type(owner, position, false);
        if (position != owner.size())
            bad("DESCRIPTOR", "Trailing provider owner descriptor data");
        if (name.empty() || name.size() > 1024 || descriptor.size() > 1024 ||
            (name != "<init>" && !std::all_of(name.begin(), name.end(), provider_name_character)))
            bad("METHOD", "Invalid or unsupported provider method name");
        if (descriptor.empty() || descriptor.front() != '(')
            bad("PROTOTYPE", "Provider method requires a canonical prototype");
        position = 1;
        std::size_t parameter_count = 0;
        std::uint32_t argument_words = 0;
        while (position < descriptor.size() && descriptor[position] != ')') {
            const auto parameter = provider_type(descriptor, position, false);
            argument_words += type_words(parameter);
            if (argument_words > 255)
                bad("PROTOTYPE", "Provider argument word count exceeds 255");
            ++parameter_count;
        }
        if (position == descriptor.size())
            bad("PROTOTYPE", "Unterminated provider method parameters");
        ++position;
        const auto return_type = provider_type(descriptor, position, true);
        if (position != descriptor.size() || (name == "<init>" && return_type != "V"))
            bad("PROTOTYPE", "Invalid provider method return descriptor");

        // A pre-existing tuple needs neither new metadata nor a new ID. This
        // also preserves a later DEX file's references to the exact same tuple.
        const auto known_owner = types.find(owner);
        const auto known_prototype = prototypes.find(descriptor);
        if (known_owner != types.end() && known_prototype != prototypes.end()) {
            const auto found = methods.find(Member{known_owner->second, name, known_prototype->second});
            if (found != methods.end()) {
                failed = false;
                return found->second;
            }
        }
        const auto intern_type = [&](std::string_view value) {
            const auto found = types.find(value);
            if (found != types.end()) return found->second;
            const auto index = next(image.types);
            charge(sizeof(std::string) + value.size());
            image.types.emplace_back(value);
            types.emplace(image.types.back(), index);
            return index;
        };
        const auto owner_index = intern_type(owner);
        Index prototype_index;
        if (known_prototype != prototypes.end()) {
            prototype_index = known_prototype->second;
        } else {
            prototype_index = next(image.prototypes);
            charge(sizeof(Prototype) + parameter_count * sizeof(Index) + descriptor.size());
            Prototype prototype;
            prototype.descriptor = descriptor;
            prototype.argument_words = argument_words;
            prototype.parameters.reserve(parameter_count);
            position = 1;
            while (descriptor[position] != ')')
                prototype.parameters.push_back(intern_type(provider_type(descriptor, position, false)));
            prototype.return_type = intern_type(return_type);
            image.prototypes.push_back(std::move(prototype));
            prototypes.emplace(image.prototypes.back().descriptor, prototype_index);
        }
        const auto index = next(image.methods);
        charge(method_metadata_charge + name.size());
        Method reference;
        reference.owner = owner_index;
        reference.prototype = prototype_index;
        reference.name = name;
        image.methods.push_back(std::move(reference));
        const auto &target = image.methods.back();
        methods.emplace(Member{target.owner, target.name, target.prototype}, index);
        failed = false;
        return index;
    }
    void add(DexImage input, std::string name, const Linker::ParentClass &parent) {
        ready();
        failed = true;
        if (image.sources.size() >= limits.files)
            bad("LIMIT", "DEX source count limit exceeded");
        if (name.empty() || name.size() > 511 || !names.insert(name).second)
            bad("SOURCE", "Duplicate or invalid DEX source name");
        if (!input.sources.empty() || (input.version != 35 && input.version != 37 && input.version != 38))
            bad("SOURCE", "Linking requires individual DEX 035/037/038 images");
        try { account(input); }
        catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::link_account);throw;
        }
        // Account and structurally parse the complete original file first.
        // Delegation changes definition ownership, not the input's identity,
        // operand indices, or its aggregate metadata/resource budget.
        std::vector<bool> parent_types(input.types.size(), false);
        if (parent)
            for (const auto &definition : input.classes)
                parent_types.at(definition.type) = parent(input.types.at(definition.type));
        for (auto &field : input.fields)
            if (parent_types.at(field.owner)) {
                field.declared = false;
                field.flags = 0;
            }
        for (auto &method : input.methods)
            if (parent_types.at(method.owner)) {
                method.declared = method.direct = false;
                method.flags = 0;
                method.code.reset();
            }
        auto map = std::make_shared<IndexMap>();
        map->source = name;
        map->version = input.version;
        map->strings.reserve(input.strings.size());
        map->types.reserve(input.types.size());
        map->fields.reserve(input.fields.size());
        map->methods.reserve(input.methods.size());
        for (auto &value : input.strings) {
            auto it = strings.find(value);
            if (it == strings.end()) {
                const auto index = next(image.strings);
                image.strings.push_back(std::move(value));
                it = strings.emplace(image.strings.back(), index).first;
            }
            map->strings.push_back(it->second);
        }
        input.strings.clear();
        for (auto &value : input.types) {
            auto it = types.find(value);
            if (it == types.end()) {
                const auto index = next(image.types);
                image.types.push_back(std::move(value));
                it = types.emplace(image.types.back(), index).first;
            }
            map->types.push_back(it->second);
        }
        input.types.clear();
        std::vector<Index> proto_map;
        proto_map.reserve(input.prototypes.size());
        for (auto &value : input.prototypes) {
            value.return_type = mapped(map->types, value.return_type);
            for (auto &type : value.parameters)
                type = mapped(map->types, type);
            auto it = prototypes.find(value.descriptor);
            if (it == prototypes.end()) {
                const auto index = next(image.prototypes);
                image.prototypes.push_back(std::move(value));
                it = prototypes.emplace(image.prototypes.back().descriptor, index).first;
            }
            proto_map.push_back(it->second);
        }
        input.prototypes.clear();
        for (auto &value : input.fields) {
            value.owner = mapped(map->types, value.owner);
            value.type = mapped(map->types, value.type);
            auto it = fields.find(Member{value.owner, value.name, value.type});
            if (it == fields.end()) {
                const auto index = next(image.fields);
                image.fields.push_back(std::move(value));
                const auto &target = image.fields.back();
                it = fields.emplace(Member{target.owner, target.name, target.type}, index).first;
            } else if (value.declared) {
                if (image.fields[it->second].declared)
                    bad("DUPLICATE", "Duplicate field definition across DEX files");
                auto &target = image.fields[it->second];
                target.flags = value.flags;
                target.declared = true;
            }
            map->fields.push_back(it->second);
        }
        input.fields.clear();
        // Publish every method mapping before moving a code body: recursive and
        // forward references retain file-local operands until verification.
        for (auto &value : input.methods) {
            value.owner = mapped(map->types, value.owner);
            value.prototype = mapped(proto_map, value.prototype);
            auto it = methods.find(Member{value.owner, value.name, value.prototype});
            if (it == methods.end()) {
                const auto index = next(image.methods);
                Method reference;
                reference.owner = value.owner;
                reference.prototype = value.prototype;
                reference.name = std::move(value.name);
                image.methods.push_back(std::move(reference));
                const auto &target = image.methods.back();
                it = methods.emplace(Member{target.owner, target.name, target.prototype}, index).first;
            }
            map->methods.push_back(it->second);
        }
        for (std::size_t i = 0; i < input.methods.size(); ++i) {
            auto &value = input.methods[i];
            if (!value.declared)
                continue;
            auto &target = image.methods[map->methods[i]];
            if (target.declared)
                bad("DUPLICATE", "Duplicate method definition across DEX files");
            if (value.code) {
                if (value.code->references)
                    bad("SOURCE", "DEX code was already linked");
                value.code->references = map;
                for (auto &block : value.code->tries)
                    for (auto &handler : block.handlers)
                        if (handler.type != no_index)
                            handler.type = mapped(map->types, handler.type);
            }
            target.flags = value.flags;
            target.declared = true;
            target.direct = value.direct;
            target.code = std::move(value.code);
        }
        input.methods.clear();
        for (auto &value : input.classes) {
            if (parent_types.at(value.type))
                continue;
            value.type = mapped(map->types, value.type);
            if (image.classes.size() >= 65536)
                bad("LIMIT", "Linked class count exceeds 65536");
            if (!classes.emplace(value.type, image.classes.size()).second)
                bad("DUPLICATE", "Duplicate class definition: " + image.types[value.type]);
            if (value.superclass != no_index)
                value.superclass = mapped(map->types, value.superclass);
            if (value.inner_class_name != no_index) {
                if (!value.inner_class_present)
                    bad("CLASS", "Inner class name has no naming annotation");
                value.inner_class_name = mapped(map->strings, value.inner_class_name);
            }
            if (value.enclosing_class != no_index)
                value.enclosing_class = mapped(map->types, value.enclosing_class);
            if (value.enclosing_method != no_index)
                value.enclosing_method = mapped(map->methods, value.enclosing_method);
            const auto translate = [](std::vector<Index> &values, const std::vector<Index> &mapping) {
                for (auto &index : values)
                    index = mapped(mapping, index);
            };
            translate(value.interfaces, map->types);
            translate(value.static_fields, map->fields);
            translate(value.instance_fields, map->fields);
            translate(value.direct_methods, map->methods);
            translate(value.virtual_methods, map->methods);
            for (auto &item : value.static_values) {
                if (item.type == 0x17)
                    item.bits = mapped(map->strings, item.bits);
                else if (item.type == 0x18)
                    item.bits = mapped(map->types, item.bits);
            }
            image.classes.push_back(std::move(value));
        }
        image.version = (std::max)(image.version, input.version);
        image.sources.push_back({std::move(name), std::move(input.sha256), input.version});
        failed = false;
    }
    void validate() {
        ready();
        failed = true;
        if (image.sources.empty())
            bad("SOURCE", "No DEX sources were supplied");
        // Cross-file superclass/interface cycles do not exist in any one parser
        // input, so validate the combined graph with a bounded iterative DFS.
        std::vector<std::uint8_t> colors(image.classes.size());
        std::vector<std::size_t> heights(image.classes.size());
        struct Work {
            std::size_t index, edge;
            std::size_t height = 1;
        };
        for (std::size_t root = 0; root < image.classes.size(); ++root) {
            if (colors[root] == 2)
                continue;
            std::vector<Work> stack{{root, 0}};
            while (!stack.empty()) {
                auto &work = stack.back();
                colors[work.index] = 1;
                const auto &item = image.classes[work.index];
                if (work.edge > item.interfaces.size()) {
                    const auto height = work.height;
                    if (height > 256)
                        bad("CLASS", "Linked class/interface hierarchy exceeds 256 levels");
                    heights[work.index] = height;
                    colors[work.index] = 2;
                    stack.pop_back();
                    if (!stack.empty())
                        stack.back().height = (std::max)(stack.back().height, height + 1);
                    continue;
                }
                const auto type = work.edge++ == 0 ? item.superclass : item.interfaces[work.edge - 2];
                const auto found = classes.find(type);
                if (found == classes.end())
                    continue;
                const bool interface_edge = work.edge > 1;
                if (((image.classes[found->second].flags & 0x200) != 0) != interface_edge)
                    bad("CLASS", "Linked superclass/interface reference has the wrong class category");
                if (colors[found->second] == 1 || (colors[found->second] == 0 && stack.size() >= 256))
                    bad("CLASS", "Cyclic or excessively deep linked class/interface hierarchy");
                if (colors[found->second] == 0)
                    stack.push_back({found->second, 0});
                else
                    work.height = (std::max)(work.height, heights[found->second] + 1);
            }
        }
        if (image.sources.size() == 1)
            image.sha256 = image.sources.front().sha256;
        else
            image.sha256.clear();
        // Several files have several hashes, never a fabricated single-file hash.
        failed = false;
    }
    DexImage finish() {
        if (&image != &owned_image)
            bad("STATE", "An incremental target is owned by its caller");
        validate();
        finished = true;
        return std::move(image);
    }
};
Linker::Linker(LinkLimits limits) : impl_(std::make_unique<Impl>(limits)) {}
Linker::Linker(DexImage &target, LinkLimits limits) : impl_(std::make_unique<Impl>(limits, &target)) {}
Linker::~Linker() = default;
void Linker::add(DexImage image, std::string source, const ParentClass &parent) {
    impl_->add(std::move(image), std::move(source), parent);
}
Index Linker::intern_provider_method(std::string_view owner, std::string_view name,
                                   std::string_view descriptor) {
    return impl_->intern_provider_method(owner, name, descriptor);
}
void Linker::validate() { impl_->validate(); }
DexImage Linker::finish() { return impl_->finish(); }
} // namespace aether::dex
