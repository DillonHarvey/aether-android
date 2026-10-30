#include "aether/dex/source.hpp"
#include "load_diagnostics.hpp"
#include <array>
#include <map>
#include <set>

namespace aether::dex {
namespace {
[[noreturn]] void bad(std::string_view kind, std::string message) {
    throw DexError("AETHER_DEX_SOURCE_" + std::string(kind), std::move(message));
}
} // namespace
struct ClassLoader::Impl {
    DexImage &image;
    std::shared_ptr<ClassSource> source;
    Linker linker;
    std::array<bool, 64> loaded{};
    // Borrow immutable names in the stable target tables. The loader and its
    // index are destroyed before the caller-owned target.
    std::map<std::string_view, std::size_t, std::less<>> definitions;
    std::set<std::string, std::less<>> complete, active;
    bool failed = false;
    std::atomic<ClassLoadAllocationPhase> allocation_phase{ClassLoadAllocationPhase::none};
    Impl(DexImage &target, std::shared_ptr<ClassSource> source, LinkLimits limits)
        : image(target), source(std::move(source)), linker(target, limits) {
        if (!this->source)
            bad("STATE", "A class loader requires an immutable class source");
    }
    void check() const {
        if (failed)
            bad("STATE", "A failed class loader cannot execute a partial linked image");
    }
    void resolve(std::string_view descriptor) {
        try {
        if (complete.contains(descriptor))
            return;
        const auto file = source->source_for(descriptor);
        if (!file)
            return; // The existing core/framework providers decide missing types.
        if (*file >= loaded.size())
            bad("LIMIT", "Class source index exceeds 64 files");
        if (active.size() >= 256 || !active.emplace(descriptor).second)
            bad("CLASS", "Cyclic or excessively deep class/interface loading");
        if (!loaded[*file]) {
            const auto name=[&] {
                try { return std::string(source->source_name(*file)); }
                catch(const std::bad_alloc &) {
                    detail::note_class_load_allocation(ClassLoadAllocationPhase::source);throw;
                }
            }();
            const auto previous_classes = image.classes.size();
            try {
                try {
                    linker.add([&] {
                        try { return source->load(*file); }
                        catch(const std::bad_alloc &) {
                            detail::note_class_load_allocation(ClassLoadAllocationPhase::source);throw;
                        }
                    }(), name);
                }
                catch(const std::bad_alloc &) {
                    detail::note_class_load_allocation(ClassLoadAllocationPhase::link_merge);throw;
                }
                try { linker.validate(); }
                catch(const std::bad_alloc &) {
                    detail::note_class_load_allocation(ClassLoadAllocationPhase::link_validate);throw;
                }
            } catch (const DexError &error) {
                throw DexError(error.code, name + ": " + error.what());
            }
            try {
                for (auto n = previous_classes; n < image.classes.size(); ++n)
                    definitions.emplace(image.types.at(image.classes[n].type), n);
            } catch(const std::bad_alloc &) {
                detail::note_class_load_allocation(ClassLoadAllocationPhase::definition_index);throw;
            }
            loaded[*file] = true;
        }
        const auto found = definitions.find(descriptor);
        if (found == definitions.end())
            bad("IDENTITY", "Selected source did not define the requested class");
        const auto *definition = &image.classes.at(found->second);
        if (definition->superclass != no_index)
            resolve(image.types.at(definition->superclass));
        for (auto type : definition->interfaces)
            resolve(image.types.at(type));
        try {
            complete.emplace(descriptor);
            active.erase(std::string(descriptor));
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::complete);throw;
        }
        } catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::lookup);throw;
        }
    }
    void ensure(std::string_view descriptor) {
        detail::ScopedClassLoadAllocation allocation(allocation_phase);
        try { check(); }
        catch(const std::bad_alloc &) {
            detail::note_class_load_allocation(ClassLoadAllocationPhase::lookup);throw;
        }
        try {
            resolve(descriptor);
        } catch (...) {
            failed = true;
            throw;
        }
    }
};
ClassLoader::ClassLoader(DexImage &target, std::shared_ptr<ClassSource> source, LinkLimits limits)
    : impl_(std::make_unique<Impl>(target, std::move(source), limits)) {}
ClassLoader::~ClassLoader() = default;
void ClassLoader::ensure(std::string_view descriptor) { impl_->ensure(descriptor); }
const Class *ClassLoader::definition(std::string_view descriptor) {
    impl_->ensure(descriptor);
    const auto found = impl_->definitions.find(descriptor);
    return found == impl_->definitions.end() ? nullptr : &impl_->image.classes.at(found->second);
}
void ClassLoader::check() const { impl_->check(); }
ClassLoadAllocationPhase ClassLoader::allocation_failure_phase() const noexcept {
    return impl_->allocation_phase.load(std::memory_order_relaxed);
}
} // namespace aether::dex
