#include "aether/android/bootstrap_class_presence.hpp"
#include <array>

namespace aether::android {
namespace {
constexpr std::array<std::string_view, 2058> classes{{
#include "bootstrap_direct_classes.inc"
}};
constexpr std::array<std::string_view, 3> packages{
    "Landroid/widget/", "Landroid/webkit/", "Landroid/app/"};
consteval bool valid_inventory() {
    for (std::size_t i = 0; i < classes.size(); ++i) {
        const auto name = classes[i];
        if (name.empty() || name.back() != ';' || (i && classes[i-1] >= name)) return false;
        bool direct = false;
        for (const auto package : packages) {
            if (name.starts_with(package) && name.size() > package.size()+1 &&
                name.substr(package.size()).find('/') == std::string_view::npos) direct = true;
        }
        if (!direct) return false;
    }
    return true;
}
static_assert(valid_inventory());
}

dex::HostBootstrapClassPresence api35_bootstrap_class_presence(
    std::string_view descriptor, void *owner, void (*charge)(void *, std::uint64_t)) {
    if (!charge) throw dex::DexError("AETHER_DEX_WORK_CONTEXT", "Class-presence lookup requires work accounting");
    bool direct = false;
    for (const auto package : packages) {
        if (descriptor.size() <= package.size()+1) continue;
        bool matches = true;
        for (std::size_t i = 0; i < package.size(); ++i) {
            charge(owner, 1);
            if (descriptor[i] != package[i]) { matches = false; break; }
        }
        if (!matches) continue;
        // Only complete direct binary packages are audited; subpackages remain unknown.
        for (std::size_t i = package.size(); i < descriptor.size(); ++i) {
            charge(owner, 1);
            if (descriptor[i] == '/' || (descriptor[i] == ';' && i+1 != descriptor.size())) {
                return dex::HostBootstrapClassPresence::unknown;
            }
        }
        charge(owner, 1);
        if (descriptor.back() != ';') return dex::HostBootstrapClassPresence::unknown;
        direct = true;
        break;
    }
    if (!direct) return dex::HostBootstrapClassPresence::unknown;
    std::size_t first = 0, last = classes.size();
    while (first < last) {
        const auto middle = first + (last-first)/2;
        const auto candidate = classes[middle];
        int order = 0;
        const auto common = descriptor.size() < candidate.size() ? descriptor.size() : candidate.size();
        for (std::size_t i = 0; i < common; ++i) {
            charge(owner, 1);
            if (descriptor[i] < candidate[i]) { order = -1; break; }
            if (descriptor[i] > candidate[i]) { order = 1; break; }
        }
        if (!order) {
            charge(owner, 1);
            order = descriptor.size() < candidate.size() ? -1 : descriptor.size() > candidate.size() ? 1 : 0;
        }
        if (!order) return dex::HostBootstrapClassPresence::known_present;
        if (order < 0) last = middle;
        else first = middle+1;
    }
    return dex::HostBootstrapClassPresence::proven_absent;
}
}
