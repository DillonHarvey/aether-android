#pragma once
#include "aether/dex/limits.hpp"
#include "aether/dex/linker.hpp"
#include <string_view>

namespace aether::dex {
// Lookup itself never executes or initializes a class. A selected file must
// pass the complete structural DEX parser before any definition is published.
class ClassSource {
  public:
    virtual ~ClassSource() = default;
    virtual std::optional<std::size_t> source_for(std::string_view descriptor) const = 0;
    virtual std::string_view source_name(std::size_t index) const = 0;
    virtual DexImage load(std::size_t index) = 0;
};
class ClassLoader {
  public:
    ClassLoader(DexImage &target, std::shared_ptr<ClassSource> source, LinkLimits limits = {});
    ~ClassLoader();
    ClassLoader(const ClassLoader &) = delete;
    ClassLoader &operator=(const ClassLoader &) = delete;
    void ensure(std::string_view descriptor);
    const Class *definition(std::string_view descriptor);
    void check() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
