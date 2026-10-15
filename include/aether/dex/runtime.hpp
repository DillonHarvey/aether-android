#pragma once
#include "aether/dex/image.hpp"
#include <memory>

namespace aether::dex {
class ClassSource;
using ObjectId = std::uint64_t;
enum class ValueKind { empty, word, wide, reference, void_value, wide_tail };
struct Value {
    ValueKind kind = ValueKind::empty;
    std::uint64_t bits = 0;
    static Value word(std::uint32_t bits) noexcept { return {ValueKind::word, bits}; }
    static Value wide(std::uint64_t bits) noexcept { return {ValueKind::wide, bits}; }
    static Value reference(ObjectId id) noexcept { return {ValueKind::reference, id}; }
    static Value nothing() noexcept { return {ValueKind::void_value, 0}; }
    bool operator==(const Value &) const = default;
};
class JavaException final : public std::exception {
  public:
    explicit JavaException(ObjectId object) : object(object) {}
    const char *what() const noexcept override { return "Pending managed exception"; }
    const ObjectId object;
};
class ManagedRuntime;
struct HostClass {
    std::string_view superclass;
    std::span<const std::string_view> interfaces;
    bool is_abstract = false, is_interface = false;
};
// Metadata is owned by the provider and stays valid until it is detached.
// An attached provider implements a bounded API surface, not arbitrary host calls.
class HostInterface {
  public:
    virtual ~HostInterface() = default;
    virtual std::optional<HostClass> class_info(std::string_view descriptor) const = 0;
    virtual bool method_is_static(const DexImage &, Index method) const = 0;
    virtual Value invoke(ManagedRuntime &, Index method, std::span<const Value> arguments) = 0;
};
class NativeInterface {
  public:
    virtual ~NativeInterface() = default;
    virtual void load_library(ManagedRuntime &, std::u16string_view name) = 0;
    virtual Value invoke(ManagedRuntime &, Index method, std::span<const Value> arguments) = 0;
};
struct RuntimeLimits {
    std::uint64_t instructions = 1'000'000;
    std::size_t frames = 64, objects = 8192, heap_bytes = 16 * 1024 * 1024, array_length = 65536;
};
struct RuntimeMetrics {
    std::uint64_t instructions = 0, managed_calls = 0, native_calls = 0, core_calls = 0;
    std::uint64_t allocations = 0, collections = 0, reclaimed = 0, exceptions = 0;
    std::size_t maximum_frames = 0, live_objects = 0, heap_bytes = 0, pinned_references = 0;
};
// Original single-owner, bounded interpreter. Loading does not authorize code execution.
// Caller-owned object references must be retained across allocations/collection.
class ManagedRuntime {
  public:
    explicit ManagedRuntime(DexImage image, RuntimeLimits limits = {});
    explicit ManagedRuntime(std::shared_ptr<ClassSource> source, RuntimeLimits limits = {});
    ~ManagedRuntime();
    ManagedRuntime(const ManagedRuntime &) = delete;
    ManagedRuntime &operator=(const ManagedRuntime &) = delete;
    void set_native_interface(NativeInterface *interface);
    void set_host_interface(HostInterface *interface);
    const DexImage &image() const noexcept;
    // Resolve definitions through the demand loader. image() is a passive view
    // of already linked data; IDs and element references survive later loads.
    const Class *class_definition(std::string_view descriptor) const;
    Index resolve_method(std::string_view owner, std::string_view name, std::string_view signature) const;
    const RuntimeMetrics &metrics() const noexcept;
    Value invoke(Index method, std::span<const Value> arguments = {});
    Value invoke_virtual(Index method, std::span<const Value> arguments);
    Value invoke_static(std::string_view owner, std::string_view name, std::string_view signature,
                        std::span<const Value> arguments = {});
    Index lookup(std::string_view owner, std::string_view name, std::string_view signature,
                 bool is_static) const;
    void initialize(std::string_view descriptor);
    ObjectId new_object(std::string_view descriptor);
    ObjectId new_string(std::u16string_view value);
    ObjectId class_object(std::string_view descriptor);
    ObjectId new_array(std::string_view descriptor, std::int32_t length);
    std::string_view object_type(ObjectId object) const;
    std::string_view represented_class(ObjectId object) const;
    std::u16string_view string(ObjectId object) const;
    std::u16string_view char_sequence(ObjectId object) const;
    std::u16string_view exception_message(ObjectId object) const;
    std::size_t array_length(ObjectId object) const;
    Value array_get(ObjectId object, std::int32_t index) const;
    void array_set(ObjectId object, std::int32_t index, Value value);
    bool assignable(ObjectId object, std::string_view type) const;
    Value get_static(Index field);
    void set_static(Index field, Value value);
    void retain(ObjectId object);
    void release(ObjectId object);
    void collect();
    [[noreturn]] void raise(std::string_view type, std::u16string_view message = {});

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
