#pragma once
#include "aether/bionic/guest_posix.hpp"
#include "aether/dex/runtime.hpp"

namespace aether::jni {
struct Metrics {
    std::uint64_t calls = 0, native_calls = 0, managed_callbacks = 0, on_load_calls = 0;
    std::uint64_t references_created = 0, automatic_local_deletions = 0, rejected_calls = 0;
    std::size_t local_references = 0, global_references = 0, string_buffers = 0;
};
// Owns guest-only tables, translator and native call stacks. The runtime, app,
// memory and clock must outlive this bridge. The ELF loader consumes module
// bytes/sources during construction; streamed files are not retained afterward.
// The caller must authorize all module bytes before executing managed/native code.
class Bridge final : public dex::NativeInterface, public a64::GuestServices {
  public:
    static constexpr a64::Address environment = 0x60000, java_vm = 0x60008;
    Bridge(dex::ManagedRuntime &runtime, a64::GuestMemory &memory, const a64::AppContext &app,
           const host::TimeService &time, std::span<const elf::ModuleInput> modules, std::string root,
           host::FileService *files = nullptr, bool attach_interface = true);
    ~Bridge();
    Bridge(const Bridge &) = delete;
    Bridge &operator=(const Bridge &) = delete;
    void load_library(dex::ManagedRuntime &, std::u16string_view name) override;
    dex::Value invoke(dex::ManagedRuntime &, dex::Index method,
                      std::span<const dex::Value> arguments) override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    a64::Fault invoke_frame(std::uint32_t service, a64::Address instruction,
                            a64::ServiceState &) noexcept override;
    const Metrics &metrics() const noexcept;
    const a64::Metrics &cpu_metrics() const noexcept;
    std::string_view last_error() const noexcept;
    void shutdown();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::jni
