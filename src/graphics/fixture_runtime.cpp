#include "fixture_runtime.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/graphics/fixture_hash.hpp"
#include <Windows.h>
#include <fstream>

namespace aether::graphics::detail {
namespace {
[[noreturn]] void fail(std::string message) {
    throw a64::GuestError("AETHER_GRAPHICS_SELFTEST", std::move(message));
}
} // namespace
FixtureRuntime::Image FixtureRuntime::load(const std::filesystem::path &path) {
    apk::InspectLimits limits;
    limits.archive_bytes = 1024 * 1024;
    return load(apk::read_package(path, limits));
}
FixtureRuntime::Image FixtureRuntime::load(std::vector<std::uint8_t> bytes) {
    if (bytes.size() > 1024 * 1024)
        fail("Graphics fixture exceeds 1 MiB");
    auto hash = apk::sha256(bytes);
    if (hash != fixture::sha256)
        throw a64::GuestError(
            "AETHER_GRAPHICS_FIXTURE_NOT_TRUSTED",
            "Only the exact built-in first-party GLES ELF fixture may execute before Phase 7");
    return {std::move(bytes), std::move(hash)};
}
FixtureRuntime::Services::Services(bionic::GuestPosixServices &posix, GuestGraphicsServices &graphics)
    : posix_(posix), graphics_(graphics) {}
bool FixtureRuntime::Services::has_library(std::string_view library) const noexcept {
    return graphics_.has_library(library) || posix_.has_library(library);
}
std::optional<elf::GuestSymbol> FixtureRuntime::Services::resolve(std::string_view library,
                                                                  std::string_view name,
                                                                  std::string_view version) const {
    return graphics_.has_library(library) ? graphics_.resolve(library, name, version)
                                          : posix_.resolve(library, name, version);
}
a64::Fault FixtureRuntime::Services::invoke(std::uint32_t service, a64::Address instruction,
                                            std::array<std::uint64_t, 31> &registers) noexcept {
    a64::ServiceState state;
    state.registers = registers;
    const auto fault = invoke_frame(service, instruction, state);
    registers = state.registers;
    return fault;
}
a64::Fault FixtureRuntime::Services::invoke_frame(std::uint32_t service, a64::Address instruction,
                                                  a64::ServiceState &state) noexcept {
    return GuestGraphicsServices::handles_service(service)
               ? graphics_.invoke_frame(service, instruction, state)
               : posix_.invoke_frame(service, instruction, state);
}
FixtureRuntime::FixtureRuntime(const std::filesystem::path &path)
    : image_(load(path)), posix(memory, app, time), graphics(memory, app), services_(posix, graphics),
      loader_(memory, services_) {
    const std::array modules{elf::ModuleInput{"libaether_gles.so", image_.bytes}};
    loader_.load(modules, "libaether_gles.so");
    memory.map(output, output_size, a64::read_write);
    memory.map(stack, 65536, a64::read_write);
    cpu_ = std::make_unique<a64::GuestCpu>(memory, app, &services_);
    loader_.initialize(*cpu_, stack_top);
}
FixtureRuntime::FixtureRuntime(std::vector<std::uint8_t> bytes, std::uint64_t app_id,
                               host::TimeService &provider, GraphicsChannel &channel)
    : image_(load(std::move(bytes))), app{app_id, true, true}, posix(memory, app, provider),
      graphics(memory, app, &channel), services_(posix, graphics), loader_(memory, services_) {
    const std::array modules{elf::ModuleInput{"libaether_gles.so", image_.bytes}};
    loader_.load(modules, "libaether_gles.so");
    memory.map(output, output_size, a64::read_write);
    memory.map(stack, 65536, a64::read_write);
    cpu_ = std::make_unique<a64::GuestCpu>(memory, app, &services_);
    loader_.initialize(*cpu_, stack_top);
}
std::uint64_t FixtureRuntime::value(std::string_view name, std::initializer_list<std::uint64_t> arguments) {
    if (finalized_)
        fail("Graphics fixture has already been finalized");
    const auto symbol = loader_.symbol("libaether_gles.so", name);
    const auto result = cpu_->call(symbol.address, {arguments.begin(), arguments.size()}, stack_top);
    if (!result.returned)
        fail(std::string(name) + ": " + std::string(a64::fault_name(result.fault)) + "; " +
             std::string(graphics.last_error()) + "; " + std::string(posix.last_rejection()));
    return result.registers[0];
}
void FixtureRuntime::call(std::string_view name, std::initializer_list<std::uint64_t> arguments) {
    const auto result = value(name, arguments);
    if (static_cast<std::uint32_t>(result) != 0)
        fail(std::string(name) + " returned fixture failure " +
             std::to_string(static_cast<std::int32_t>(result)));
}
void FixtureRuntime::finalize() {
    if (!finalized_) {
        finalized_ = true;
        loader_.finalize(*cpu_, stack_top);
    }
}
const std::string &FixtureRuntime::hash() const noexcept { return image_.hash; }
std::size_t FixtureRuntime::relocations() const noexcept { return loader_.relocation_count(); }
const a64::Metrics &FixtureRuntime::cpu_metrics() const noexcept { return cpu_->metrics(); }
std::string save_capture(std::string_view name, std::span<const std::uint8_t> pixels) {
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size())
        fail("Cannot locate the graphics evidence directory");
    executable.resize(length);
    const auto path = std::filesystem::path(executable).parent_path() / name;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char *>(pixels.data()), static_cast<std::streamsize>(pixels.size()));
    file.close();
    if (!file)
        fail("Cannot write the GPU evidence artifact");
    return utf8(path.native());
}
} // namespace aether::graphics::detail
