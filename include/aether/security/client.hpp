#pragma once
#include "aether/host/file_service.hpp"
#include "aether/host/time_service.hpp"
#include "aether/security/worker.hpp"

namespace aether::security {
// Single owner-thread worker provider. Guest descriptors map to opaque, non-reused
// broker tokens, never Windows handles. Transport failure permanently closes the client.
class BrokerClient final : public host::TimeService, public host::FileService {
  public:
    BrokerClient(HANDLE reader, HANDLE writer, std::uint64_t session, bool interactive = false);
    ~BrokerClient() override;
    Frame request(Operation operation, std::vector<std::uint8_t> payload = {});
    std::vector<std::uint8_t> read_package();
    void verify_package(std::span<const std::uint8_t> bytes);
    std::uint64_t next_sequence() const noexcept;
    host::TimeStatus read_monotonic(host::MonotonicTime &value) const noexcept override;
    host::FileResult open(std::string_view name, host::FileOpen options) override;
    host::FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    host::FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    host::FileResult close(int descriptor) noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
