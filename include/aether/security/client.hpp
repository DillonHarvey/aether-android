#pragma once
#include "aether/host/file_service.hpp"
#include "aether/host/time_service.hpp"
#include "aether/security/worker.hpp"

namespace aether::security {
// Single owner-thread worker provider. Guest descriptors map to opaque, non-reused
// broker tokens, never Windows handles. Transport failure permanently closes the client.
class BrokerClient final : public host::TimeService, public host::FileService {
  public:
    BrokerClient(HANDLE reader, HANDLE writer, std::uint64_t session, bool interactive = false,
                 bool activity_commands = false);
    ~BrokerClient() override;
    Frame request(Operation operation, std::vector<std::uint8_t> payload = {});
    // Nonblocking owner-only interactive command mailbox; one command in order.
    // RPC calls may collect its validated fragments but never execute commands.
    std::optional<std::vector<std::uint8_t>> poll_activity_command(std::uint64_t sequence);
    std::vector<std::uint8_t> read_package();
    void verify_package(std::span<const std::uint8_t> bytes);
    std::uint64_t next_sequence() const noexcept;
    host::TimeStatus read_monotonic(host::MonotonicTime &value) const noexcept override;
    host::TimeStatus read_wall_time(host::EpochTime &value) const noexcept override;
    host::TimeStatus convert_local_time(std::int64_t epoch, host::LocalTime &value) const noexcept override;
    host::TimeStatus read_elapsed_realtime(host::MonotonicTime &value) const noexcept override;
    host::TimeStatus read_thread_cpu(host::MonotonicTime &value) const noexcept override;
    host::TimeStatus read_uptime(host::MonotonicTime &value) const noexcept override;
    host::TimeStatus read_process_start_uptime(host::MonotonicTime &value) const noexcept override;
    host::FileResult private_root() noexcept override;
    host::FileResult observe_data_file(std::string_view name) noexcept override;
    host::FileResult list_directory(std::vector<host::DirectoryEntry> &output) noexcept override;
    host::FileResult open(std::string_view name, host::FileOpen options) override;
    host::FileResult open_scoped(host::FileAccessScope scope, std::string_view name, host::FileOpen options) override;
    host::FileResult make_directory(host::FileAccessScope scope, std::string_view name, std::uint32_t mode) noexcept override;
    host::FileResult open_directory(host::FileAccessScope scope, std::string_view name) override;
    host::FileResult directory_valid(int descriptor) noexcept override;
    host::FileResult open_relative(int parent, std::string_view name, host::FileOpen options) override;
    host::FileResult open_directory_relative(int parent, std::string_view name) override;
    host::FileResult make_directory_relative(int parent, std::string_view name, std::uint32_t mode) noexcept override;
    host::FileResult access_relative(int parent, std::string_view name, std::uint32_t mode) noexcept override;
    host::FileResult access_path(host::FileAccessScope scope, std::string_view name, std::uint32_t mode, bool directory_required) noexcept override;
    host::FileResult access_relative_path(int parent, std::string_view name, std::uint32_t mode, bool directory_required) noexcept override;
    host::FileResult remove_relative(int parent, std::string_view name, host::FileRemoveMode mode, bool directory_required = false) noexcept override;
    host::FileResult rename_path(const host::FilePathRef&,const host::FilePathRef&,host::FileRenameInfo&) noexcept override;
    host::FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    host::FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    host::FileResult close(int descriptor) noexcept override;
    host::FileResult flush(int descriptor) noexcept override;
    host::FileResult metadata(int descriptor, host::FileMetadata &output) noexcept override;
    host::FileResult remove(host::FileAccessScope scope, std::string_view name, host::FileRemoveMode mode, bool directory_required = false) noexcept override;
    host::FileResult seek(int descriptor, std::int64_t offset, unsigned whence) noexcept override;
    host::FileResult access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;
    host::FileResult lock(int descriptor,std::uint32_t operation) noexcept override;

  private:
    host::FileResult path_request(unsigned action, host::FileAccessScope scope, int parent, std::string_view name, std::uint64_t options, bool directory_required = false) noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
