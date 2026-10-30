#pragma once
#include "aether/host/file_service.hpp"
#include "aether/host/document_service.hpp"
#include "aether/host/drop_text.hpp"
#include "aether/host/time_service.hpp"
#include "aether/host/clipboard_service.hpp"
#include "aether/security/worker.hpp"

namespace aether::android { struct TextEditObservation; struct SoftInputObservation; }
namespace aether::security {
struct ActivityTerminalActivations;
// Single owner-thread worker provider. Guest descriptors map to opaque, non-reused
// broker tokens, never Windows handles. Transport failure permanently closes the client.
class BrokerClient final : public host::TimeService, public host::FileService, public host::DocumentService,
                           public host::ClipboardService {
  public:
    BrokerClient(HANDLE reader, HANDLE writer, std::uint64_t session, bool interactive = false,
                 bool activity_commands = false);
    ~BrokerClient() override;
    Frame request(Operation operation, std::vector<std::uint8_t> payload = {});
    // Nonblocking owner-only interactive command mailbox; one command in order.
    // RPC calls may collect its validated fragments but never execute commands.
    std::optional<std::vector<std::uint8_t>> poll_activity_command(std::uint64_t sequence);
    // One synchronous presentation record, acknowledged only after consumption.
    // Commands received while waiting are validated/queued, never executed.
    void send_text_edit_observation(const android::TextEditObservation &observation, std::uint64_t context);
    bool send_soft_input_observation(const android::SoftInputObservation &observation, std::uint64_t context);
    // One terminal attempt; receipt acknowledges bounded host custody only.
    void send_terminal_view_activations(const ActivityTerminalActivations &batch, std::uint64_t context);
    // Trusted final cleanup, including an empty terminal batch. Sends no IPC.
    void retire_activity_channel() noexcept;
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
    // Document FDs share the existing 16 slots but cannot enter private-file APIs.
    // Revocation disables only this document adapter and closes its live streams.
    host::FileResult describe(std::string_view uri, host::DocumentInfo &output) noexcept override;
    host::FileResult open_document(std::string_view uri) noexcept override;
    host::FileResult read_document(int descriptor, std::span<std::uint8_t> output) noexcept override;
    host::FileResult close_document(int descriptor) noexcept override;
    host::FileResult claim_drop(std::string_view uri, std::uint64_t drop_id) noexcept override;
    host::FileResult release_drop(std::string_view uri, std::uint64_t drop_id) noexcept override;
    // Complete one separately reviewed selection; output changes only after
    // all bounded chunks match its exact metadata and UTF-16LE digest.
    host::FileResult read_drop_text(std::uint64_t drop_id, const host::DropTextInfo &info,
                                   std::u16string &output) noexcept;
    host::ClipboardStatus has_text(bool &value) noexcept override;
    host::ClipboardStatus read_text(std::optional<std::u16string> &value) noexcept override;
    host::ClipboardStatus write_text(std::u16string_view value) noexcept override;
    host::ClipboardStatus clear() noexcept override;
    void revoke_documents() noexcept override;

  private:
    host::FileResult path_request(unsigned action, host::FileAccessScope scope, int parent, std::string_view name, std::uint64_t options, bool directory_required = false) noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
