#pragma once
#include "aether/host/file_service.hpp"
#include <array>
#include <functional>
#include <memory>
#include <optional>
namespace aether::bionic {
// Worker-owned descriptor aliases; provider tokens/handles never become guest FDs.
class NativeDescriptors final:public host::FileService {
    struct Description;
  public:
    explicit NativeDescriptors(host::FileService *provider):provider_(provider){}
    ~NativeDescriptors() override;
    using StandardWrite=std::function<bool(int,std::span<const std::uint8_t>)>;
    // Explicit process setup only: no Windows standard handles are imported.
    void initialize_standard_streams(StandardWrite);
    host::FileResult private_root() noexcept override;
    host::FileResult observe_data_file(std::string_view name) override;
    host::FileResult list_directory(std::vector<host::DirectoryEntry> &output) override;
    host::FileResult open(std::string_view name,host::FileOpen options) override;
    host::FileResult open_scoped(host::FileAccessScope scope,std::string_view name,host::FileOpen options) override;
    host::FileResult open_directory(host::FileAccessScope scope,std::string_view name={});
    host::FileResult open_at(int directory,std::string_view name,host::FileOpen options);
    host::FileResult open_directory_at(int directory,std::string_view name);
    host::FileResult make_directory(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;
    host::FileResult make_directory_at(int directory,std::string_view name,std::uint32_t mode) noexcept;
    host::FileResult access_at(int directory,std::string_view name,std::uint32_t mode,bool directory_required=false) noexcept;
    host::FileResult access_path(host::FileAccessScope scope,std::string_view name,std::uint32_t mode,bool directory_required) noexcept override;
    host::FileResult remove_at(int directory,std::string_view name,host::FileRemoveMode mode,bool directory_required=false) noexcept;
    host::FileResult rename_path(const host::FilePathRef &source,const host::FilePathRef &destination,host::FileRenameInfo &output) noexcept override;
    host::FileResult directory_scope(int fd) const noexcept;
    host::FileResult read(int fd,std::span<std::uint8_t> output) noexcept override;
    host::FileResult write(int fd,std::span<const std::uint8_t> input) noexcept override;
    host::FileResult close(int fd) noexcept override;
    host::FileResult flush(int fd) noexcept override;
    host::FileResult access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;
    host::FileResult lock(int fd,std::uint32_t operation) noexcept override;
    host::FileResult metadata(int fd,host::FileMetadata &output) noexcept override;
    host::FileResult metadata_path(const host::FilePathRef &,host::FilePathMetadata &) noexcept override;
    host::FileResult truncate(int,std::uint64_t) noexcept override;
    host::FileResult read_at(int,std::uint64_t,std::span<std::uint8_t>) noexcept override;
    host::FileResult write_at(int,std::uint64_t,std::span<const std::uint8_t>) noexcept override;
    host::FileResult seek(int fd,std::int64_t offset,unsigned whence) noexcept override;
    host::FileResult remove(host::FileAccessScope scope,std::string_view name,host::FileRemoveMode mode,bool directory_required=false) noexcept override;
    // A logical self-proc link; it conveys no provider token or file authority.
    host::FileResult link_target(int fd,std::string_view package,std::string &output) const;
    host::FileResult duplicate_to(int old_fd,int new_fd) noexcept;
    // Finite Android fcntl profile; aliases retain one shared open description.
    host::FileResult control(int fd,int command,std::uint64_t argument) noexcept;
    // RLIMIT_NOFILE is the native descriptor-number boundary, independent of provider quotas.
    std::uint64_t descriptor_soft_limit() const noexcept {return soft_limit_;}
    std::uint64_t descriptor_hard_limit() const noexcept {return hard_limit_;}
    // Lowering never closes existing descriptions; an unprivileged hard limit cannot increase.
    bool set_descriptor_limits(std::uint64_t soft,std::uint64_t hard) noexcept;
    // Anonymous counters use the same owned descriptions and descriptor namespace.
    host::FileResult event(std::uint32_t initial,std::uint32_t flags);
    // Owned read-only virtual /dev/urandom; never a host pathname/provider FD.
    host::FileResult entropy_device(std::uint32_t flags);
    bool is_entropy(int fd) const noexcept;
    // Trusted app-owned level readiness. This is a real descriptor description,
    // but grants no byte I/O, provider access, or mutable nonblocking behavior.
    class PollSource {
      public:
        virtual ~PollSource() = default;
        virtual std::uint16_t readiness() const noexcept = 0;
    };
    host::FileResult poll_source(std::shared_ptr<const PollSource>);
    static constexpr std::size_t pipe_capacity=64*1024,pipe_atomic_limit=4096,pipe_limit=128;
    // Both fresh aliases are published together only after all allocation succeeds.
    host::FileResult pipe(std::uint32_t flags,std::array<int,2> &output);
    bool contains(int fd) const noexcept {return get(fd)!=nullptr;}
    bool is_event(int fd) const noexcept;
    bool is_pipe(int fd) const noexcept;
    // Trusted host-only description identity for eventfd polling. Keep only a
    // weak registration reference; no provider pointer or token reaches guests.
    std::shared_ptr<const void> event_identity(int fd) const noexcept;
    // Only anonymous event/pipe endpoints are eligible; regular provider files
    // do not acquire native Looper admission through this identity query.
    std::shared_ptr<const void> poll_identity(int fd) const noexcept;
    // Observation only for an in-flight poll; grants no I/O or Looper admission.
    std::shared_ptr<const void> descriptor_identity(int fd) const noexcept;
    std::uint16_t readiness(int fd,std::uint16_t events) const noexcept;
    using Progress=std::function<bool()>;
    host::FileResult read_wait(int fd,std::span<std::uint8_t>,const Progress &);
    host::FileResult write_wait(int fd,std::span<const std::uint8_t>,const Progress &);
    struct WriteOutcome {
        host::FileResult result;
        bool broken_pipe=false;
    };
    // Worker-only result. Broken-pipe signal delivery belongs to the adapter,
    // after committing the actual partial count or EPIPE in the service frame.
    // A positive count with unsupported preserves bytes already published
    // before an unavailable blocking continuation; it is not a broker result.
    WriteOutcome write_wait_outcome(int fd,std::span<const std::uint8_t>,const Progress &);
    enum class IoDirection {read,write};
    struct IoStep {
        host::FileResult result;
        bool broken_pipe=false,pending=false;
    };
    // Host-only in-flight authority, independent of alias close/dup2/reuse.
    // No step or readiness query allocates, invokes Progress/provider code, or
    // changes shared O_NONBLOCK. Blocking pending is distinct from real EAGAIN.
    class PinnedIo {
      public:
        IoStep read_step(std::span<std::uint8_t>) const noexcept;
        IoStep write_step(std::span<const std::uint8_t> remaining) const noexcept;
        bool read_ready() const noexcept;
        bool write_ready(std::span<const std::uint8_t> remaining) const noexcept;
      private:
        friend class NativeDescriptors;
        PinnedIo(std::shared_ptr<Description>,IoDirection,std::size_t) noexcept;
        std::shared_ptr<Description> description_;
        IoDirection direction_;
        std::size_t original_size_;
    };
    // Only owned anonymous pipes/event counters are admitted. A wrong endpoint
    // remains pinned so its step reports EBADF; other kinds keep their old path.
    // The adapter owns buffers/offset and allocates all continuation state before
    // the first step. Advance offset once for a positive prefix, even if pending.
    std::optional<PinnedIo> pin_io(int fd,IoDirection,std::size_t original_size) const noexcept;
    void set_close_on_exec(int fd,bool value) noexcept;
    // Trusted opening adapter records accepted persistent request flags only.
    // This never changes provider access rights or performs another open.
    void record_open_status(int fd,std::uint32_t original_flags) noexcept;
  private:
    struct PipeChannel;
    struct Entry {std::shared_ptr<Description> description;bool close_on_exec=false;};
    host::FileService *provider_;
    std::array<Entry,256> entries_{};
    // Weak slots retain the charge while any endpoint/in-flight syscall holds
    // the channel, without extending lifetime themselves or creating cycles.
    std::array<std::weak_ptr<PipeChannel>,pipe_limit> pipes_{};
    std::uint64_t next_pipe_identity_=1;
    std::uint64_t soft_limit_=256,hard_limit_=256;
    bool standard_initialized_=false;
    Description *get(int fd) const noexcept;
    host::FileResult relative_target(int fd,std::string_view path,host::FileAccessScope &scope,std::string &name,int &parent) const;
    host::FileResult remove_owned(host::FileAccessScope scope,std::string_view name,host::FileRemoveMode mode,bool directory_required,int parent=-1,std::string_view relative={}) noexcept;
    host::FileResult open_owned(host::FileAccessScope scope,std::string_view name,host::FileOpen options,bool directory,int parent=-1,std::string_view display={});
};
}
