#pragma once
#include "aether/host/file_service.hpp"
#include <array>
#include <functional>
namespace aether::bionic {
// Worker-owned descriptor aliases; provider tokens/handles never become guest FDs.
class NativeDescriptors final:public host::FileService {
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
    host::FileResult seek(int fd,std::int64_t offset,unsigned whence) noexcept override;
    host::FileResult remove(host::FileAccessScope scope,std::string_view name,host::FileRemoveMode mode,bool directory_required=false) noexcept override;
    // A logical self-proc link; it conveys no provider token or file authority.
    host::FileResult link_target(int fd,std::string_view package,std::string &output) const;
    host::FileResult duplicate_to(int old_fd,int new_fd) noexcept;
    // RLIMIT_NOFILE is the native descriptor-number boundary, independent of provider quotas.
    std::uint64_t descriptor_soft_limit() const noexcept {return soft_limit_;}
    std::uint64_t descriptor_hard_limit() const noexcept {return hard_limit_;}
    // Lowering never closes existing descriptions; an unprivileged hard limit cannot increase.
    bool set_descriptor_limits(std::uint64_t soft,std::uint64_t hard) noexcept;
    // Anonymous counters use the same owned descriptions and descriptor namespace.
    host::FileResult event(std::uint32_t initial,std::uint32_t flags);
    bool contains(int fd) const noexcept {return get(fd)!=nullptr;}
    bool is_event(int fd) const noexcept;
    std::uint16_t readiness(int fd,std::uint16_t events) const noexcept;
    using Progress=std::function<bool()>;
    host::FileResult read_wait(int fd,std::span<std::uint8_t>,const Progress &);
    host::FileResult write_wait(int fd,std::span<const std::uint8_t>,const Progress &);
    void set_close_on_exec(int fd,bool value) noexcept;
  private:
    struct Description;
    struct Entry {std::shared_ptr<Description> description;bool close_on_exec=false;};
    host::FileService *provider_;
    std::array<Entry,256> entries_{};
    std::uint64_t soft_limit_=256,hard_limit_=256;
    bool standard_initialized_=false;
    Description *get(int fd) const noexcept;
    host::FileResult relative_target(int fd,std::string_view path,host::FileAccessScope &scope,std::string &name,int &parent) const;
    host::FileResult remove_owned(host::FileAccessScope scope,std::string_view name,host::FileRemoveMode mode,bool directory_required,int parent=-1,std::string_view relative={}) noexcept;
    host::FileResult open_owned(host::FileAccessScope scope,std::string_view name,host::FileOpen options,bool directory,int parent=-1,std::string_view display={});
};
}
