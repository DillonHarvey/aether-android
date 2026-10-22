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
    host::FileResult private_root() noexcept override;
    host::FileResult observe_data_file(std::string_view name) override;
    host::FileResult list_directory(std::vector<host::DirectoryEntry> &output) override;
    host::FileResult open(std::string_view name,host::FileOpen options) override;
    host::FileResult read(int fd,std::span<std::uint8_t> output) noexcept override;
    host::FileResult write(int fd,std::span<const std::uint8_t> input) noexcept override;
    host::FileResult close(int fd) noexcept override;
    host::FileResult flush(int fd) noexcept override;
    host::FileResult access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;
    host::FileResult lock(int fd,std::uint32_t operation) noexcept override;
    host::FileResult duplicate_to(int old_fd,int new_fd) noexcept;
    // Anonymous counters use the same owned descriptions and descriptor namespace.
    host::FileResult event(std::uint32_t initial,std::uint32_t flags);
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
    Description *get(int fd) const noexcept;
};
}
