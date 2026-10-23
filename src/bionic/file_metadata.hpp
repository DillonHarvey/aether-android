#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <string>
namespace aether::bionic {
class NativeDescriptors;
class NativeAccess;
enum class FileMetadataOperation {read_link,read_link_at,descriptor_stat,descriptor_seek,user_id};
class NativeFileMetadata {
  public:
    NativeFileMetadata(a64::GuestMemory &,const a64::AppContext &,NativeDescriptors &,NativeAccess &,std::string_view package);
    a64::Fault invoke(FileMetadataOperation,a64::Address error,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    a64::GuestMemory &memory_;NativeDescriptors &descriptors_;NativeAccess &access_;
    std::string package_,self_,image_;
    std::uint32_t uid_;
    std::string_view rejection_;
};
}
