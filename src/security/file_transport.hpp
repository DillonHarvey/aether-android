#pragma once
#include "aether/security/protocol.hpp"
#include "aether/host/file_service.hpp"
#include <algorithm>
#include <optional>

namespace aether::security {
// Shared canonical bookkeeping, independent of provider handles and wire input.
// Names are prepared before mutation; committing a prepared position only swaps strings.
namespace file_transport {
inline constexpr std::size_t descriptor_limit=16, rename_row_bytes=48,
    rename_reply_bytes=48+descriptor_limit*rename_row_bytes;
struct Position {
    host::FileAccessScope root=host::FileAccessScope::files_root;
    std::string name;
    std::uint32_t depth=0,length=0;
    std::uint64_t identity=0;
    bool directory=false,unlinked=false;
};
inline host::FileAccessScope scope(const Position &value) noexcept {
    return value.name.empty()?value.root:value.root==host::FileAccessScope::data_root?
        host::FileAccessScope::data_leaf:host::FileAccessScope::files_leaf;
}
inline bool same(const Position &a,const Position &b) noexcept {return a.root==b.root && a.name==b.name;}
inline bool beneath(const Position &value,const Position &parent) noexcept {
    return value.root==parent.root && (value.name==parent.name ||
        (value.name.size()>parent.name.size() && value.name.starts_with(parent.name) && value.name[parent.name.size()]=='/'));
}
inline std::optional<Position> position(host::FileAccessScope selected,std::string_view name,const Position *parent=nullptr) {
    Position result;
    if(parent){
        if(!parent->directory || parent->unlinked || !host::valid_file_path(name,true))return {};
        result.root=parent->root;result.name=parent->name;
        if(!name.empty()){if(!result.name.empty())result.name+='/';result.name+=name;}
    }else{
        if(!host::valid_file_access(selected,name,0))return {};
        result.root=selected==host::FileAccessScope::data_root || selected==host::FileAccessScope::data_leaf?
            host::FileAccessScope::data_root:host::FileAccessScope::files_root;
        result.name=name;
    }
    if(result.root==host::FileAccessScope::data_root && (result.name=="files" || result.name.starts_with("files/"))){
        result.name.erase(0,result.name=="files"?5:6);result.root=host::FileAccessScope::files_root;
    }
    if(!host::valid_file_path(result.name,true))return {};
    result.length=static_cast<std::uint32_t>(result.name.size());
    result.depth=result.name.empty()?0:1+static_cast<std::uint32_t>(std::count(result.name.begin(),result.name.end(),'/'));
    return result;
}
struct Candidate {Position position;bool source=false,replaced=false;};
inline std::optional<Candidate> candidate(const Position &old,const Position &source,const Position &destination) {
    if(old.unlinked)return {};
    Candidate result;
    if(beneath(old,source)){
        result.source=true;result.position=old;result.position.root=destination.root;
        result.position.name=destination.name+old.name.substr(source.name.size());
        if(!host::valid_file_path(result.position.name))throw ProtocolError("AETHER_IPC_RENAME: moved ancestry exceeds profile");
        result.position.length=static_cast<std::uint32_t>(result.position.name.size());
        result.position.depth=1+static_cast<std::uint32_t>(std::count(result.position.name.begin(),result.position.name.end(),'/'));
    }else if(same(old,destination)){result.replaced=true;result.position=old;result.position.unlinked=true;}
    else return {};
    return result;
}
inline bool expected(const Candidate &candidate,const Position &old,const Position &source,const host::FileRenameInfo &info) noexcept {
    return !info.unchanged && (candidate.replaced || (candidate.source && (info.directory || same(old,source))));
}
inline bool valid_row(const Position &old,const Candidate &candidate,const Position &source,
                      const host::FileRenameInfo &info,std::uint64_t identity,bool directory,bool unlinked) noexcept {
    if(!identity || identity>4096 || directory!=old.directory || unlinked!=candidate.replaced ||
        (old.identity && old.identity!=identity))return false;
    if(candidate.replaced)return info.replaced_identity && identity==info.replaced_identity && directory==info.directory;
    return !same(old,source) || (identity==info.source_identity && directory==info.directory);
}
inline bool valid_info(const host::FileRenameInfo &info,const Position &source,const Position &destination) noexcept {
    return info.source_identity && info.source_identity<=4096 && info.replaced_identity<=4096 &&
        info.relocation_count<=descriptor_limit &&
        (info.unchanged?(!info.replaced_identity && !info.relocation_count && same(source,destination)):
            (info.replaced_identity!=info.source_identity && !same(source,destination)));
}
inline bool untouched(const host::FileRenameInfo &info) noexcept {
    if(info.source_identity || info.replaced_identity || info.directory || info.unchanged || info.relocation_count)return false;
    for(const auto &row:info.relocations)if(row.descriptor!=-1 || row.identity || row.scope!=host::FileAccessScope::files_leaf ||
        row.name_length || row.directory || row.unlinked || std::any_of(row.name.begin(),row.name.end(),[](char value){return value!=0;}))return false;
    return true;
}
inline void removed(Position &position,const Position &target,std::uint64_t identity) noexcept {
    if(!position.unlinked && same(position,target) && (!position.identity || position.identity==identity)){
        position.unlinked=true;position.identity=identity;
    }
}
}
} // namespace aether::security
