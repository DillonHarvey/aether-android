#include "aether/host/file_service.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <windows.h>
#include <aclapi.h>
#include <winternl.h>

extern "C" NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

namespace aether::host {
namespace {
// Documented FILE_RENAME_INFORMATION ABI; the SDK user-mode enum omits class 65.
// NtSetInformationFile retains the actual destination parent instead of converting
// this safe relative leaf through the Win32 DOS-path wrapper.
struct NativeRenameInformation {
    ULONG flags;
    HANDLE root_directory;
    ULONG name_length;
    WCHAR name[1];
};
static_assert(sizeof(void*)==8 && sizeof(NativeRenameInformation)==24);
static_assert(offsetof(NativeRenameInformation,flags)==0 && offsetof(NativeRenameInformation,root_directory)==8);
static_assert(offsetof(NativeRenameInformation,name_length)==16 && offsetof(NativeRenameInformation,name)==20);
constexpr auto rename_information_ex=static_cast<FILE_INFORMATION_CLASS>(65);
constexpr NTSTATUS status_pending=0x103;
constexpr std::uint64_t maximum_file = private_file_size_limit;
constexpr DWORD advisory_lock_offset=static_cast<DWORD>(maximum_file*2);
FileError error(DWORD value) {
    switch (value) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return FileError::missing;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_CANT_ACCESS_FILE:
        return FileError::denied;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return FileError::exists;
    case ERROR_INVALID_HANDLE:
        return FileError::bad_descriptor;
    case ERROR_DIR_NOT_EMPTY:
        return FileError::not_empty;
    case ERROR_DIRECTORY:
        return FileError::not_directory;
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_NAME:
        return FileError::invalid;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        return FileError::quota;
    default:
        return FileError::io;
    }
}
bool safe_name(std::string_view name) {
    if (name.empty() || name.size() > 127 || name.front() == '.' || name.back() == '.' ||
        name.find("..") != std::string_view::npos)
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
    });
}
} // namespace
struct HostFileService::Impl {
    struct File {
        HANDLE handle = INVALID_HANDLE_VALUE;
        bool read = false, write = false;
        std::uint32_t lock_mode=0;
        std::uint64_t index=0;
        bool unlinked=false;
        bool directory=false;
        std::uint32_t depth=0,path_length=0;
        FileAccessScope root_scope=FileAccessScope::files_leaf;
        FileAccessScope scope=FileAccessScope::files_leaf;
        std::string name;
        FileResult release() noexcept {
            const auto held=handle;handle=INVALID_HANDLE_VALUE;
            DWORD failure=ERROR_SUCCESS;
            if(lock_mode){OVERLAPPED region{};region.Offset=advisory_lock_offset;if(!UnlockFileEx(held,0,1,0,&region))failure=GetLastError();}
            lock_mode=0;
            if(!CloseHandle(held))return {-1,error(GetLastError())};
            return failure?FileResult{-1,error(failure)}:FileResult{0,FileError::none};
        }
    };
    HANDLE root = INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR directory_security=nullptr;
    std::array<File, 64> files{};
    std::map<std::uint64_t, std::uint64_t> identities; // Native indices remain broker-side only.
    FileResult opaque_identity(std::uint64_t index) noexcept {
        try {
            auto found = identities.find(index);
            if (found == identities.end()) {
                if (identities.size() >= 4096) return {-1, FileError::quota};
                found = identities.emplace(index, identities.size() + 1).first;
            }
            return {static_cast<std::int64_t>(found->second), FileError::none};
        } catch (...) { return {-1, FileError::io}; }
    }
    struct Resolved {
        HANDLE base=INVALID_HANDLE_VALUE;
        std::array<HANDLE,private_path_depth> ancestors{};std::size_t count=0;
        std::wstring leaf;std::uint32_t depth=0,length=0;
        FileAccessScope root_scope=FileAccessScope::files_leaf;
        FileAccessScope scope=FileAccessScope::files_leaf;
        std::string name;
        ~Resolved(){for(std::size_t i=count;i>0;--i)CloseHandle(ancestors[i-1]);}
    };
    FileResult check_directory(HANDLE handle) noexcept {
        BY_HANDLE_FILE_INFORMATION info{};FILE_STANDARD_INFO standard{};
        if(GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,&info) ||
           !GetFileInformationByHandleEx(handle,FileStandardInfo,&standard,sizeof(standard)))return {-1,FileError::io};
        if(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)return {-1,FileError::denied};
        if(!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) || !standard.Directory)return {-1,FileError::not_directory};
        if(standard.DeletePending)return {-1,FileError::missing};
        return {0,FileError::none};
    }
    static NTSTATUS relative_open(HANDLE base,std::wstring &leaf,ACCESS_MASK rights,ULONG disposition,ULONG options,
                                  HANDLE &handle,PSECURITY_DESCRIPTOR security=nullptr,ULONG sharing=FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE) noexcept {
        UNICODE_STRING relative{};relative.Length=static_cast<USHORT>(leaf.size()*sizeof(wchar_t));relative.MaximumLength=relative.Length;relative.Buffer=leaf.data();
        OBJECT_ATTRIBUTES attributes{};attributes.Length=sizeof(attributes);attributes.RootDirectory=base;attributes.ObjectName=&relative;attributes.SecurityDescriptor=security;
        IO_STATUS_BLOCK io{};
        return NtCreateFile(&handle,rights,&attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,sharing,disposition,options|0x20u|0x00200000u,nullptr,0);
    }
    FileResult resolve(FileAccessScope scope,std::string_view name,int parent,Resolved &out) {
        bool data=false;std::uint32_t depth=0,length=0;std::string_view prefix;
        if(parent>=0){
            const auto file=find(parent);if(!file)return {-1,FileError::bad_descriptor};
            if(!file->directory)return {-1,FileError::not_directory};if(file->unlinked)return {-1,FileError::missing};
            const auto valid=check_directory(file->handle);if(valid.error!=FileError::none)return valid;
            if(!valid_file_path(name,true))return {-1,FileError::invalid};
            out.base=file->handle;depth=file->depth;length=file->path_length;out.root_scope=file->root_scope;
            data=file->root_scope==FileAccessScope::data_root;prefix=file->name;out.scope=file->scope;
        }else{
            if(!valid_file_access(scope,name,0))return {-1,FileError::denied};
            out.base=root;data=scope==FileAccessScope::data_root || scope==FileAccessScope::data_leaf;
            out.root_scope=data?FileAccessScope::data_root:FileAccessScope::files_root;out.scope=data?FileAccessScope::data_leaf:FileAccessScope::files_leaf;
        }
        // files/ is the existing logical files-root alias within the app-data root.
        if(data && (name=="files" || name.starts_with("files/"))){name.remove_prefix(name=="files"?5:6);data=false;out.root_scope=FileAccessScope::files_root;out.scope=FileAccessScope::files_leaf;}
        if(!name.empty()){
            const auto parts=1+static_cast<std::uint32_t>(std::count(name.begin(),name.end(),'/'));
            if(depth+parts>private_path_depth || name.size()+length+(length?1:0)>private_path_limit)return {-1,FileError::invalid};
            out.depth=depth+parts;out.length=length+static_cast<std::uint32_t>(name.size())+(length?1:0);
            out.root_scope=FileAccessScope::files_leaf;
        }else{out.depth=depth;out.length=length;}
        out.name=prefix;
        if(!name.empty()){if(!out.name.empty())out.name+='/';out.name+=name;}
        while(true){
            const auto slash=name.find('/');const auto component=name.substr(0,slash);
            std::wstring wide=std::wstring(component.begin(),component.end());
            if(data && !wide.empty()){wide.insert(wide.begin(),L'@');data=false;}
            if(slash==std::string_view::npos){out.leaf=std::move(wide);return {0,FileError::none};}
            HANDLE next=INVALID_HANDLE_VALUE;
            // No delete sharing on traversal handles: every validated ancestor stays fixed for this operation.
            const auto status=relative_open(out.base,wide,FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,1u,1u,next,nullptr,FILE_SHARE_READ|FILE_SHARE_WRITE);
            if(status<0)return {-1,error(RtlNtStatusToDosError(status))};
            out.ancestors[out.count++]=next;
            const auto valid=check_directory(next);if(valid.error!=FileError::none)return valid;
            out.base=next;name.remove_prefix(slash+1);
        }
    }
    FileResult path(unsigned action,FileAccessScope scope,std::string_view name,int parent,FileOpen options={},std::uint32_t mode=0,
                    FileRemoveMode remove_mode=FileRemoveMode::file,bool directory_required=false) noexcept {
        try{
            if(action==0 && mode!=0700)return {-1,FileError::unsupported};
            if(action==2 && ((!options.read && !options.write)||(options.truncate && !options.write)||(options.exclusive && !options.create)))return {-1,FileError::invalid};
            if(action==3 && (mode&~7U))return {-1,FileError::invalid};
            if(action==4 && static_cast<unsigned>(remove_mode)>2)return {-1,FileError::invalid};
            Resolved resolved;const auto walked=resolve(scope,name,parent,resolved);if(walked.error!=FileError::none)return walked;
            if(resolved.leaf.empty() && action==0){const auto valid=check_directory(resolved.base);return valid.error==FileError::none?FileResult{-1,FileError::exists}:valid;}
            if(resolved.leaf.empty() && action==4)return {-1,FileError::denied};
            auto slot=files.end();if(action==1 || action==2){slot=std::find_if(files.begin(),files.end(),[](const auto &file){return file.handle==INVALID_HANDLE_VALUE;});if(slot==files.end())return {-1,FileError::descriptor_limit};}
            ACCESS_MASK rights=FILE_READ_ATTRIBUTES|SYNCHRONIZE;ULONG disposition=1u,kind=0;
            if(action==0){kind=1u;disposition=2u;}
            if(action==1){kind=1u;rights|=FILE_LIST_DIRECTORY|FILE_TRAVERSE;}
            if(action==2){kind=0x40u;rights|=(options.read?FILE_READ_DATA:0)|(options.write?FILE_WRITE_DATA:0);disposition=options.create?(options.exclusive?2u:3u):1u;}
            if(action==3)rights|=(mode&4?FILE_READ_DATA:0)|(mode&2?FILE_WRITE_DATA|FILE_APPEND_DATA:0)|(mode&1?FILE_TRAVERSE:0);
            if(action==4)rights|=DELETE;
            HANDLE handle=INVALID_HANDLE_VALUE;
            const auto status=relative_open(resolved.base,resolved.leaf,rights,disposition,kind,handle,action==0?directory_security:nullptr);
            if(status<0){if(static_cast<ULONG>(status)==0xc00000baU)return {-1,FileError::is_directory};return {-1,error(RtlNtStatusToDosError(status))};}
            struct Close {HANDLE value;~Close(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}} close{handle};
            BY_HANDLE_FILE_INFORMATION info{};FILE_STANDARD_INFO standard{};
            if(GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,&info) || !GetFileInformationByHandleEx(handle,FileStandardInfo,&standard,sizeof(standard)))return {-1,FileError::io};
            if(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)return {-1,FileError::denied};
            const bool directory=(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;
            if(directory!=static_cast<bool>(standard.Directory))return {-1,FileError::io};
            if(standard.DeletePending)return {-1,FileError::missing};
            if((action==0 || action==1) && !directory)return {-1,FileError::not_directory};
            if(action==2 && directory)return {-1,FileError::is_directory};
            if(!directory && (info.nNumberOfLinks!=1 || standard.NumberOfLinks!=1 || standard.EndOfFile.QuadPart<0 || static_cast<std::uint64_t>(standard.EndOfFile.QuadPart)>maximum_file))return {-1,FileError::denied};
            const auto index=(static_cast<std::uint64_t>(info.nFileIndexHigh)<<32)|info.nFileIndexLow;
            if(action==0){close.value=INVALID_HANDLE_VALUE;return CloseHandle(handle)?FileResult{0,FileError::none}:FileResult{-1,FileError::io};}
            if(action==3 && directory_required && !directory)return {-1,FileError::not_directory};
            if(action==3)return !directory && (mode&1)?FileResult{-1,FileError::denied}:FileResult{0,FileError::none};
            if(action==4){
                if(directory_required && !directory)return {-1,FileError::not_directory};
                if(remove_mode==FileRemoveMode::file && directory)return {-1,FileError::is_directory};
                if(remove_mode==FileRemoveMode::directory && !directory)return {-1,FileError::not_directory};
                const auto identity=opaque_identity(index);if(identity.error!=FileError::none)return identity;
                FILE_DISPOSITION_INFO_EX disposition_info{};disposition_info.Flags=FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS|FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
                if(!SetFileInformationByHandle(handle,FileDispositionInfoEx,&disposition_info,sizeof(disposition_info))){const auto failure=GetLastError();if(failure==ERROR_INVALID_FUNCTION || failure==ERROR_INVALID_PARAMETER || failure==ERROR_NOT_SUPPORTED)return {-1,FileError::unsupported};return {-1,error(failure)};}
                close.value=INVALID_HANDLE_VALUE;if(!CloseHandle(handle))return {-1,FileError::io};
                for(auto &file:files)if(file.handle!=INVALID_HANDLE_VALUE && file.index==index)file.unlinked=true;
                return identity;
            }
            // Keep published descriptions on identity handles. Named descendant opens prevent
            // NTFS parent-directory renames even when they share delete. The ID comes only
            // from this already-contained, no-follow held object, never from a caller.
            if(!index)return {-1,FileError::denied};
            FILE_ID_DESCRIPTOR object_id{};object_id.dwSize=sizeof(object_id);object_id.Type=FileIdType;
            object_id.FileId.QuadPart=std::bit_cast<LONGLONG>(index);
            const auto by_identity=OpenFileById(root,&object_id,rights,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                nullptr,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT);
            if(by_identity==INVALID_HANDLE_VALUE){
                const auto failure=GetLastError();
                if(failure==ERROR_INVALID_FUNCTION || failure==ERROR_INVALID_PARAMETER || failure==ERROR_NOT_SUPPORTED ||
                   failure==ERROR_CALL_NOT_IMPLEMENTED)return {-1,FileError::unsupported};
                return {-1,error(failure)};
            }
            Close identity_close{by_identity};
            BY_HANDLE_FILE_INFORMATION identity_info{};FILE_STANDARD_INFO identity_standard{};
            const auto verified=inspect_object(by_identity,identity_info,identity_standard);if(verified.error!=FileError::none)return verified;
            const auto verified_index=(static_cast<std::uint64_t>(identity_info.nFileIndexHigh)<<32)|identity_info.nFileIndexLow;
            if(verified_index!=index || identity_info.dwVolumeSerialNumber!=info.dwVolumeSerialNumber ||
               static_cast<bool>(identity_standard.Directory)!=directory)return {-1,FileError::denied};
            close.value=INVALID_HANDLE_VALUE;if(!CloseHandle(handle))return {-1,FileError::io};
            handle=by_identity;close.value=handle;identity_close.value=INVALID_HANDLE_VALUE;
            if(action==1){const auto identity=opaque_identity(index);if(identity.error!=FileError::none)return identity;}
            if(action==2 && options.truncate && !SetEndOfFile(handle))return {-1,error(GetLastError())};
            *slot={handle,action==2?options.read:true,action==2?options.write:false,0,index,false,action==1,resolved.depth,resolved.length,resolved.root_scope};
            slot->name.swap(resolved.name);slot->scope=resolved.scope;
            close.value=INVALID_HANDLE_VALUE;return {3+(slot-files.begin()),FileError::none};
        }catch(...){return {-1,FileError::io};}
    }
    struct NamespaceNode {
        std::uint64_t index=0,parent=0;
        FileAccessScope scope=FileAccessScope::files_leaf;
        std::string name;
        bool directory=false;
    };
    struct NamespaceSnapshot {
        std::array<NamespaceNode,private_namespace_limit+1> nodes{};
        std::size_t count=1;
        DWORD volume=0;
        const NamespaceNode *find(std::uint64_t index) const noexcept {
            for(std::size_t i=0;i<count;++i)if(nodes[i].index==index)return &nodes[i];return nullptr;
        }
        bool within(std::uint64_t index,std::uint64_t ancestor) const noexcept {
            for(unsigned depth=0;index && depth<=private_path_depth;++depth){
                if(index==ancestor)return true;const auto node=find(index);if(!node)return false;index=node->parent;
            }
            return false;
        }
    };
    FileResult inspect_object(HANDLE handle,BY_HANDLE_FILE_INFORMATION &info,FILE_STANDARD_INFO &standard) noexcept {
        if(GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,&info) ||
            !GetFileInformationByHandleEx(handle,FileStandardInfo,&standard,sizeof(standard)))return {-1,FileError::io};
        if(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)return {-1,FileError::denied};
        const bool directory=(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;
        if(directory!=static_cast<bool>(standard.Directory))return {-1,FileError::io};
        if(standard.DeletePending)return {-1,FileError::missing};
        if(!directory && (info.nNumberOfLinks!=1 || standard.NumberOfLinks!=1 || standard.EndOfFile.QuadPart<0 ||
            static_cast<std::uint64_t>(standard.EndOfFile.QuadPart)>maximum_file))return {-1,FileError::denied};
        return {0,FileError::none};
    }
    FileResult snapshot_directory(HANDLE handle,std::size_t parent,NamespaceSnapshot &snapshot) {
        alignas(FILE_ID_BOTH_DIR_INFO) std::array<std::uint8_t,4096> buffer{};bool restart=true;
        for(;;){
            if(!GetFileInformationByHandleEx(handle,restart?FileIdBothDirectoryRestartInfo:FileIdBothDirectoryInfo,buffer.data(),static_cast<DWORD>(buffer.size()))){
                const auto failure=GetLastError();return failure==ERROR_NO_MORE_FILES?FileResult{0,FileError::none}:FileResult{-1,error(failure)};
            }
            restart=false;std::size_t offset=0;
            for(;;){
                constexpr auto header=offsetof(FILE_ID_BOTH_DIR_INFO,FileName);
                if(offset>buffer.size()-header)return {-1,FileError::io};
                const auto *entry=reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(buffer.data()+offset);const auto remaining=buffer.size()-offset;
                if(entry->FileNameLength%sizeof(wchar_t) || entry->FileNameLength>remaining-header)return {-1,FileError::io};
                const std::wstring_view physical(entry->FileName,entry->FileNameLength/sizeof(wchar_t));
                if(physical!=L"." && physical!=L".."){
                    if(snapshot.count==snapshot.nodes.size())return {-1,FileError::quota};
                    if(physical.empty() || physical.size()>128 || (entry->FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))return {-1,FileError::denied};
                    std::string component;component.reserve(physical.size());for(const auto c:physical){if(c>127)return {-1,FileError::denied};component+=static_cast<char>(c);}
                    auto scope=snapshot.nodes[parent].scope;
                    if(parent==0){scope=FileAccessScope::files_leaf;if(component.starts_with('@')){component.erase(0,1);scope=FileAccessScope::data_leaf;}}
                    if(!safe_name(component))return {-1,FileError::denied};
                    std::string full=snapshot.nodes[parent].name;if(!full.empty())full+='/';full+=component;
                    if(!valid_file_path(full))return {-1,FileError::invalid};
                    std::wstring leaf(physical);HANDLE child=INVALID_HANDLE_VALUE;
                    const auto status=relative_open(handle,leaf,FILE_READ_ATTRIBUTES|FILE_LIST_DIRECTORY|SYNCHRONIZE,1u,0,child,nullptr,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE);
                    if(status<0)return {-1,error(RtlNtStatusToDosError(status))};
                    struct Close {HANDLE value;~Close(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}} close{child};
                    BY_HANDLE_FILE_INFORMATION info{};FILE_STANDARD_INFO standard{};const auto valid=inspect_object(child,info,standard);if(valid.error!=FileError::none)return valid;
                    const auto index=(static_cast<std::uint64_t>(info.nFileIndexHigh)<<32)|info.nFileIndexLow;
                    if(!index || info.dwVolumeSerialNumber!=snapshot.volume || index!=static_cast<std::uint64_t>(entry->FileId.QuadPart) || snapshot.find(index))return {-1,FileError::denied};
                    const auto position=snapshot.count++;
                    snapshot.nodes[position]={index,snapshot.nodes[parent].index,scope,std::move(full),standard.Directory!=FALSE};
                    if(standard.Directory){const auto scanned=snapshot_directory(child,position,snapshot);if(scanned.error!=FileError::none)return scanned;}
                }
                if(!entry->NextEntryOffset)break;
                if(entry->NextEntryOffset<header+entry->FileNameLength || entry->NextEntryOffset>remaining || entry->NextEntryOffset%alignof(FILE_ID_BOTH_DIR_INFO))return {-1,FileError::io};
                offset+=entry->NextEntryOffset;
            }
        }
    }
    FileResult rename_path(const FilePathRef &source,const FilePathRef &destination,FileRenameInfo &output) noexcept {
        try{
            if(source.directory<-1 || destination.directory<-1)return {-1,FileError::bad_descriptor};
            Resolved from,to;
            auto result=resolve(source.scope,source.name,source.directory,from);if(result.error!=FileError::none)return result;
            result=resolve(destination.scope,destination.name,destination.directory,to);if(result.error!=FileError::none)return result;
            if(from.leaf.empty() || to.leaf.empty())return {-1,FileError::denied}; // Both logical roots stay immutable.
            HANDLE source_handle=INVALID_HANDLE_VALUE,target_handle=INVALID_HANDLE_VALUE;
            struct Close {HANDLE &value;~Close(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}} source_close{source_handle},target_close{target_handle};
            auto status=relative_open(from.base,from.leaf,FILE_READ_ATTRIBUTES|SYNCHRONIZE,1u,0,source_handle);
            if(status<0)return {-1,error(RtlNtStatusToDosError(status))};
            BY_HANDLE_FILE_INFORMATION source_info{};FILE_STANDARD_INFO source_standard{};
            result=inspect_object(source_handle,source_info,source_standard);if(result.error!=FileError::none)return result;
            const bool directory=source_standard.Directory!=FALSE;
            if(source.directory_required && !directory)return {-1,FileError::not_directory};
            const auto source_index=(static_cast<std::uint64_t>(source_info.nFileIndexHigh)<<32)|source_info.nFileIndexLow;
            const auto source_identity=opaque_identity(source_index);if(source_identity.error!=FileError::none)return source_identity;
            auto prepared=std::make_unique<FileRenameInfo>();prepared->source_identity=static_cast<std::uint64_t>(source_identity.value);prepared->directory=directory;
            status=relative_open(to.base,to.leaf,FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,1u,0,target_handle);
            std::uint64_t target_index=0;bool target_exists=status>=0;
            if(!target_exists){const auto failure=error(RtlNtStatusToDosError(status));if(failure!=FileError::missing)return {-1,failure};}
            if(target_exists){
                BY_HANDLE_FILE_INFORMATION target_info{};FILE_STANDARD_INFO target_standard{};
                result=inspect_object(target_handle,target_info,target_standard);if(result.error!=FileError::none)return result;
                if(source_info.dwVolumeSerialNumber!=target_info.dwVolumeSerialNumber)return {-1,FileError::denied};
                if(directory!=static_cast<bool>(target_standard.Directory))return {-1,directory?FileError::not_directory:FileError::is_directory};
                target_index=(static_cast<std::uint64_t>(target_info.nFileIndexHigh)<<32)|target_info.nFileIndexLow;
            }
            if(destination.directory_required && !directory)return {-1,FileError::not_directory};
            const auto close_once=[](HANDLE &handle) noexcept {if(handle==INVALID_HANDLE_VALUE)return true;const auto value=handle;handle=INVALID_HANDLE_VALUE;return CloseHandle(value)!=FALSE;};
            if(target_exists && target_index==source_index){
                prepared->unchanged=true;
                const auto target_closed=close_once(target_handle),source_closed=close_once(source_handle);if(!target_closed || !source_closed)return {-1,FileError::io};
                output=*prepared;return {0,FileError::none};
            }
            auto snapshot=std::make_unique<NamespaceSnapshot>();
            BY_HANDLE_FILE_INFORMATION root_info{};if(!GetFileInformationByHandle(root,&root_info))return {-1,FileError::io};
            snapshot->volume=root_info.dwVolumeSerialNumber;
            snapshot->nodes[0].index=(static_cast<std::uint64_t>(root_info.nFileIndexHigh)<<32)|root_info.nFileIndexLow;snapshot->nodes[0].directory=true;
            if(!snapshot->nodes[0].index || source_info.dwVolumeSerialNumber!=snapshot->volume)return {-1,FileError::denied};
            // Snapshot handles share delete to coexist with live provider handles.
            // They are all released by the read-only scan before the one rename below.
            result=snapshot_directory(root,0,*snapshot);if(result.error!=FileError::none)return result;
            const auto source_node=snapshot->find(source_index);if(!source_node || source_node->directory!=directory || source_node->name!=from.name || source_node->scope!=from.scope)return {-1,FileError::denied};
            BY_HANDLE_FILE_INFORMATION parent_info{};if(!GetFileInformationByHandle(to.base,&parent_info))return {-1,FileError::io};
            const auto parent_index=(static_cast<std::uint64_t>(parent_info.nFileIndexHigh)<<32)|parent_info.nFileIndexLow;
            const auto parent_node=snapshot->find(parent_index);if(!parent_node || !parent_node->directory || parent_info.dwVolumeSerialNumber!=snapshot->volume)return {-1,FileError::denied};
            const auto parent_separator=to.name.rfind('/');
            const auto expected_parent=parent_separator==std::string::npos?std::string_view{}:std::string_view(to.name).substr(0,parent_separator);
            if(parent_node->name!=expected_parent || (parent_index!=snapshot->nodes[0].index && parent_node->scope!=to.scope))return {-1,FileError::denied};
            if(directory && snapshot->within(parent_index,source_index))return {-1,FileError::invalid};
            if(target_exists){
                const auto target_node=snapshot->find(target_index);if(!target_node || target_node->name!=to.name || target_node->scope!=to.scope)return {-1,FileError::denied};
                if(directory)for(std::size_t i=1;i<snapshot->count;++i)if(snapshot->nodes[i].parent==target_index)return {-1,FileError::not_empty};
                const auto identity=opaque_identity(target_index);if(identity.error!=FileError::none)return identity;prepared->replaced_identity=static_cast<std::uint64_t>(identity.value);
            }
            std::array<std::string,private_namespace_limit+1> moved_names{};
            for(std::size_t i=1;i<snapshot->count;++i)if(snapshot->within(snapshot->nodes[i].index,source_index)){
                const auto &node=snapshot->nodes[i];if(node.scope!=from.scope || !std::string_view(node.name).starts_with(from.name))return {-1,FileError::denied};
                moved_names[i]=to.name+node.name.substr(from.name.size());if(!valid_file_path(moved_names[i]))return {-1,FileError::invalid};
            }
            std::array<std::string,64> held_names{};
            for(std::size_t i=0;i<files.size();++i){
                const auto &file=files[i];if(file.handle==INVALID_HANDLE_VALUE || file.unlinked)continue;
                const auto node=snapshot->find(file.index);if(!node)continue;
                const bool replaced=target_exists && file.index==target_index;
                const bool moved=snapshot->within(file.index,source_index);if(!replaced && !moved)continue;
                if(node->name!=file.name || node->scope!=file.scope || node->directory!=file.directory)return {-1,FileError::denied};
                const auto identity=opaque_identity(file.index);if(identity.error!=FileError::none)return identity;
                const auto position=static_cast<std::size_t>(node-snapshot->nodes.data());
                held_names[i]=replaced?file.name:moved_names[position];
                auto &row=prepared->relocations[prepared->relocation_count++];row.descriptor=3+static_cast<int>(i);row.identity=static_cast<std::uint64_t>(identity.value);
                row.scope=replaced?file.scope:to.scope;row.name_length=static_cast<std::uint32_t>(held_names[i].size());row.directory=file.directory;row.unlinked=replaced;
                std::copy(held_names[i].begin(),held_names[i].end(),row.name.begin());
            }
            std::vector<std::uint8_t> bytes(sizeof(NativeRenameInformation)+to.leaf.size()*sizeof(wchar_t));
            auto *rename=reinterpret_cast<NativeRenameInformation*>(bytes.data());
            rename->flags=0x1u|0x2u|0x40u; // REPLACE_IF_EXISTS | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE.
            rename->root_directory=to.base;rename->name_length=static_cast<ULONG>(to.leaf.size()*sizeof(wchar_t));
            std::copy(to.leaf.begin(),to.leaf.end(),rename->name);
            // Acquire DELETE only after cycle/subtree checks; destination traversal pins may otherwise
            // prevent opening a source directory that is also an invalid destination ancestor.
            HANDLE writable=INVALID_HANDLE_VALUE;
            status=relative_open(from.base,from.leaf,DELETE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,1u,0,writable);
            if(status<0)return {-1,error(RtlNtStatusToDosError(status))};
            struct WritableClose {HANDLE &value;~WritableClose(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}} writable_close{writable};
            BY_HANDLE_FILE_INFORMATION final_source{};FILE_STANDARD_INFO final_standard{};
            result=inspect_object(writable,final_source,final_standard);if(result.error!=FileError::none)return result;
            const auto final_index=(static_cast<std::uint64_t>(final_source.nFileIndexHigh)<<32)|final_source.nFileIndexLow;
            if(final_index!=source_index || final_source.dwVolumeSerialNumber!=source_info.dwVolumeSerialNumber ||
                static_cast<bool>(final_standard.Directory)!=directory)return {-1,FileError::denied};
            if(!close_once(source_handle))return {-1,FileError::io};source_handle=writable;writable=INVALID_HANDLE_VALUE;
            // The only namespace mutation. No unlink, attribute clearing, copy fallback, or write retry.
            IO_STATUS_BLOCK completion{};completion.Status=status_pending;
            const auto renamed=NtSetInformationFile(source_handle,&completion,rename,static_cast<ULONG>(bytes.size()),rename_information_ex);
            if(renamed==status_pending)return {-1,FileError::io}; // Synchronous handles must not leave an uncertain operation pending.
            if(renamed<0){
                const auto failure=RtlNtStatusToDosError(renamed);if(failure==ERROR_INVALID_FUNCTION || failure==ERROR_INVALID_PARAMETER || failure==ERROR_NOT_SUPPORTED)return {-1,FileError::unsupported};return {-1,error(failure)};
            }
            if(renamed!=0 || completion.Status!=0)return {-1,FileError::io}; // Fail closed; never replay an uncertain completion.
            for(std::size_t i=0;i<prepared->relocation_count;++i){
                const auto &row=prepared->relocations[i];auto &file=files[static_cast<std::size_t>(row.descriptor-3)];
                file.unlinked=row.unlinked;
                if(!row.unlinked){file.name.swap(held_names[static_cast<std::size_t>(row.descriptor-3)]);file.scope=row.scope;file.path_length=row.name_length;file.depth=1+static_cast<std::uint32_t>(std::count(file.name.begin(),file.name.end(),'/'));file.root_scope=FileAccessScope::files_leaf;}
            }
            const auto target_closed=close_once(target_handle),source_closed=close_once(source_handle);
            if(!target_closed || !source_closed)return {-1,FileError::io}; // Ambiguous acknowledgement is never replayed.
            output=*prepared;return {0,FileError::none};
        }catch(...){return {-1,FileError::io};}
    }
    ~Impl() {
        for (auto &file : files)
            if (file.handle != INVALID_HANDLE_VALUE)
                (void)file.release();
        if (root != INVALID_HANDLE_VALUE)
            CloseHandle(root);
        if(directory_security)LocalFree(directory_security);
    }
    File *find(int fd) noexcept {
        if (fd < 3 || fd - 3 >= static_cast<int>(files.size()))
            return nullptr;
        auto &file = files[static_cast<std::size_t>(fd - 3)];
        return file.handle == INVALID_HANDLE_VALUE ? nullptr : &file;
    }
};
HostFileService::HostFileService(const std::filesystem::path &root) : impl_(std::make_unique<Impl>()) {
    if (!root.is_absolute())
        throw std::runtime_error("Host file root must be an explicit absolute directory");
    impl_->root =
        CreateFileW(root.c_str(), READ_CONTROL | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    if (impl_->root == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(impl_->root, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("Cannot hold a non-reparse scoped directory");
    if(GetSecurityInfo(impl_->root,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        nullptr,nullptr,nullptr,nullptr,&impl_->directory_security)!=ERROR_SUCCESS ||
        !SetSecurityDescriptorControl(impl_->directory_security,SE_DACL_PROTECTED,SE_DACL_PROTECTED))
        throw std::runtime_error("Cannot capture private directory creation policy");
}
HostFileService::~HostFileService() = default;
FileResult HostFileService::private_root() noexcept {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(impl_->root, &info))
        return {-1, error(GetLastError())};
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return {-1, FileError::denied};
    return {0, FileError::none};
}
FileResult HostFileService::list_directory(std::vector<DirectoryEntry> &output) {
    std::vector<DirectoryEntry> entries;
    std::size_t encoded = 24; // Standard result, then entry count.
    alignas(FILE_ID_BOTH_DIR_INFO) std::array<std::uint8_t, 4096> buffer{};
    bool restart = true;
    for (;;) {
        if (!GetFileInformationByHandleEx(impl_->root,
                restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
                buffer.data(), static_cast<DWORD>(buffer.size()))) {
            const auto failure = GetLastError();
            if (failure != ERROR_NO_MORE_FILES) return {-1, error(failure)};
            output.swap(entries);
            return {static_cast<std::int64_t>(output.size()), FileError::none};
        }
        restart = false;
        std::size_t offset = 0;
        for (;;) {
            constexpr auto header = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
            if (offset > buffer.size() - header) return {-1, FileError::io};
            const auto *info = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO *>(buffer.data() + offset);
            const auto remaining = buffer.size() - offset;
            if (info->FileNameLength % sizeof(wchar_t) || info->FileNameLength > remaining - header)
                return {-1, FileError::io};
            const std::wstring_view wide(info->FileName, info->FileNameLength / sizeof(wchar_t));
            // '@' is the reserved backing namespace for app-data-root siblings,
            // not a member of the guest private-files directory.
            if (wide != L"." && wide != L".." && (wide.empty() || wide.front() != L'@')) {
                if (wide.empty()) return {-1, FileError::io};
                const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                    static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
                if (!count) return {-1, FileError::io};
                if (static_cast<std::size_t>(count) > directory_name_limit ||
                    entries.size() == directory_entry_limit ||
                    static_cast<std::size_t>(count) + 17 > directory_payload_limit - encoded)
                    return {-1, FileError::quota};
                DirectoryEntry entry{std::string(static_cast<std::size_t>(count), '\0'), 0,
                    static_cast<std::uint8_t>((info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 0 :
                        (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 4 : 8)};
                if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                        static_cast<int>(wide.size()), entry.name.data(), count, nullptr, nullptr) != count ||
                    !valid_directory_entry(entry)) return {-1, FileError::io};
                if (std::any_of(entries.begin(), entries.end(), [&](const auto &prior) { return prior.name == entry.name; }))
                    return {-1, FileError::io};
                const auto identity = impl_->opaque_identity(static_cast<std::uint64_t>(info->FileId.QuadPart));
                if (identity.error != FileError::none) return identity;
                entry.inode = static_cast<std::uint64_t>(identity.value);
                encoded += entry.name.size() + 17;
                entries.push_back(std::move(entry));
            }
            if (!info->NextEntryOffset) break;
            if (info->NextEntryOffset < header + info->FileNameLength ||
                info->NextEntryOffset > remaining || info->NextEntryOffset % alignof(FILE_ID_BOTH_DIR_INFO))
                return {-1, FileError::io};
            offset += info->NextEntryOffset;
        }
    }
}
FileResult HostFileService::open(std::string_view name, FileOpen options) {
    return open_scoped(FileAccessScope::files_leaf, name, options);
}
FileResult HostFileService::open_scoped(FileAccessScope scope,std::string_view name,FileOpen options) {return impl_->path(2,scope,name,-1,options);}
FileResult HostFileService::open_relative(int parent,std::string_view name,FileOpen options) {if(parent<0)return {-1,FileError::bad_descriptor};return impl_->path(2,FileAccessScope::files_leaf,name,parent,options);}
FileResult HostFileService::make_directory(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {return impl_->path(0,scope,name,-1,{},mode);}
FileResult HostFileService::make_directory_relative(int parent,std::string_view name,std::uint32_t mode) noexcept {if(parent<0)return {-1,FileError::bad_descriptor};return impl_->path(0,FileAccessScope::files_leaf,name,parent,{},mode);}
FileResult HostFileService::open_directory(FileAccessScope scope,std::string_view name) {return impl_->path(1,scope,name,-1);}
FileResult HostFileService::open_directory_relative(int parent,std::string_view name) {if(parent<0)return {-1,FileError::bad_descriptor};return impl_->path(1,FileAccessScope::files_leaf,name,parent);}
FileResult HostFileService::directory_valid(int descriptor) noexcept {
    const auto file=impl_->find(descriptor);if(!file)return {-1,FileError::bad_descriptor};
    if(!file->directory)return {-1,FileError::not_directory};if(file->unlinked)return {-1,FileError::missing};
    return impl_->check_directory(file->handle);
}
FileResult HostFileService::rename_path(const FilePathRef &source,const FilePathRef &destination,FileRenameInfo &output) noexcept {return impl_->rename_path(source,destination,output);}
FileResult HostFileService::observe_data_file(std::string_view name) {
    if (!safe_name(name)) return {-1, FileError::denied};
    // '@' cannot occur in the existing files/ name alphabet. This mapping is
    // injective and preserves all existing flat-file names without migration.
    const std::wstring mapped = L"@" + std::wstring(name.begin(), name.end());
    UNICODE_STRING relative{};
    relative.Length = static_cast<USHORT>(mapped.size() * sizeof(wchar_t));
    relative.MaximumLength = relative.Length;
    relative.Buffer = const_cast<wchar_t *>(mapped.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = impl_->root;
    attributes.ObjectName = &relative;
    IO_STATUS_BLOCK io{};
    HANDLE raw = INVALID_HANDLE_VALUE;
    constexpr ULONG synchronous_nonalert = 0x20, non_directory = 0x40, open_reparse = 0x00200000;
    const auto status = NtCreateFile(&raw, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, 1u,
        synchronous_nonalert | non_directory | open_reparse, nullptr, 0);
    if (status < 0) return {-1, error(RtlNtStatusToDosError(status))};
    struct Close { HANDLE value; ~Close() { CloseHandle(value); } } close{raw};
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (GetFileType(raw) != FILE_TYPE_DISK || !GetFileInformationByHandle(raw, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        info.nNumberOfLinks != 1 || !GetFileSizeEx(raw, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum_file) return {-1, FileError::denied};
    return {1, FileError::none};
}
FileResult HostFileService::read(int descriptor, std::span<std::uint8_t> output) noexcept {
    const auto file = impl_->find(descriptor);
    if(file && file->directory)return {-1,FileError::is_directory};
    if (!file || !file->read)
        return {-1, FileError::bad_descriptor};
    if (output.size() > maximum_file)
        return {-1, FileError::invalid};
    DWORD count = 0;
    if (!ReadFile(file->handle, output.data(), static_cast<DWORD>(output.size()), &count, nullptr))
        return {-1, error(GetLastError())};
    return {count, FileError::none};
}
FileResult HostFileService::write(int descriptor, std::span<const std::uint8_t> input) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file || !file->write)
        return {-1, FileError::bad_descriptor};
    LARGE_INTEGER zero{}, position{};
    if (!SetFilePointerEx(file->handle, zero, &position, FILE_CURRENT))
        return {-1, error(GetLastError())};
    if (position.QuadPart < 0 || static_cast<std::uint64_t>(position.QuadPart) > maximum_file ||
        input.size() > maximum_file - static_cast<std::uint64_t>(position.QuadPart))
        return {-1, FileError::quota};
    DWORD count = 0;
    // One write attempt only; short writes are returned to the guest.
    if (!WriteFile(file->handle, input.data(), static_cast<DWORD>(input.size()), &count, nullptr))
        return {-1, error(GetLastError())};
    return {count, FileError::none};
}
FileResult HostFileService::metadata(int descriptor, FileMetadata &output) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file) return {-1, FileError::bad_descriptor};
    if(file->directory)return {-1,FileError::unsupported};
    FILE_BASIC_INFO basic{};
    FILE_STANDARD_INFO standard{};
    if (GetFileType(file->handle) != FILE_TYPE_DISK) return {-1, FileError::denied};
    if (!GetFileInformationByHandleEx(file->handle, FileBasicInfo, &basic, sizeof(basic)) ||
        !GetFileInformationByHandleEx(file->handle, FileStandardInfo, &standard, sizeof(standard)))
        return {-1, error(GetLastError())};
    if ((basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        standard.Directory || standard.NumberOfLinks != (file->unlinked ? 0U : 1U) || standard.EndOfFile.QuadPart < 0 ||
        standard.AllocationSize.QuadPart < 0 ||
        static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) > maximum_file)
        return {-1, FileError::denied};
    FileMetadata value;
    value.size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    value.allocated_bytes = static_cast<std::uint64_t>(standard.AllocationSize.QuadPart);
    value.links = standard.NumberOfLinks;
    value.readonly = (basic.FileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
    const auto convert = [](LARGE_INTEGER ticks, std::int64_t &seconds, std::uint32_t &nanoseconds) {
        if (ticks.QuadPart < 0) return false;
        constexpr std::int64_t epoch = 116444736000000000, frequency = 10'000'000;
        const auto delta = ticks.QuadPart - epoch;
        seconds = delta / frequency;
        auto fraction = delta % frequency;
        if (fraction < 0) { --seconds; fraction += frequency; }
        nanoseconds = static_cast<std::uint32_t>(fraction * 100);
        return true;
    };
    if (!convert(basic.LastAccessTime, value.access_seconds, value.access_nanoseconds) ||
        !convert(basic.LastWriteTime, value.modified_seconds, value.modified_nanoseconds) ||
        !convert(basic.ChangeTime, value.changed_seconds, value.changed_nanoseconds))
        return {-1, FileError::io};
    BY_HANDLE_FILE_INFORMATION identity{};
    if (!GetFileInformationByHandle(file->handle, &identity)) return {-1, error(GetLastError())};
    const auto index = (static_cast<std::uint64_t>(identity.nFileIndexHigh) << 32) | identity.nFileIndexLow;
    const auto identified = impl_->opaque_identity(index);
    if (identified.error != FileError::none) return identified;
    value.identity = static_cast<std::uint64_t>(identified.value);
    output = value;
    return {0, FileError::none};
}
FileResult HostFileService::remove(FileAccessScope scope,std::string_view name,FileRemoveMode mode,bool directory_required) noexcept {
    if(!valid_file_remove(scope,name,mode))return {-1,FileError::denied};
    return impl_->path(4,scope,name,-1,{},0,mode,directory_required);
}
FileResult HostFileService::remove_relative(int parent,std::string_view name,FileRemoveMode mode,bool directory_required) noexcept {if(parent<0)return {-1,FileError::bad_descriptor};
    if(!valid_file_path(name))return {-1,FileError::invalid};return impl_->path(4,FileAccessScope::files_leaf,name,parent,{},0,mode,directory_required);
}
FileResult HostFileService::seek(int descriptor, std::int64_t offset, unsigned whence) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file) return {-1, FileError::bad_descriptor};
    if(file->directory)return {-1,FileError::is_directory};
    if (whence > 2) return {-1, FileError::invalid};
    LARGE_INTEGER base{};
    if (whence == 1) {
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(file->handle, zero, &base, FILE_CURRENT)) return {-1, error(GetLastError())};
    } else if (whence == 2 && !GetFileSizeEx(file->handle, &base)) return {-1, error(GetLastError())};
    if (base.QuadPart < 0 || (offset >= 0 && base.QuadPart > std::numeric_limits<std::int64_t>::max() - offset) ||
        (offset < 0 && offset < -base.QuadPart)) return {-1, FileError::invalid};
    LARGE_INTEGER target{};
    target.QuadPart = base.QuadPart + offset;
    // Keep all permitted reads/writes below the reserved advisory-lock region.
    // Seeking beyond EOF is supported inside the existing 1 MiB private-file profile.
    if (static_cast<std::uint64_t>(target.QuadPart) > maximum_file) return {-1, FileError::quota};
    return SetFilePointerEx(file->handle, target, nullptr, FILE_BEGIN)
               ? FileResult{target.QuadPart, FileError::none} : FileResult{-1, error(GetLastError())};
}
FileResult HostFileService::flush(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file || !file->write)
        return {-1, FileError::bad_descriptor};
    // One attempt only. A failure is never retried or reported as durable.
    return FlushFileBuffers(file->handle) ? FileResult{0, FileError::none}
                                        : FileResult{-1, error(GetLastError())};
}
FileResult HostFileService::close(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, FileError::bad_descriptor};
    return file->release();
}
FileResult HostFileService::access(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {if(!valid_file_access(scope,name,mode))return {-1,FileError::invalid};return impl_->path(3,scope,name,-1,{},mode);}
FileResult HostFileService::access_relative(int parent,std::string_view name,std::uint32_t mode) noexcept {if(parent<0)return {-1,FileError::bad_descriptor};return impl_->path(3,FileAccessScope::files_leaf,name,parent,{},mode);}
FileResult HostFileService::access_path(FileAccessScope scope,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {if(!valid_file_access(scope,name,mode))return {-1,FileError::invalid};return impl_->path(3,scope,name,-1,{},mode,FileRemoveMode::file,directory_required);}
FileResult HostFileService::access_relative_path(int parent,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {if(parent<0)return {-1,FileError::bad_descriptor};return impl_->path(3,FileAccessScope::files_leaf,name,parent,{},mode,FileRemoveMode::file,directory_required);}
FileResult HostFileService::lock(int descriptor,std::uint32_t operation) noexcept {
    const auto file=impl_->find(descriptor);if(!file)return {-1,FileError::bad_descriptor};
    if(file->directory)return {-1,FileError::unsupported};
    if(!valid_file_lock(operation))return {-1,FileError::invalid};
    const auto mode=operation&~4U;
    if(mode==file->lock_mode || (mode==8 && !file->lock_mode))return {0,FileError::none};
    // One reserved byte beyond every permitted data/read-request span. Windows enforces conflict
    // across independently opened handles without making guest data I/O mandatory-locking.
    OVERLAPPED region{};region.Offset=advisory_lock_offset;
    if(file->lock_mode) {
        if(!UnlockFileEx(file->handle,0,1,0,&region))return {-1,error(GetLastError())};
        file->lock_mode=0;
    }
    if(mode==8)return {0,FileError::none};
    const DWORD flags=LOCKFILE_FAIL_IMMEDIATELY|(mode==2?LOCKFILE_EXCLUSIVE_LOCK:0);
    if(!LockFileEx(file->handle,flags,0,1,0,&region)) {
        const auto failure=GetLastError();
        if(failure==ERROR_LOCK_VIOLATION)return {-1,(operation&4)?FileError::would_block:FileError::unsupported};
        return {-1,error(failure)};
    }
    file->lock_mode=mode;return {0,FileError::none};
}

} // namespace aether::host
