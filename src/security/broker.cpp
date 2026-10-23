#include "local_calendar.hpp"
#include "file_transport.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/worker.hpp"
#include "aether/apk/inspect.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <climits>
#include <exception>

namespace aether::security {
namespace {
std::atomic<std::uint64_t> next_descriptor{1};
Status file_status(host::FileError error) {
    switch (error) {
    case host::FileError::none:
        return Status::ok;
    case host::FileError::denied:
        return Status::denied;
    case host::FileError::unsupported:
        return Status::unsupported;
    case host::FileError::descriptor_limit:
    case host::FileError::quota:
        return Status::quota;
    default:
        return Status::invalid;
    }
}
constexpr std::size_t file_transfer_limit = maximum_payload - 16;
std::string package_hash(const std::vector<std::uint8_t> &bytes) {
    return bytes.empty() ? std::string{} : apk::sha256(bytes);
}
} // namespace
struct Broker::FilePathLedger {
    using Map=std::map<std::uint64_t,file_transport::Position>;
    Map positions;
};
Broker::Broker(BrokerPolicy policy, std::shared_ptr<AuditTrail> journal,
               std::unique_ptr<host::FileService> files, std::vector<std::uint8_t> package,
               std::unique_ptr<host::AudioService> audio, bool retain_fixture_pcm,
               std::unique_ptr<GraphicsService> graphics)
    : policy_(policy), journal_(std::move(journal)), files_(std::move(files)), file_paths_(std::make_unique<FilePathLedger>()), package_(std::move(package)),
      package_hash_(package_hash(package_)),
      audio_(policy.audio_playback, std::move(audio), retain_fixture_pcm), graphics_(std::move(graphics)) {
    if (!policy_.app_id || !policy_.session || !policy_.request_limit || policy_.request_limit > 256)
        throw ProtocolError("AETHER_BROKER_POLICY: invalid identity or quota");
    if (policy_.private_storage && !files_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing storage");
    if (policy_.graphics && !graphics_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing graphics provider");
    if (!journal_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing mandatory audit trail");
    journal_->configure(policy.app_id, policy.session,
                        (policy.monotonic_time ? 1u : 0u) | (policy.private_storage ? 2u : 0u) |
                            (policy.interactive ? 4u : 0u) | (policy.audio_playback ? 8u : 0u) |
                            (policy.graphics ? 16u : 0u) | (policy.wall_time ? 32u : 0u));
    audit_.reserve(policy_.request_limit + 1);
}
Broker::~Broker() { revoke_all(); }
void Broker::bind_worker_thread(const WorkerProcess &worker) {
    if (closed_ || total_requests_ || next_sequence_ != 1)
        throw ProtocolError("AETHER_BROKER_TIME: worker thread binding after requests refused");
    const auto ticks=worker.start_uptime_ticks();
    time_.bind_thread(worker.primary_thread(), worker.process_id(),
                      host::MonotonicTime{ticks/10'000'000,(ticks%10'000'000)*100});
}
void Broker::close() noexcept {
    closed_ = true;
    revoke_all();
}
void Broker::revoke_all() noexcept {
    time_.unbind_thread();
    revoke_storage();
    revoke_audio();
    revoke_graphics();
}
void Broker::revoke_graphics() noexcept {
    policy_.graphics = false;
    if (graphics_)
        graphics_->revoke();
}
void Broker::begin_turn() {
    if (!policy_.interactive || closed_ || executing_ || idle_dispatch_)
        throw ProtocolError("AETHER_BROKER_TURN: session does not accept interactive turns");
    turn_requests_ = 0;
}
void Broker::revoke_storage() noexcept {
    policy_.private_storage = false;
    for (const auto &[token, descriptor] : descriptors_) {
        (void)token;
        (void)files_->close(descriptor);
    }
    descriptors_.clear();
    file_paths_->positions.clear();
}
host::FileResult Broker::file_request(const Frame &request, Frame &response) {
    using host::FileError;
    using host::FileResult;
    auto &file_paths=file_paths_->positions;
    if (!policy_.private_storage || !files_)
        return {-1, FileError::denied};
    if(request.header.operation==Operation::file_rename){
        namespace ft=file_transport;
        struct Endpoint {host::FilePathRef ref;std::string name;ft::Position position;};
        std::size_t offset=0;Endpoint source,destination;
        const auto endpoint=[&](Endpoint &out)->FileError {
            if(offset>request.payload.size() || request.payload.size()-offset<32)return FileError::invalid;
            const auto kind=read_u64(request.payload,offset),base=read_u64(request.payload,offset+8),required=read_u64(request.payload,offset+16);offset+=24;
            if(kind>1 || required>1)return FileError::invalid;
            out.name=read_text(request.payload,offset,host::private_path_limit);out.ref.name=out.name;out.ref.directory_required=required!=0;
            if(!host::valid_file_path(out.name))return FileError::invalid;
            std::optional<ft::Position> position;
            if(kind){
                const auto owned=descriptors_.find(base);if(owned==descriptors_.end())return FileError::bad_descriptor;
                const auto held=file_paths.find(base);if(held==file_paths.end() || !held->second.directory)return FileError::not_directory;
                if(held->second.unlinked)return FileError::missing;
                out.ref.directory=owned->second;position=ft::position(host::FileAccessScope::files_leaf,out.name,&held->second);
            }else{
                if(base<2 || base>3)return FileError::invalid;
                out.ref.scope=static_cast<host::FileAccessScope>(base);position=ft::position(out.ref.scope,out.name);
            }
            if(!position || position->name.empty())return FileError::invalid;
            out.position=std::move(*position);return FileError::none;
        };
        if(const auto error=endpoint(source);error!=FileError::none)return {-1,error};
        if(const auto error=endpoint(destination);error!=FileError::none)return {-1,error};
        if(offset!=request.payload.size())return {-1,FileError::invalid};
        std::array<std::optional<ft::Candidate>,ft::descriptor_limit> candidates;
        std::array<FilePathLedger::Map::iterator,ft::descriptor_limit> positions;
        std::size_t count=0;
        for(auto it=file_paths.begin();it!=file_paths.end();++it){
            if(count==positions.size())throw std::runtime_error("AETHER_BROKER_RENAME: ancestry ledger exceeds descriptor bound");
            positions[count]=it;candidates[count]=ft::candidate(it->second,source.position,destination.position);++count;
        }
        // Both serialization buffers and every possible ancestry string exist
        // before the sole provider invocation. Audit intent already persisted.
        response.payload.reserve(ft::rename_reply_bytes-16);
        host::FileRenameInfo info;
        const auto result=files_->rename_path(source.ref,destination.ref,info);
        if(static_cast<unsigned>(result.error)>static_cast<unsigned>(FileError::not_empty) ||
            (result.error==FileError::none?result.value!=0:result.value!=-1))
            throw std::runtime_error("AETHER_BROKER_RENAME: malformed provider result after invocation");
        if(result.error!=FileError::none){
            if(!ft::untouched(info))
                throw std::runtime_error("AETHER_BROKER_RENAME: failure changed relocation output");
            if(result.error==FileError::io)throw std::runtime_error("AETHER_BROKER_RENAME: uncertain provider failure, authority revoked");
            return result;
        }
        if(!ft::valid_info(info,source.position,destination.position))throw std::runtime_error("AETHER_BROKER_RENAME: malformed provider identity result");
        std::array<bool,ft::descriptor_limit> seen{};
        std::array<std::size_t,ft::descriptor_limit> rows{};
        for(unsigned row=0;row<info.relocation_count;++row){
            const auto &value=info.relocations[row];std::size_t index=0;
            for(;index<count;++index){const auto fd=descriptors_.find(positions[index]->first);if(fd!=descriptors_.end() && fd->second==value.descriptor)break;}
            if(index==count || seen[index] || !candidates[index] ||
                !ft::expected(*candidates[index],positions[index]->second,source.position,info) ||
                !ft::valid_row(positions[index]->second,*candidates[index],source.position,info,value.identity,value.directory,value.unlinked))
                throw std::runtime_error("AETHER_BROKER_RENAME: foreign duplicate or inconsistent relocation");
            auto &prepared=candidates[index]->position;
            if(value.scope!=ft::scope(prepared) || value.name_length!=prepared.name.size() ||
                value.name_length>=value.name.size() || value.name[value.name_length]!=0 ||
                !std::equal(prepared.name.begin(),prepared.name.end(),value.name.begin()))
                throw std::runtime_error("AETHER_BROKER_RENAME: provider ancestry disagrees with prepared relocation");
            prepared.identity=value.identity;seen[index]=true;rows[row]=index;
        }
        for(std::size_t i=0;i<count;++i)if(candidates[i] && ft::expected(*candidates[i],positions[i]->second,source.position,info)!=seen[i])
            throw std::runtime_error("AETHER_BROKER_RENAME: missing affected descriptor relocation");
        append_u64(response.payload,info.source_identity);append_u64(response.payload,info.replaced_identity);
        append_u64(response.payload,(info.directory?1u:0u)|(info.unchanged?2u:0u));append_u64(response.payload,info.relocation_count);
        for(unsigned row=0;row<info.relocation_count;++row){
            const auto index=rows[row];const auto &position=candidates[index]->position;
            append_u64(response.payload,positions[index]->first);append_u64(response.payload,position.identity);
            append_u64(response.payload,static_cast<unsigned>(ft::scope(position)));
            append_u64(response.payload,(position.directory?1u:0u)|(position.unlinked?2u:0u));
            append_u64(response.payload,position.depth);append_u64(response.payload,position.length);
        }
        for(std::size_t i=0;i<count;++i)if(seen[i])std::swap(positions[i]->second,candidates[i]->position);
        return result;
    }
    if(request.header.operation==Operation::file_path){
        if(request.payload.size()<48)return {-1,FileError::invalid};
        const auto action=read_u64(request.payload,0),kind=read_u64(request.payload,8),base=read_u64(request.payload,16),options=read_u64(request.payload,24),required=read_u64(request.payload,32);
        if(action>5 || kind>1 || required>1 || (required && action!=3 && action!=4))return {-1,FileError::invalid};
        std::size_t offset=40;auto name=read_text(request.payload,offset,host::private_path_limit);
        if(offset!=request.payload.size())return {-1,FileError::invalid};
        if((action==0 && options!=0700) || ((action==1 || action==5) && options) ||
            (action==2 && (options>31 || !(options&3) || ((options&8) && !(options&4)) || ((options&16) && !(options&2)))) ||
            (action==3 && options>7) || (action==4 && options>2))return {-1,action==0?FileError::unsupported:FileError::invalid};
        int parent=-1;auto scope=host::FileAccessScope::files_leaf;file_transport::Position position;
        if(kind==0){
            if(base>3 || action==5)return {-1,FileError::invalid};scope=static_cast<host::FileAccessScope>(base);
            if(!host::valid_file_access(scope,name,0) || ((action==2 || action==4) && (base<2)))return {-1,FileError::invalid};
            const auto prepared=file_transport::position(scope,name);if(!prepared)return {-1,FileError::invalid};position=*prepared;
        }else{
            const auto found=descriptors_.find(base);if(found==descriptors_.end())return {-1,FileError::bad_descriptor};
            const auto directory=file_paths.find(base);if(directory==file_paths.end() || !directory->second.directory)return {-1,FileError::not_directory};
            if(directory->second.unlinked)return {-1,FileError::missing};parent=found->second;
            if(!host::valid_file_path(name,action!=2 && action!=4) || (action==5 && !name.empty()))return {-1,FileError::invalid};
            const auto prepared=file_transport::position(scope,name,&directory->second);if(!prepared)return {-1,FileError::invalid};position=*prepared;
        }
        const bool opening=action==1 || action==2;std::uint64_t token=0;
        if(opening){
            if(descriptors_.size()>=16)return {-1,FileError::descriptor_limit};
            const auto identity=next_descriptor.fetch_add(1);if(!identity || identity>UINT32_MAX)return {-1,FileError::quota};
            token=0x2ee3000000000000ULL|identity;
            if(!descriptors_.emplace(token,-1).second)throw std::runtime_error("AETHER_BROKER_STORAGE: directory token collision");
            position.directory=action==1;
            try{file_paths.emplace(token,std::move(position));}catch(...){descriptors_.erase(token);throw;}
        }
        FileResult result;
        try{
            if(action==0)result=kind?files_->make_directory_relative(parent,name,static_cast<std::uint32_t>(options)):files_->make_directory(scope,name,static_cast<std::uint32_t>(options));
            else if(action==1)result=kind?files_->open_directory_relative(parent,name):files_->open_directory(scope,name);
            else if(action==2){const host::FileOpen flags{(options&1)!=0,(options&2)!=0,(options&4)!=0,(options&8)!=0,(options&16)!=0};result=kind?files_->open_relative(parent,name,flags):files_->open_scoped(scope,name,flags);}
            else if(action==3)result=kind?files_->access_relative_path(parent,name,static_cast<std::uint32_t>(options),required!=0):files_->access_path(scope,name,static_cast<std::uint32_t>(options),required!=0);
            else if(action==4)result=kind?files_->remove_relative(parent,name,static_cast<host::FileRemoveMode>(options),required!=0):files_->remove(scope,name,static_cast<host::FileRemoveMode>(options),required!=0);
            else result=files_->directory_valid(parent);
        }catch(...){if(opening){descriptors_.erase(token);file_paths.erase(token);}throw std::runtime_error("AETHER_BROKER_STORAGE: path provider failed after invocation");}
        const bool success=result.error==FileError::none;
        const bool invalid=static_cast<unsigned>(result.error)>static_cast<unsigned>(FileError::not_empty) ||
            (!success && result.value!=-1) || (success && (opening?(result.value<0 || result.value>INT_MAX):action==4?(result.value<=0 || result.value>4096):result.value!=0));
        bool duplicate=false;if(success && opening)for(const auto &[owned,fd]:descriptors_)if(owned!=token && fd==result.value)duplicate=true;
        if(invalid || duplicate){if(opening){descriptors_.erase(token);file_paths.erase(token);if(!duplicate && result.value>=0 && result.value<=INT_MAX)(void)files_->close(static_cast<int>(result.value));}throw std::runtime_error("AETHER_BROKER_STORAGE: invalid path provider result");}
        if(opening){if(!success){descriptors_.erase(token);file_paths.erase(token);return result;}descriptors_.find(token)->second=static_cast<int>(result.value);return {static_cast<std::int64_t>(token),FileError::none};}
        if(success && action==4)for(auto &[owned,held]:file_paths){(void)owned;file_transport::removed(held,position,static_cast<std::uint64_t>(result.value));}
        return result;
    }
    if (request.header.operation == Operation::file_remove) {
        if (request.payload.size() < 33 || read_u64(request.payload, 0) > 3 ||
            read_u64(request.payload, 8) > 2 || read_u64(request.payload, 16) > 1)
            return {-1, FileError::invalid};
        const auto scope = static_cast<host::FileAccessScope>(read_u64(request.payload, 0));
        const auto mode = static_cast<host::FileRemoveMode>(read_u64(request.payload, 8));
        std::size_t offset = 24; const auto name = read_text(request.payload, offset, host::private_path_limit);
        if (offset != request.payload.size() || !host::valid_file_remove(scope, name, mode)) return {-1, FileError::invalid};
        const auto position=file_transport::position(scope,name);
        const auto result = files_->remove(scope, name, mode, read_u64(request.payload, 16) != 0);
        if (static_cast<unsigned>(result.error) > static_cast<unsigned>(FileError::not_empty) ||
            (result.error == FileError::none && (result.value <= 0 || result.value > 4096)) ||
            (result.error != FileError::none && result.value != -1))
            throw std::runtime_error("AETHER_BROKER_STORAGE: invalid removal result after mutation");
        if(result.error==FileError::none)for(auto &[owned,held]:file_paths){(void)owned;file_transport::removed(held,*position,static_cast<std::uint64_t>(result.value));}
        return result;
    }
    if(request.header.operation==Operation::file_access) {
        if(request.payload.size()<24 || read_u64(request.payload,0)>3 || read_u64(request.payload,8)>7)return {-1,FileError::invalid};
        const auto scope=static_cast<host::FileAccessScope>(read_u64(request.payload,0));const auto mode=static_cast<std::uint32_t>(read_u64(request.payload,8));std::size_t offset=16;const auto name=read_text(request.payload,offset,host::private_path_limit);
        if(offset!=request.payload.size() || !host::valid_file_access(scope,name,mode))return {-1,FileError::invalid};
        const auto result=files_->access(scope,name,mode);
        if((result.error==FileError::none && result.value!=0) || (result.error!=FileError::none && result.value!=-1))throw ProtocolError("AETHER_BROKER_STORAGE: invalid access result");return result;
    }
    if (request.header.operation == Operation::file_directory) {
        if (!request.payload.empty()) return {-1, FileError::invalid};
        std::vector<host::DirectoryEntry> entries;
        const auto result = files_->list_directory(entries);
        if (result.error != FileError::none) {
            if (result.value != -1 || !entries.empty())
                throw ProtocolError("AETHER_BROKER_DIRECTORY: invalid provider failure");
            return result;
        }
        if (result.value != static_cast<std::int64_t>(entries.size()))
            throw ProtocolError("AETHER_BROKER_DIRECTORY: inconsistent provider count");
        if (entries.size() > host::directory_entry_limit) return {-1, FileError::quota};
        std::vector<std::uint8_t> payload;
        append_u64(payload, entries.size());
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto &entry = entries[i];
            if (!host::valid_directory_entry(entry))
                throw ProtocolError("AETHER_BROKER_DIRECTORY: invalid provider entry");
            for (std::size_t prior = 0; prior < i; ++prior)
                if (entries[prior].name == entry.name)
                    throw ProtocolError("AETHER_BROKER_DIRECTORY: duplicate provider entry");
            if (payload.size() > host::directory_payload_limit - 16 ||
                entry.name.size() + 17 > host::directory_payload_limit - 16 - payload.size())
                return {-1, FileError::quota};
            append_u64(payload, entry.inode);
            payload.push_back(entry.type);
            append_text(payload, entry.name);
        }
        response.payload.swap(payload);
        return result;
    }
    if (request.header.operation == Operation::file_data_observe) {
        if (request.payload.size() < 9) return {-1, FileError::invalid};
        std::size_t offset = 0;
        const auto name = read_text(request.payload, offset, 127);
        if (offset != request.payload.size()) return {-1, FileError::invalid};
        const auto result = files_->observe_data_file(name);
        if ((result.error == FileError::none && result.value != 1) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: invalid app-data file observation result");
        return result;
    }
    if (request.header.operation == Operation::file_root) {
        if (!request.payload.empty())
            return {-1, FileError::invalid};
        const auto result = files_->private_root();
        if ((result.error == FileError::none && result.value != 0) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: provider returned an invalid root result");
        return result;
    }
    if (request.header.operation == Operation::file_open_scoped) {
        if (request.payload.size() < 25 || read_u64(request.payload, 0) > 3) return {-1, FileError::invalid};
        const auto scope = static_cast<host::FileAccessScope>(read_u64(request.payload, 0));
        const auto flags = read_u64(request.payload, 8);
        std::size_t offset = 16; const auto name = read_text(request.payload, offset, host::private_path_limit);
        if (offset != request.payload.size() ||
            (scope != host::FileAccessScope::files_leaf && scope != host::FileAccessScope::data_leaf) ||
            !host::valid_file_access(scope, name, 0) || flags > 31 || !(flags & 3) ||
            ((flags & 8) && !(flags & 4)) || ((flags & 16) && !(flags & 2)))
            return {-1, FileError::invalid};
        if (descriptors_.size() >= 16) return {-1, FileError::descriptor_limit};
        const auto identity = next_descriptor.fetch_add(1);
        if (!identity || identity > UINT32_MAX) return {-1, FileError::quota};
        const auto token = 0x2ee3000000000000ULL | identity;
        // Reserve publication before create/truncate. Successful publication cannot allocate.
        const auto inserted = descriptors_.emplace(token, -1);
        if (!inserted.second) throw std::runtime_error("AETHER_BROKER_STORAGE: scoped token collision");
        try{file_paths.emplace(token,*file_transport::position(scope,name));}catch(...){descriptors_.erase(inserted.first);throw;}
        host::FileResult result;
        try {
            result = files_->open_scoped(scope, name, {(flags & 1) != 0, (flags & 2) != 0, (flags & 4) != 0,
                                                       (flags & 8) != 0, (flags & 16) != 0});
        } catch (...) {
            descriptors_.erase(inserted.first);
            file_paths.erase(token);
            throw std::runtime_error("AETHER_BROKER_STORAGE: scoped open provider failed after invocation");
        }
        if (static_cast<unsigned>(result.error) > static_cast<unsigned>(FileError::not_empty) ||
            (result.error == FileError::none && (result.value < 0 || result.value > INT_MAX)) ||
            (result.error != FileError::none && result.value != -1)) {
            descriptors_.erase(inserted.first);
            file_paths.erase(token);
            throw std::runtime_error("AETHER_BROKER_STORAGE: invalid scoped open provider result");
        }
        if (result.error != FileError::none) {descriptors_.erase(inserted.first);file_paths.erase(token); return result;}
        inserted.first->second = static_cast<int>(result.value);
        return {static_cast<std::int64_t>(token), FileError::none};
    }
    if (request.header.operation == Operation::file_open) {
        if (request.payload.size() < 17)
            return {-1, FileError::invalid};
        const auto flags = read_u64(request.payload, 0);
        std::size_t offset = 8;
        const auto name = read_text(request.payload, offset, 127);
        if (offset != request.payload.size() || name.find('/')!=std::string::npos || !host::valid_file_path(name) || flags > 31 || !(flags & 3) || ((flags & 8) && !(flags & 4)) ||
            ((flags & 16) && !(flags & 2)))
            return {-1, FileError::invalid};
        if (descriptors_.size() >= 16)
            return {-1, FileError::descriptor_limit};
        const auto identity = next_descriptor.fetch_add(1);
        if (!identity || identity > UINT32_MAX)
            return {-1, FileError::quota};
        const auto token = 0x2ee3000000000000ULL | identity;
        descriptors_.emplace(token,-1);
        try {
            file_paths.emplace(token,*file_transport::position(host::FileAccessScope::files_leaf,name));
        } catch (...) {
            descriptors_.erase(token);throw;
        }
        host::FileResult result;
        try{result=files_->open(name, {(flags & 1) != 0, (flags & 2) != 0, (flags & 4) != 0,
                                                (flags & 8) != 0, (flags & 16) != 0});}
        catch(...){descriptors_.erase(token);file_paths.erase(token);throw;}
        if (result.error != FileError::none){descriptors_.erase(token);file_paths.erase(token);return result;}
        descriptors_.find(token)->second=static_cast<int>(result.value);
        return {static_cast<std::int64_t>(token), FileError::none};
    }
    if (request.payload.size() < 8)
        return {-1, FileError::invalid};
    const auto token = read_u64(request.payload, 0);
    const auto found = descriptors_.find(token);
    if (found == descriptors_.end())
        return {-1, FileError::bad_descriptor};
    const auto descriptor = found->second;
    if (request.header.operation == Operation::file_metadata) {
        if (request.payload.size() != 8) return {-1, FileError::invalid};
        host::FileMetadata value;
        const auto result = files_->metadata(descriptor, value);
        if ((result.error == FileError::none && (result.value != 0 || !host::valid_file_metadata(value))) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: invalid metadata result");
        if (result.error == FileError::none) {
            if(const auto held=file_paths.find(token);held!=file_paths.end()){held->second.identity=value.identity;held->second.unlinked=value.links==0;}
            append_u64(response.payload, value.size);
            append_u64(response.payload, value.identity);
            append_u64(response.payload, value.allocated_bytes);
            append_u64(response.payload, value.readonly ? 1 : 0);
            append_u64(response.payload, std::bit_cast<std::uint64_t>(value.access_seconds));
            append_u64(response.payload, value.access_nanoseconds);
            append_u64(response.payload, std::bit_cast<std::uint64_t>(value.modified_seconds));
            append_u64(response.payload, value.modified_nanoseconds);
            append_u64(response.payload, std::bit_cast<std::uint64_t>(value.changed_seconds));
            append_u64(response.payload, value.changed_nanoseconds);
            append_u64(response.payload, value.links);
        }
        return result;
    }
    if (request.header.operation == Operation::file_seek) {
        if (request.payload.size() != 24 || read_u64(request.payload, 16) > 2) return {-1, FileError::invalid};
        const auto result = files_->seek(descriptor, std::bit_cast<std::int64_t>(read_u64(request.payload, 8)),
                                        static_cast<unsigned>(read_u64(request.payload, 16)));
        if ((result.error == FileError::none && (result.value < 0 || static_cast<std::uint64_t>(result.value) > host::private_file_size_limit)) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: invalid seek result");
        return result;
    }
    if(request.header.operation==Operation::file_lock) {
        if(request.payload.size()!=16 || read_u64(request.payload,8)>UINT32_MAX || !host::valid_file_lock(static_cast<std::uint32_t>(read_u64(request.payload,8))))return {-1,FileError::invalid};
        const auto result=files_->lock(descriptor,static_cast<std::uint32_t>(read_u64(request.payload,8)));
        if((result.error==FileError::none && result.value!=0) || (result.error!=FileError::none && result.value!=-1))throw ProtocolError("AETHER_BROKER_STORAGE: invalid lock result");
        return result;
    }
    if (request.header.operation == Operation::file_flush) {
        if (request.payload.size() != 8)
            return {-1, FileError::invalid};
        const auto result = files_->flush(descriptor);
        if ((result.error == FileError::none && result.value != 0) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: provider returned an invalid flush result");
        return result;
    }
    if (request.header.operation == Operation::file_close) {
        if (request.payload.size() != 8)
            return {-1, FileError::invalid};
        file_paths.erase(found->first);
        descriptors_.erase(found); // Never reuse or replay a close, even on Windows failure.
        return files_->close(descriptor);
    }
    if (request.header.operation == Operation::file_write) {
        const auto input = std::span(request.payload).subspan(8);
        if (input.size() > file_transfer_limit)
            return {-1, FileError::invalid};
        return files_->write(descriptor, input); // Exactly one write attempt.
    }
    if (request.payload.size() != 16 || read_u64(request.payload, 8) > file_transfer_limit)
        return {-1, FileError::invalid};
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(read_u64(request.payload, 8)));
    const auto result = files_->read(descriptor, bytes);
    if (result.error == FileError::none) {
        if (result.value < 0 || static_cast<std::uint64_t>(result.value) > bytes.size())
            throw ProtocolError("AETHER_BROKER_STORAGE: provider returned an invalid byte count");
        bytes.resize(static_cast<std::size_t>(result.value));
        response.payload = std::move(bytes);
    }
    return result;
}
Frame Broker::dispatch_idle(const Frame &request) {
    if (!policy_.interactive || closed_ || executing_ || idle_dispatch_) {
        close();
        throw ProtocolError("AETHER_BROKER_IDLE: idle dispatch requires an open interactive session without reentry");
    }
    idle_dispatch_ = true;
    struct Reset { bool &flag; ~Reset() { flag = false; } } reset{idle_dispatch_};
    return dispatch(request);
}
Frame Broker::dispatch(const Frame &request) {
    if (executing_) {
        close();
        throw ProtocolError("AETHER_BROKER_REENTRY: broker dispatch is already executing");
    }
    if (closed_)
        throw ProtocolError("AETHER_BROKER_CLOSED: session already terminated");
    try {
        const auto ticket = journal_->begin(request);
        Frame response;
        std::exception_ptr failure;
        try {
            response = dispatch_prepared(request, ticket);
        } catch (...) {
            failure = std::current_exception();
        }
        journal_->complete(ticket); // A result is never returned before its durable outcome.
        if (failure)
            std::rethrow_exception(failure);
        return response;
    } catch (...) {
        close();
        throw;
    }
}
Frame Broker::dispatch_prepared(const Frame &request, AuditTicket ticket) {
    if (executing_) {
        close();
        throw ProtocolError("AETHER_BROKER_REENTRY: broker dispatch is already executing");
    }
    executing_ = true;
    struct Reset { bool &flag; ~Reset() { flag = false; } } reset{executing_};
    try {
        if (closed_)
            throw ProtocolError("AETHER_BROKER_CLOSED: session already terminated");
        journal_->claim(ticket, request);
        return execute(request, ticket);
    } catch (...) {
        close();
        throw;
    }
}
Frame Broker::execute(const Frame &request, AuditTicket ticket) {
    if (closed_)
        throw ProtocolError("AETHER_BROKER_CLOSED: session already terminated");
    const auto &header = request.header;
    host::FileError file_error = host::FileError::none;
    std::uint32_t audio_error = 0, graphics_operation = UINT32_MAX;
    const auto record = [&](Status status) {
        if (policy_.interactive && audit_.size() == policy_.request_limit + 1)
            audit_.erase(audit_.begin());
        const AuditEntry entry{policy_.app_id,      header.sequence, header.operation, status,
                               header.payload_size, file_error,      audio_error,      graphics_operation};
        journal_->note(ticket, entry);
        audit_.push_back(entry);
        ++total_requests_;
    };
    if (header.session != policy_.session || header.sequence != next_sequence_ ||
        next_sequence_ == UINT64_MAX || header.status != Status::ok ||
        header.payload_size != request.payload.size() || header.payload_size > maximum_payload) {
        closed_ = true;
        record(Status::invalid);
        revoke_all();
        throw ProtocolError("AETHER_BROKER_IDENTITY: invalid session, sequence or envelope");
    }
    if (idle_dispatch_) {
        const auto now = std::chrono::steady_clock::now();
        if (!idle_requests_ || now - idle_window_start_ >= std::chrono::seconds(1)) {
            idle_window_start_ = now;
            idle_requests_ = 0;
        }
    }
    auto &requests = idle_dispatch_ ? idle_requests_ : turn_requests_;
    if (requests == policy_.request_limit) {
        closed_ = true;
        record(Status::quota);
        revoke_all();
        throw ProtocolError("AETHER_BROKER_QUOTA: request limit exceeded");
    }
    ++next_sequence_;
    ++requests;
    Frame response{{header.operation, header.sequence, policy_.session, 0, Status::denied}, {}};
    if (header.operation == Operation::monotonic_time || header.operation == Operation::uptime ||
        header.operation == Operation::elapsed_realtime || header.operation == Operation::thread_cpu ||
        header.operation == Operation::process_start_uptime) {
        if (!request.payload.empty()) {
            response.header.status = Status::invalid;
        } else if (policy_.monotonic_time) {
            host::MonotonicTime time{};
            const auto status = header.operation == Operation::uptime ? time_.read_uptime(time) :
                header.operation == Operation::elapsed_realtime ? time_.read_elapsed_realtime(time) :
                header.operation == Operation::thread_cpu ? time_.read_thread_cpu(time) :
                header.operation == Operation::process_start_uptime ? time_.read_process_start_uptime(time) : time_.read_monotonic(time);
            if (status != host::TimeStatus::ok) {
                closed_ = true;
                record(Status::invalid);
                revoke_all();
                throw ProtocolError("AETHER_BROKER_TIME: Windows clock failed");
            }
            append_u64(response.payload, time.seconds);
            append_u64(response.payload, time.nanoseconds);
            response.header.status = Status::ok;
        }
    } else if (header.operation == Operation::wall_time) {
        if (!request.payload.empty()) {
            response.header.status = Status::invalid;
        } else if (policy_.wall_time) {
            host::EpochTime time{};
            if (time_.read_wall_time(time) != host::TimeStatus::ok || time.nanoseconds >= 1'000'000'000) {
                closed_ = true;
                record(Status::invalid);
                revoke_all();
                throw ProtocolError("AETHER_BROKER_TIME: Windows UTC clock failed");
            }
            append_u64(response.payload, std::bit_cast<std::uint64_t>(time.seconds));
            append_u64(response.payload, time.nanoseconds);
            response.header.status = Status::ok;
        }
    } else if (header.operation == Operation::local_calendar) {
        if(request.payload.size()!=8)response.header.status=Status::invalid;
        else if(policy_.wall_time){
            host::LocalTime value;
            const auto status=time_.convert_local_time(std::bit_cast<std::int64_t>(read_u64(request.payload,0)),value);
            if(status==host::TimeStatus::ok){if(!host::local_time_matches_epoch(value,std::bit_cast<std::int64_t>(read_u64(request.payload,0))))throw ProtocolError("AETHER_BROKER_TIME: inconsistent local calendar");append_local_calendar(response.payload,value);response.header.status=Status::ok;}
            else response.header.status=status==host::TimeStatus::out_of_range?Status::invalid:Status::unsupported;
        }
    } else if ((header.operation >= Operation::file_open && header.operation <= Operation::file_close) ||
               header.operation == Operation::file_root || header.operation == Operation::file_flush || header.operation == Operation::file_lock || header.operation == Operation::file_access ||
               header.operation == Operation::file_metadata || header.operation == Operation::file_seek || header.operation == Operation::file_remove ||
               header.operation == Operation::file_open_scoped || header.operation == Operation::file_path || header.operation == Operation::file_rename ||
               header.operation == Operation::file_data_observe || header.operation == Operation::file_directory) {
        host::FileResult result;
        std::vector<std::uint8_t> payload;
        try {
            if (header.operation == Operation::file_remove || header.operation == Operation::file_open_scoped || header.operation == Operation::file_path || header.operation == Operation::file_rename)
                payload.reserve(header.operation==Operation::file_rename?file_transport::rename_reply_bytes:16);
            result = file_request(request, response);
        } catch (const ProtocolError &) {
            result = {-1, host::FileError::invalid};
            response.payload.clear();
        } catch (...) {
            closed_ = true;
            record(Status::invalid);
            revoke_all();
            throw;
        }
        file_error = result.error;
        response.header.status = file_status(result.error);
        append_u64(payload, std::bit_cast<std::uint64_t>(result.value));
        append_u64(payload, static_cast<std::uint64_t>(result.error));
        payload.insert(payload.end(), response.payload.begin(), response.payload.end());
        response.payload = std::move(payload);
    } else if (header.operation >= Operation::audio_open && header.operation <= Operation::audio_close) {
        try {
            response = audio_.dispatch(request);
            if (response.header.status != Status::ok)
                audio_error = 1 + static_cast<std::uint32_t>(read_u64(response.payload, 0));
        } catch (...) {
            closed_ = true;
            record(Status::invalid);
            revoke_all();
            throw;
        }
    } else if (header.operation == Operation::graphics_bind_surface) {
        response.header.status = Status::denied; // Only the trusted parent can grant a renderer texture.
    } else if (header.operation >= Operation::graphics_call &&
               header.operation <= Operation::graphics_close) {
        if (policy_.graphics) {
            try {
                response = graphics_->dispatch(request);
                graphics_operation = graphics_->last_operation();
            } catch (...) {
                graphics_operation = graphics_->last_operation();
                closed_ = true;
                record(Status::invalid);
                revoke_all();
                throw;
            }
        }
    } else if (header.operation == Operation::package_info && !package_.empty()) {
        response.header.status = request.payload.empty() ? Status::ok : Status::invalid;
        if (request.payload.empty()) {
            append_u64(response.payload, package_.size());
            append_text(response.payload, package_hash_);
        }
    } else if (header.operation == Operation::package_read && !package_.empty()) {
        response.header.status = Status::invalid;
        if (request.payload.size() == 16) {
            const auto offset = read_u64(request.payload, 0), count = read_u64(request.payload, 8);
            if (offset <= package_.size() && count > 0 && count <= maximum_payload &&
                count <= package_.size() - offset) {
                response.payload.assign(package_.begin() + static_cast<std::size_t>(offset),
                                        package_.begin() + static_cast<std::size_t>(offset + count));
                response.header.status = Status::ok;
            }
        }
    } else if (header.operation != Operation::package_info && header.operation != Operation::package_read &&
               (header.operation < Operation::storage || header.operation > Operation::audio)) {
        response.header.status = Status::unsupported;
    }
    response.header.payload_size = static_cast<std::uint32_t>(response.payload.size());
    record(response.header.status);
    return response;
}
} // namespace aether::security
