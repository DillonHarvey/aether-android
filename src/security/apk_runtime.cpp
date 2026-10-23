#include "aether/android/selftest.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/apk_session.hpp"
#include <bit>

namespace aether::security {
ApkWorkerResult execute_apk_fixture(BrokerClient &client, std::uint64_t app_id, bool storage_allowed,
                                    const std::array<std::wstring, 3> &denied_files) {
    ApkWorkerResult result;
    const auto package = client.read_package();
    const auto wide = utf16("Aether private storage " + std::to_string(app_id));
    const std::u16string contents(wide.begin(), wide.end());
    const a64::AppContext app{app_id, true};
    android::FrameworkSelftestReport report;
    try {
        report = android::framework_selftest(package, client, app, &client, storage_allowed, contents);
    } catch (const dex::DexError &error) {
        throw ProtocolError(error.code + ": " + error.what());
    }
    if (!report.passed())
        for (const auto &check : report.checks)
            if (!check.passed)
                throw ProtocolError("AETHER_ISOLATED_APK_CHECK: " + check.name);
    // Exercise held-file metadata and real shared offsets through the LPAC pipe.
    // Read the existing first-party proof only; never create an extra input.
    if (storage_allowed) {
        const auto opened = client.open("proof.txt", {true});
        if (opened.error != host::FileError::none) throw ProtocolError("AETHER_ISOLATED_METADATA: open failed");
        const auto fd = static_cast<int>(opened.value);
        host::FileMetadata metadata;
        std::array<std::uint8_t, 1> last{};
        const auto observed = client.metadata(fd, metadata);
        const auto tail = client.seek(fd, -1, 2);
        const auto read = client.read(fd, last);
        const auto start = client.seek(fd, 0, 0);
        const auto closed = client.close(fd);
        if (observed.error != host::FileError::none || observed.value != 0 ||
            !host::valid_file_metadata(metadata) || metadata.size != contents.size() ||
            tail.error != host::FileError::none || tail.value != static_cast<std::int64_t>(contents.size() - 1) ||
            read.error != host::FileError::none || read.value != 1 || last[0] != contents.back() ||
            start.error != host::FileError::none || start.value != 0 ||
            closed.error != host::FileError::none)
            throw ProtocolError("AETHER_ISOLATED_METADATA: held-file metadata or seek mismatch");
    }
    if (storage_allowed) {
        // Required live deletion fixture, distinct from retained proof.txt. A failed
        // run retains its input; exclusive per-process names never overwrite it.
        const auto name="unlink-proof-"+std::to_string(GetCurrentProcessId())+".txt";
        const auto require_file=[](bool okay){if(!okay)throw ProtocolError("AETHER_ISOLATED_REMOVE: held-file unlink or name reuse failed");};
        const auto opened=client.open(name,{true,true,true,true});require_file(opened.error==host::FileError::none);
        const auto fd=static_cast<int>(opened.value);const std::array<std::uint8_t,1> payload{'z'};
        require_file(client.write(fd,payload).value==1);
        host::FileMetadata before,after,replacement;
        require_file(client.metadata(fd,before).error==host::FileError::none && before.links==1);
        const auto removed=client.remove(host::FileAccessScope::files_leaf,name,host::FileRemoveMode::file);
        require_file(removed.error==host::FileError::none && removed.value==static_cast<std::int64_t>(before.identity));
        require_file(client.metadata(fd,after).error==host::FileError::none && after.links==0 && after.identity==before.identity && after.size==1);
        require_file(client.seek(fd,0,0).value==0);std::array<std::uint8_t,1> held{};
        require_file(client.read(fd,held).value==1 && held==payload);
        const auto created=client.open(name,{true,true,true,true});require_file(created.error==host::FileError::none);
        const auto next=static_cast<int>(created.value);
        require_file(client.metadata(next,replacement).error==host::FileError::none && replacement.links==1 && replacement.identity!=before.identity);
        require_file(client.close(next).value==0);
        require_file(client.remove(host::FileAccessScope::files_leaf,name,host::FileRemoveMode::either).value==static_cast<std::int64_t>(replacement.identity));
        require_file(client.close(fd).value==0);
    } else {
        const auto denied=client.remove(host::FileAccessScope::files_leaf,"proof.txt",host::FileRemoveMode::file);
        if(denied.error!=host::FileError::denied || denied.value!=-1)
            throw ProtocolError("AETHER_ISOLATED_REMOVE: missing private grant did not deny deletion");
    }
    if(storage_allowed){
        // Required scoped-open inputs: keep failures, remove only this successful run's names.
        const auto name="scope-proof-"+std::to_string(GetCurrentProcessId())+".txt";
        const auto require_scope=[](bool okay){if(!okay)throw ProtocolError("AETHER_ISOLATED_SCOPED_OPEN: namespace separation or I/O failed");};
        const auto first=client.open_scoped(host::FileAccessScope::files_leaf,name,{true,true,true,true});
        require_scope(first.error==host::FileError::none);
        const auto second=client.open_scoped(host::FileAccessScope::data_leaf,name,{true,true,true,true});
        require_scope(second.error==host::FileError::none);
        const auto one=static_cast<int>(first.value),two=static_cast<int>(second.value);
        const std::array<std::uint8_t,1> a{'f'},b{'d'};std::array<std::uint8_t,1> ar{},br{};
        require_scope(client.write(one,a).value==1);require_scope(client.write(two,b).value==1);
        host::FileMetadata am,bm;
        require_scope(client.metadata(one,am).error==host::FileError::none);
        require_scope(client.metadata(two,bm).error==host::FileError::none && am.identity!=bm.identity && am.size==1 && bm.size==1);
        require_scope(client.seek(one,0,0).value==0);require_scope(client.seek(two,0,0).value==0);
        require_scope(client.read(one,ar).value==1 && ar==a);require_scope(client.read(two,br).value==1 && br==b);
        require_scope(client.close(one).value==0);require_scope(client.close(two).value==0);
        require_scope(client.remove(host::FileAccessScope::files_leaf,name,host::FileRemoveMode::file).value==static_cast<std::int64_t>(am.identity));
        require_scope(client.remove(host::FileAccessScope::data_leaf,name,host::FileRemoveMode::file).value==static_cast<std::int64_t>(bm.identity));
    }else{
        const auto denied=client.open_scoped(host::FileAccessScope::data_leaf,"proof.txt",{true,true,true});
        if(denied.error!=host::FileError::denied || denied.value!=-1)
            throw ProtocolError("AETHER_ISOLATED_SCOPED_OPEN: missing private grant did not deny open");
    }
    for (const auto &path : denied_files) {
        host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file || GetLastError() != ERROR_ACCESS_DENIED)
            throw ProtocolError("AETHER_ISOLATED_STORAGE_ESCAPE: broker-owned file was not access-denied");
        ++result[ApkMetric::direct_file_denials];
    }
    result[ApkMetric::app_id] = app_id;
    result[ApkMetric::checks] = report.checks.size();
    result[ApkMetric::storage_result] =
        std::bit_cast<std::uint64_t>(static_cast<std::int64_t>(report.storage_result));
    result[ApkMetric::storage_denials] = report.storage_denials;
    result[ApkMetric::compiled_blocks] = report.cpu.compiled_blocks;
    result[ApkMetric::emitted_bytes] = report.cpu.emitted_bytes;
    result[ApkMetric::rx_failures] = report.cpu.rx_failures;
    result[ApkMetric::interpreter_fallbacks] = report.cpu.interpreter_fallbacks;
    result[ApkMetric::native_calls] = report.jni.native_calls;
    result[ApkMetric::managed_callbacks] = report.jni.managed_callbacks;
    result[ApkMetric::on_load_calls] = report.jni.on_load_calls;
    result[ApkMetric::managed_instructions] = report.managed.instructions;
    result[ApkMetric::pinned_references] = report.managed.pinned_references;
    result[ApkMetric::local_references] = report.jni.local_references;
    result[ApkMetric::global_references] = report.jni.global_references;
    result[ApkMetric::string_buffers] = report.jni.string_buffers;
    result[ApkMetric::lifecycle_callbacks] = report.framework.lifecycle_callbacks;
    result[ApkText::apk_hash] = report.apk_sha256;
    result[ApkText::dex_hash] = report.dex_sha256;
    result[ApkText::resources_hash] = report.resources_sha256;
    result[ApkText::package] = report.package;
    result[ApkText::activity] = report.launch_activity;
    result[ApkText::result] = utf8(std::wstring(report.result_text.begin(), report.result_text.end()));
    result[ApkText::trace] = utf8(std::wstring(report.managed_trace.begin(), report.managed_trace.end()));
    return result;
}
} // namespace aether::security
