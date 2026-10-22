#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/audit.hpp"
#include "aether/security/storage.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace aether::security {
namespace {
void require(bool valid, const char *message) {
    if (!valid)
        throw ProtocolError(std::string("AETHER_AUDIT_STORAGE: ") + message +
                            "; Windows error=" + std::to_string(GetLastError()));
}
std::string file_name(std::uint64_t session) {
    std::ostringstream name;
    name << "session_" << std::hex << std::setw(16) << std::setfill('0') << session << ".audit";
    return name.str();
}
bool valid_name(const std::string &name) {
    return name.size() == 30 && name.starts_with("session_") && name.ends_with(".audit") &&
           name.substr(8, 16).find_first_not_of("0123456789abcdef") == std::string::npos;
}
std::vector<std::uint8_t> read_file(const std::filesystem::path &path) {
    host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    LARGE_INTEGER size{};
    BY_HANDLE_FILE_INFORMATION info{};
    require(file && GetFileType(file.get()) == FILE_TYPE_DISK && GetFileSizeEx(file.get(), &size) &&
                size.QuadPart >= 0 && size.QuadPart <= audit_file_limit &&
                GetFileInformationByHandle(file.get(), &info) && info.nNumberOfLinks == 1 &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)),
            "Cannot inspect a normal bounded audit file");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    require(ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) &&
                read == bytes.size(),
            "Cannot read complete audit file");
    return bytes;
}
class FileAuditWriter final : public AuditWriter {
    std::filesystem::path parent_, path_;
    std::unique_ptr<PrivateStorage> storage_;
    host::UniqueHandle file_;
    std::size_t bytes_ = 0;
    bool explicit_root_ = false;

  public:
    explicit FileAuditWriter(std::filesystem::path parent, bool explicit_root = false)
        : parent_(std::move(parent)), explicit_root_(explicit_root) {
        require(parent_.is_absolute(), "Audit parent must be an absolute trusted path");
    }
    void open(const AuditContext &context) override {
        require(!storage_ && context.worker_process && context.worker_process != context.parent_process,
                "A real isolated worker binding is required before audit startup");
        if (explicit_root_)
            storage_ = std::make_unique<PrivateStorage>(parent_, StoragePurpose::audit);
        else {
            std::filesystem::create_directory(parent_);
            storage_ = std::make_unique<PrivateStorage>(parent_, context.app_id, StoragePurpose::audit);
        }
        path_ = storage_->root() / file_name(context.session);
        require(!std::filesystem::exists(path_), "Refusing to overwrite an existing session audit");
        struct Candidate {
            std::filesystem::path path;
            std::uint64_t timestamp;
            std::size_t bytes;
        };
        std::vector<Candidate> completed;
        std::size_t count = 0, retained_bytes = 0;
        for (const auto &entry : std::filesystem::directory_iterator(storage_->root())) {
            ++count;
            const auto name = entry.path().filename().string();
            require(valid_name(name), "Unrecognized audit file; no automatic deletion");
            // Incomplete/corrupt evidence is retained, never repaired or reused as a fresh log.
            const auto bytes = read_file(entry.path());
            if (bytes.size() > audit_total_limit - retained_bytes)
                throw ProtocolError(
                    "AETHER_AUDIT_STORAGE: Retained evidence exceeds the 16 MiB bound; no files changed");
            retained_bytes += bytes.size();
            try {
                const auto summary = inspect_audit(bytes);
                require(summary.context.app_id == context.app_id &&
                            file_name(summary.context.session) == name,
                        "Retained audit identity differs from its location");
                if (summary.ended && !summary.pending && !summary.aborted)
                    completed.push_back({entry.path(), summary.first_utc_100ns, bytes.size()});
            } catch (const ProtocolError &) {
                // A bounded damaged/unfinished file consumes retention capacity for later diagnosis.
            }
        }
        std::sort(completed.begin(), completed.end(), [](const auto &a, const auto &b) {
            return a.timestamp != b.timestamp ? a.timestamp < b.timestamp : a.path < b.path;
        });
        std::size_t retired = 0;
        while (count >= PrivateStorage::maximum_audit_names ||
               retained_bytes > audit_total_limit - audit_file_limit ||
               completed.size() - retired >= audit_retained_successes) {
            if (retired == completed.size())
                throw ProtocolError(
                    "AETHER_AUDIT_STORAGE: Preserved evidence fills the audit capacity; startup refused (" +
                    std::to_string(count) + " sessions, " + std::to_string(retained_bytes) + " bytes)");
            retained_bytes -= completed[retired++].bytes;
            --count;
        }
        // Decide whether all bounds can be satisfied before retiring any file.
        for (std::size_t n = 0; n < retired; ++n)
            require(DeleteFileW(completed[n].path.c_str()), "Cannot retire oldest successful audit");
        file_.reset(CreateFileW(
            path_.c_str(), GENERIC_WRITE | READ_CONTROL, FILE_SHARE_READ, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        require(file_ && GetFileType(file_.get()) == FILE_TYPE_DISK &&
                    GetFileInformationByHandle(file_.get(), &info) && info.nNumberOfLinks == 1 &&
                    !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)),
                "Cannot create exclusive protected audit file");
    }
    void append(std::span<const std::uint8_t> record) override {
        require(file_ && record.size() == audit_record_bytes && record.size() <= audit_file_limit - bytes_,
                "Audit file is absent or at capacity");
        DWORD written = 0;
        require(WriteFile(file_.get(), record.data(), static_cast<DWORD>(record.size()), &written, nullptr) &&
                    written == record.size() && FlushFileBuffers(file_.get()),
                "Audit persistence failed; record will not be retried");
        bytes_ += record.size();
    }
    std::filesystem::path path() const override { return path_; }
};
} // namespace
std::shared_ptr<AuditTrail> make_file_audit(const std::filesystem::path &parent) {
    return std::make_shared<AuditTrail>(std::make_unique<FileAuditWriter>(parent));
}
std::shared_ptr<AuditTrail> make_file_audit_at_root(const std::filesystem::path &root) {
    return std::make_shared<AuditTrail>(std::make_unique<FileAuditWriter>(root, true));
}
} // namespace aether::security
