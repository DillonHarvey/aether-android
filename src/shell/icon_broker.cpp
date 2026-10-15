#include "aether/shell/icon_broker.hpp"
#include "aether/common/text.hpp"
#include "aether/security/metadata_process.hpp"
#include "aether/shell/icon_cache.hpp"
#include "aether/shell/icon_service.hpp"
#include "aether/shell/icons.hpp"
#include <ShlObj.h>
#include <atomic>
#include <iostream>
#include <mutex>
#include <set>
#include <wrl/client.h>

namespace aether::shell {
namespace {
bool notify_icon_changed(const std::wstring &path) {
    // File handles use extended paths, but the Shell needs the ordinary drive
    // path. Filesystem PIDLs avoid SHCNF_PATHW's MAX_PATH limit.
    const auto name = path.starts_with(L"\\\\?\\") ? path.c_str() + 4 : path.c_str();
    if (wcslen(name) < MAX_PATH) {
        SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, name, nullptr);
        return true;
    }
    const auto apartment = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(apartment))
        return false;
    struct Apartment {
        ~Apartment() { CoUninitialize(); }
    } initialized;
    auto ancestor = std::filesystem::path(name);
    std::vector<std::wstring> descendants;
    while (ancestor.native().size() >= MAX_PATH) {
        descendants.push_back(ancestor.filename().native());
        ancestor = ancestor.parent_path();
    }
    struct FreePidl {
        using pointer = PIDLIST_ABSOLUTE;
        void operator()(pointer value) const noexcept { ILFree(value); }
    };
    using Pidl = std::unique_ptr<ITEMIDLIST, FreePidl>;
    Pidl item(ILCreateFromPathW(ancestor.c_str()));
    if (!item)
        return false;
    // Build bounded relative components beneath the same filesystem ancestor
    // identity used by path notifications. ILCreateFromPath itself is only
    // defined up to MAX_PATH.
    for (auto part = descendants.rbegin(); part != descendants.rend(); ++part) {
        Microsoft::WRL::ComPtr<IShellFolder> folder;
        if (FAILED(SHBindToObject(nullptr, item.get(), nullptr, IID_PPV_ARGS(&folder))))
            return false;
        PIDLIST_RELATIVE raw = nullptr;
        if (FAILED(folder->ParseDisplayName(nullptr, nullptr, part->data(), nullptr, &raw, nullptr)))
            return false;
        Pidl relative(raw), combined(ILCombine(item.get(), relative.get()));
        if (!combined)
            return false;
        item = std::move(combined);
    }
    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT, item.get(), nullptr);
    return true;
}
} // namespace
void run_icon_broker(const std::filesystem::path &worker_path, const std::filesystem::path &cache_root,
                     const std::wstring &endpoint, HANDLE stop_event,
                     const std::function<void(std::string_view)> &diagnostic) {
    IconCache cache(cache_root, true);
    std::mutex cache_mutex, workers_mutex;
    std::set<security::MetadataProcess *> workers;
    std::atomic<bool> stopping = false;
    IconQueue queue([&](const std::wstring &path) {
        if (stopping)
            return;
        IconSource source(path, true);
        {
            std::lock_guard lock(cache_mutex);
            const auto current = cache.lookup(source.identity());
            if (current.state == CacheState::ready) {
                cache.touch(source.identity());
                return;
            }
            if (current.state == CacheState::retry_later)
                return;
        }
        try {
            security::MetadataProcess worker(worker_path);
            {
                std::lock_guard lock(workers_mutex);
                if (stopping)
                    worker.request_stop();
                workers.insert(&worker);
            }
            struct Unregister {
                std::mutex &mutex;
                std::set<security::MetadataProcess *> &workers;
                security::MetadataProcess *worker;
                ~Unregister() {
                    std::lock_guard lock(mutex);
                    workers.erase(worker);
                }
            } unregister{workers_mutex, workers, &worker};
            const auto result = worker.inspect(source);
            if (diagnostic && result.preview.status != apk::IconStatus::extracted)
                diagnostic(result.preview.code + ": " + result.preview.reason);
            bool changed = false;
            {
                std::lock_guard lock(cache_mutex);
                if (result.preview.status == apk::IconStatus::extracted ||
                    (result.exit_code == 0 && result.preview.format == apk::PreviewFormat::aab))
                    changed = cache.commit(source.identity(),
                                           apk::icon_file(result.preview.presentation.bitmap, 2));
                else
                    cache.failure(source.identity());
            }
            if (changed && !stopping) {
                const auto notified = notify_icon_changed(path);
                if (diagnostic)
                    diagnostic(notified
                                   ? "AETHER_ICON_READY: Cache committed and item update submitted"
                                   : "AETHER_ICON_NOTIFY_FAILED: Cannot identify the completed Shell item");
            }
        } catch (const std::exception &error) {
            if (diagnostic)
                diagnostic(std::string_view(error.what()).substr(0, 512));
            if (!stopping) {
                std::lock_guard lock(cache_mutex);
                cache.failure(source.identity());
            }
            throw;
        }
    });
    const auto stop = [&] {
        stopping = true;
        {
            std::lock_guard lock(workers_mutex);
            for (auto worker : workers)
                worker->request_stop();
        }
        queue.stop();
    };
    try {
        serve_icon_requests(endpoint, queue, stop_event);
    } catch (...) {
        stop();
        throw;
    }
    stop();
}
namespace {
std::filesystem::path own_worker() {
    std::wstring path(32768, L'\0');
    const auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!count || count >= path.size())
        throw std::runtime_error("Cannot identify the installed icon worker");
    path.resize(count);
    return std::filesystem::path(path).parent_path() / L"runtime" / L"aether_icon_worker.exe";
}
} // namespace
std::optional<int> dispatch_icon_cli(const std::vector<std::string> &arguments, bool json) {
    if (arguments.empty() || arguments.front() != "shell-icons")
        return std::nullopt;
    try {
        std::vector<std::string> args;
        bool seen_json = false;
        for (std::size_t i = 1; i < arguments.size(); ++i) {
            if (arguments[i] == "--json" && !seen_json)
                seen_json = true;
            else
                args.push_back(arguments[i]);
        }
        if (args.size() == 1 && args[0] == "status") {
            const auto cache = icon_cache_root();
            const auto live = send_icon_message(icon_endpoint(), IconMessage::ping);
            bool available = false;
            try {
                IconCache existing(cache);
                available = true;
            } catch (...) {
            }
            const std::string report =
                "{\"cacheVersion\":2,\"rendererVersion\":2,\"contentVersion\":" +
                std::to_string(icon_content_version) +
                ",\"serviceRunning\":" + std::string(live ? "true" : "false") +
                ",\"cacheAvailable\":" + (available ? "true" : "false") +
                ",\"cachePath\":" + json_quote(utf8(cache.native())) +
                ",\"workerPolicy\":\"LPAC; zero capabilities; no dynamic code\",\"workerDeadlineMs\":5000,"
                "\"memoryLimitBytes\":268435456,\"cacheQuotaBytes\":268435456,\"queueLimit\":1024,"
                "\"workerConcurrency\":2,\"installationAssessed\":false,\"executionAvailable\":false}";
            std::cout << (json ? report
                               : std::string("Package icon service: ") + (live ? "running" : "not running") +
                                     "; cache " + (available ? "available" : "unavailable"))
                      << '\n';
            return 0;
        }
        if (args.size() == 1 && args[0] == "stop") {
            const auto sent = send_icon_message(icon_endpoint(), IconMessage::stop);
            std::cout << (json   ? std::string("{\"stopAccepted\":") + (sent ? "true}" : "false}")
                          : sent ? "Icon service is stopping."
                                 : "No responding icon service.")
                      << '\n';
            return 0;
        }
        if (args.size() == 1 && args[0] == "serve") {
            host::UniqueHandle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!stop)
                throw std::runtime_error("Cannot create icon service stop event");
            run_icon_broker(own_worker(), icon_cache_root(), icon_endpoint(), stop.get());
            return 0;
        }
        if (args.size() == 2 && args[0] == "probe") {
            IconSource source(std::filesystem::absolute(utf16(args[1])), true);
            security::MetadataProcess worker(own_worker());
            const auto result = worker.inspect(source);
            const auto &account = result.accounting;
            const auto report = "{\"preview\":" + result.preview.json() +
                                ",\"worker\":{\"isolated\":true,\"pid\":" + std::to_string(result.pid) +
                                ",\"exitCode\":" + std::to_string(result.exit_code) +
                                ",\"timedOut\":" + (result.timed_out ? "true" : "false") +
                                ",\"totalProcesses\":" + std::to_string(account.total_processes) +
                                ",\"activeAfterExit\":" + std::to_string(account.active_processes) +
                                ",\"peakCommitBytes\":" + std::to_string(account.peak_commit_bytes) +
                                ",\"memoryLimitBytes\":" + std::to_string(account.memory_limit_bytes) +
                                ",\"cpuLimit100ns\":" + std::to_string(account.user_time_limit_100ns) +
                                ",\"limitFlags\":" + std::to_string(account.limit_flags) + "}}";
            std::cout << (json ? report
                               : std::string(apk::icon_status_name(result.preview.status)) + ": " +
                                     result.preview.reason)
                      << '\n';
            return result.preview.status == apk::IconStatus::extracted ||
                           result.preview.status == apk::IconStatus::no_icon
                       ? 0
                   : result.preview.status == apk::IconStatus::unsupported ? 3
                                                                           : 1;
        }
        std::cerr << "Use shell-icons status|stop|serve, or shell-icons probe <local-package> [--json].\n";
        return 2;
    } catch (const std::exception &error) {
        std::cout << (json ? std::string("{\"code\":\"AETHER_ICON_SERVICE_FAILED\",\"reason\":") +
                                 json_quote(std::string_view(error.what()).substr(0, 512)) + "}"
                           : std::string("AETHER_ICON_SERVICE_FAILED: ") + error.what())
                  << '\n';
        return 1;
    }
}
} // namespace aether::shell
