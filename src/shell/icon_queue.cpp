#include "aether/shell/icon_service.hpp"
#include "aether/shell/icons.hpp"
#include <algorithm>
#include <array>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

namespace aether::shell {
struct IconQueue::Impl {
    std::function<void(const std::wstring &)> processor;
    mutable std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::wstring> queue;
    std::set<std::wstring> outstanding;
    IconQueueStats counts;
    std::size_t path_bytes = 0;
    bool stopping = false;
    std::array<std::thread, 2> workers;
    explicit Impl(std::function<void(const std::wstring &)> work) : processor(std::move(work)) {
        if (!processor)
            throw std::invalid_argument("An icon processor is required");
        try {
            for (auto &thread : workers)
                thread = std::thread([this] { run(); });
        } catch (...) {
            stop();
            throw;
        }
    }
    ~Impl() { stop(); }
    void stop() {
        {
            std::lock_guard lock(mutex);
            stopping = true;
            for (const auto &path : queue) {
                outstanding.erase(path);
                path_bytes -= path.size() * sizeof(wchar_t);
            }
            queue.clear();
            counts.pending = 0;
        }
        ready.notify_all();
        for (auto &thread : workers)
            if (thread.joinable())
                thread.join();
    }
    void run() {
        for (;;) {
            std::wstring path;
            {
                std::unique_lock lock(mutex);
                ready.wait(lock, [this] { return stopping || !queue.empty(); });
                if (stopping)
                    return;
                path = std::move(queue.front());
                queue.pop_front();
                counts.pending = static_cast<std::uint32_t>(queue.size());
                ++counts.active;
                counts.peak_active = std::max(counts.peak_active, counts.active);
            }
            bool failed = false;
            try {
                processor(path);
            } catch (...) {
                failed = true;
            }
            {
                std::lock_guard lock(mutex);
                outstanding.erase(path);
                path_bytes -= path.size() * sizeof(wchar_t);
                --counts.active;
                ++counts.completed;
                if (failed)
                    ++counts.failed;
            }
        }
    }
};
IconQueue::IconQueue(std::function<void(const std::wstring &)> processor)
    : impl_(std::make_unique<Impl>(std::move(processor))) {}
IconQueue::~IconQueue() = default;
bool IconQueue::submit(std::wstring path) {
    path = icon_input_path(path);
    if (path.empty())
        return false;
    std::lock_guard lock(impl_->mutex);
    if (impl_->stopping)
        return false;
    if (impl_->outstanding.contains(path)) {
        ++impl_->counts.coalesced;
        return true;
    }
    if (impl_->outstanding.size() >= 1024 ||
        path.size() * sizeof(wchar_t) > 4 * 1024 * 1024 - impl_->path_bytes) {
        ++impl_->counts.rejected;
        return false;
    }
    impl_->queue.push_back(path);
    try {
        impl_->outstanding.insert(path);
    } catch (...) {
        impl_->queue.pop_back();
        throw;
    }
    ++impl_->counts.accepted;
    impl_->path_bytes += path.size() * sizeof(wchar_t); // Two string copies: at most 8 MiB total.
    impl_->counts.pending = static_cast<std::uint32_t>(impl_->queue.size());
    impl_->counts.peak_pending = std::max(impl_->counts.peak_pending, impl_->counts.pending);
    impl_->ready.notify_one();
    return true;
}
IconQueueStats IconQueue::stats() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->counts;
}
void IconQueue::stop() { impl_->stop(); }
} // namespace aether::shell
