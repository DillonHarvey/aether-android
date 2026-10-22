#pragma once
#include "aether/dex/runtime.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <string>
#include <string_view>

namespace aether::security {
// Diagnostic-only anonymous section. The caller must prove worker termination
// before reading; records never authorize work or extend a deadline.
class WorkerProgress final {
  public:
    WorkerProgress();
    ~WorkerProgress();
    WorkerProgress(const WorkerProgress &)=delete;
    WorkerProgress &operator=(const WorkerProgress &)=delete;
    HANDLE handle() const noexcept{return mapping_.get();}
    std::string summary_after_exit() const;
  private:
    host::UniqueHandle mapping_;
    void *view_=nullptr;
};
// Takes ownership of the already duplicated, read/write-only section handle.
// A single worker owner serializes all reports, including logical guest tasks.
class ScopedWorkerFaultCapture;
class WorkerProgressWriter final:public dex::RuntimeProgressSink {
  public:
    explicit WorkerProgressWriter(HANDLE owned_duplicated_handle);
    ~WorkerProgressWriter() override;
    WorkerProgressWriter(const WorkerProgressWriter &)=delete;
    WorkerProgressWriter &operator=(const WorkerProgressWriter &)=delete;
    void report(const dex::RuntimeProgress &) noexcept override;
    void stage(std::uint32_t numeric,std::string_view label) noexcept;
    bool prepare_native_stack() noexcept override;
  private:
    friend class ScopedWorkerFaultCapture;
    host::UniqueHandle mapping_;
    void *view_=nullptr;
    std::uint64_t sequence_=0;
    DWORD fault_owner_=0;
    std::uint64_t image_base_=0,cached_stack_base_=0,cached_allocation_base_=0;
    void refresh_native_stack() noexcept;
    void capture_native_fault(EXCEPTION_POINTERS *) noexcept;
    void write(std::uint32_t kind,std::uint32_t stage,std::uint32_t method,std::uint32_t pc,
               std::uint64_t instructions,std::string_view owner,std::string_view name,std::string_view label) noexcept;
};
class ScopedWorkerFaultCapture final {
  public:
    explicit ScopedWorkerFaultCapture(WorkerProgressWriter &);
    ~ScopedWorkerFaultCapture();
    ScopedWorkerFaultCapture(const ScopedWorkerFaultCapture &)=delete;
    ScopedWorkerFaultCapture &operator=(const ScopedWorkerFaultCapture &)=delete;
  private:
    WorkerProgressWriter &writer_;
    void *handler_=nullptr;
    static LONG CALLBACK handle(EXCEPTION_POINTERS *) noexcept;
};
} // namespace aether::security
