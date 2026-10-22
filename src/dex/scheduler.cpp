#include "aether/dex/scheduler.hpp"
#include "aether/dex/image.hpp"
#include "aether/host/thread_priority.hpp"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <thread>
#include <utility>

namespace aether::dex {
namespace {
[[noreturn]] void bad(const char *code, const char *message) { throw DexError(code, message); }
struct Cancellation final {};
std::atomic<std::uint64_t> next_identity{1};
thread_local Scheduler::TaskId active_task = 0;
std::uint64_t identity() {
    auto next = next_identity.load(std::memory_order_relaxed);
    do {
        if (next == UINT64_MAX) bad("AETHER_SCHEDULER_ID_LIMIT", "Task identities are exhausted");
    } while (!next_identity.compare_exchange_weak(next, next + 1, std::memory_order_relaxed));
    return next;
}
std::optional<std::uint64_t> thread_cpu_ticks() noexcept {
    FILETIME created{}, exited{}, kernel{}, user{};
    if(!GetThreadTimes(GetCurrentThread(),&created,&exited,&kernel,&user))return {};
    const auto ticks=[](FILETIME value){return (std::uint64_t(value.dwHighDateTime)<<32)|value.dwLowDateTime;};
    const auto k=ticks(kernel),u=ticks(user);
    if(k>UINT64_MAX-u)return {};
    return k+u;
}
bool terminal(Scheduler::State state) {
    return state == Scheduler::State::completed || state == Scheduler::State::cancelled || state == Scheduler::State::failed;
}
}
struct Scheduler::Impl {
    using Clock = std::chrono::steady_clock;
    struct Task {
        Impl *owner = nullptr;
        TaskId id = 0;
        void *fiber = nullptr;
        State state = State::runnable;
        bool cancelled = false, cancellation_delivered = false;
        bool park_permit = false, park_timed = false;
        std::int32_t priority = 0;
        std::uint64_t cpu_ticks = 0, cpu_slice_start = 0;
        Clock::time_point deadline{};
        std::function<void()> callback;
        std::exception_ptr failure;
    };
    CpuClock cpu_clock;
    std::shared_ptr<ProcessState> process;
    mutable bool cpu_valid = true;
    mutable std::optional<std::uint64_t> cpu_observed;
    std::uint64_t background_cpu_ticks = 0;
    bool observe_cpu(std::uint64_t ticks) const noexcept {
        if(cpu_observed && ticks<*cpu_observed)cpu_valid=false;
        cpu_observed=ticks;
        return cpu_valid;
    }
    std::optional<std::uint64_t> sample_cpu() noexcept {
        if(!cpu_valid)return {};
        try {
            const auto sample=cpu_clock();
            if(sample && observe_cpu(*sample))return sample;
        } catch(...) {}
        cpu_valid=false;return {};
    }
    Limits limits;
    DWORD owner_thread = GetCurrentThreadId();
    void *root = nullptr;
    Task *running = nullptr;
    bool closed = false, close_complete = false;
    int initial_priority = THREAD_PRIORITY_NORMAL;
    std::int32_t root_priority = 0;
    bool priority_changed = false;
    std::array<std::unique_ptr<Task>, 32> tasks;
    std::size_t cursor = 0;
    explicit Impl(Limits value,CpuClock clock,std::optional<int> baseline={}) : cpu_clock(std::move(clock)), limits(value) {
        if(!cpu_clock)bad("AETHER_SCHEDULER_CPU_CLOCK", "CPU sampler is absent");
        if (!limits.contexts || limits.contexts > tasks.size() || limits.stack_commit < 16 * 1024 ||
            limits.stack_commit > 256 * 1024 || limits.stack_reserve < limits.stack_commit ||
            limits.stack_reserve > 2 * 1024 * 1024 || limits.stack_commit % 4096 || limits.stack_reserve % 65536)
            bad("AETHER_SCHEDULER_LIMITS", "Invalid bounded fiber context or stack limits");
        if (IsThreadAFiber()) bad("AETHER_SCHEDULER_FIBER", "Owner is already a fiber; external or nested ownership is unsupported");
        initial_priority = baseline?*baseline:GetThreadPriority(GetCurrentThread());
        if(initial_priority == THREAD_PRIORITY_ERROR_RETURN)
            bad("AETHER_SCHEDULER_PRIORITY", "Cannot query the scheduler owner's Win32 priority");
        root = ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH);
        if (!root) bad("AETHER_SCHEDULER_FIBER", "Cannot convert scheduler owner to a floating-point-preserving fiber");
    }
    void check() const {
        if (GetCurrentThreadId() != owner_thread)
            bad("AETHER_SCHEDULER_THREAD", "Scheduler belongs to another OS thread");
        if (!IsThreadAFiber() || GetCurrentFiber() != (running ? running->fiber : root))
            bad("AETHER_SCHEDULER_FIBER", "Scheduler entered from an unowned fiber");
    }
    void external() const {
        check();
        if (running) bad("AETHER_SCHEDULER_STATE", "Operation requires the external owner main context");
    }
    Task &find(TaskId id) const {
        for (const auto &task : tasks) if (task && task->id == id) return *task;
        bad("AETHER_SCHEDULER_TASK", "Task identity is absent, released or belongs to another scheduler");
    }
    void checkpoint() {
        check();
        if (!running) bad("AETHER_SCHEDULER_STATE", "No managed fiber is running");
        if(process)process->checkpoint();
        if (running->cancelled) {
            // Trusted callbacks may catch all for cleanup and immediately rethrow.
            // Suppression followed by another checkpoint is a fatal contract violation;
            // repeatedly injecting exceptions on the same native stack is not cleanup.
            if (running->cancellation_delivered) std::terminate();
            running->cancellation_delivered = true;
            throw Cancellation{};
        }
    }
    void park(std::optional<Clock::time_point> deadline) {
        checkpoint();
        if (std::exchange(running->park_permit, false)) return;
        if (deadline && Clock::now() >= *deadline) return;
        running->park_timed = deadline.has_value();
        if (deadline) running->deadline = *deadline;
        running->state = State::parked;
        SwitchToFiber(root);
        checkpoint();
        running->park_timed = false;
        running->park_permit = false; // Consume the single permit, if unpark supplied one.
    }
    static VOID WINAPI entry(void *parameter) {
        auto &task = *static_cast<Task *>(parameter);
        auto &owner = *task.owner;
        try {
            owner.checkpoint();
            task.callback();
            if(owner.process)owner.process->checkpoint();
            task.state = task.cancelled ? State::cancelled : State::completed;
        } catch (const ProcessExit &) {
            task.failure = std::current_exception();
            task.state = State::cancelled;
        } catch (const Cancellation &) {
            task.state = State::cancelled;
        } catch (...) {
            task.failure = std::current_exception();
            task.state = State::failed;
        }
        task.callback = {}; // Destroy captures only after stack-local RAII has unwound.
        SwitchToFiber(owner.root);
        std::terminate(); // Terminal fibers must only be deleted, never resumed.
    }
    void resume(Task &task) {
        const auto previous_priority = GetThreadPriority(GetCurrentThread());
        if(previous_priority == THREAD_PRIORITY_ERROR_RETURN)
            bad("AETHER_SCHEDULER_PRIORITY", "Cannot preserve owner priority before logical task execution");
        const auto target_priority = *host::priority_profile_target(initial_priority,task.priority);
        if(target_priority != previous_priority && !SetThreadPriority(GetCurrentThread(),target_priority))
            bad("AETHER_SCHEDULER_PRIORITY", "Cannot apply logical task priority to the Win32 owner");
        running = &task;
        active_task = task.id;
        task.state = State::running;
        const auto cpu_start=sample_cpu();
        if(cpu_start)task.cpu_slice_start=*cpu_start;
        SwitchToFiber(task.fiber);
        const auto cpu_end=sample_cpu();
        if(cpu_start && cpu_end) {
            const auto elapsed=*cpu_end-*cpu_start;
            if(elapsed>UINT64_MAX-task.cpu_ticks || elapsed>UINT64_MAX-background_cpu_ticks)cpu_valid=false;
            else {task.cpu_ticks+=elapsed;background_cpu_ticks+=elapsed;}
        }
        running = nullptr;
        active_task = 0;
        if(target_priority != previous_priority || priority_changed) {
            if(!SetThreadPriority(GetCurrentThread(),previous_priority))
                bad("AETHER_SCHEDULER_PRIORITY", "Cannot restore owner priority after logical task execution");
        }
        check();
    }
};
Scheduler::Scheduler() : Scheduler(Limits{}) {}
Scheduler::Scheduler(int baseline) : impl_(std::make_unique<Impl>(Limits{},thread_cpu_ticks,baseline)) {}
Scheduler::Scheduler(Limits limits) : Scheduler(limits,thread_cpu_ticks) {}
Scheduler::Scheduler(Limits limits,CpuClock clock) : impl_(std::make_unique<Impl>(limits,std::move(clock))) {}
std::uint64_t Scheduler::logical_cpu_ticks(std::uint64_t raw) const {
    const auto &p=*impl_;p.check();
    if(!p.cpu_valid || !p.observe_cpu(raw))
        bad("AETHER_SCHEDULER_CPU_UNAVAILABLE","Logical-thread CPU accounting is unavailable");
    if(p.running) {
        const auto elapsed=raw-p.running->cpu_slice_start;
        if(elapsed>UINT64_MAX-p.running->cpu_ticks) {
            p.cpu_valid=false;bad("AETHER_SCHEDULER_CPU_UNAVAILABLE","Logical-thread CPU accounting overflowed");
        }
        return p.running->cpu_ticks+elapsed;
    }
    if(raw<p.background_cpu_ticks) {
        p.cpu_valid=false;bad("AETHER_SCHEDULER_CPU_UNAVAILABLE","Owner CPU clock does not match scheduler accounting");
    }
    return raw-p.background_cpu_ticks;
}
Scheduler::~Scheduler() {
    if (!impl_) return;
    try {
        close();
        for (auto &task : impl_->tasks) if (task) {
            if(!terminal(task->state))std::terminate();
            DeleteFiber(task->fiber);
        }
        if (!ConvertFiberToThread()) std::terminate();
    } catch (...) { std::terminate(); }
}
Scheduler::TaskId Scheduler::submit(std::function<void()> callback,std::optional<std::int32_t> inherited_priority) {
    auto &p = *impl_;p.check();
    if(p.process)p.process->checkpoint();
    if (p.closed) bad("AETHER_SCHEDULER_CLOSED", "Submissions are closed");
    if (!callback) bad("AETHER_SCHEDULER_TASK", "Empty scheduler callback");
    if(inherited_priority && !host::priority_profile_supported(*inherited_priority))bad("AETHER_SCHEDULER_PRIORITY_UNSUPPORTED","Unsupported inherited priority profile");
    std::size_t occupied = 0;std::unique_ptr<Impl::Task> *slot = nullptr;
    for (auto &task : p.tasks) { if (task) ++occupied; else if (!slot) slot = &task; }
    if (!slot || occupied == p.limits.contexts) bad("AETHER_SCHEDULER_CONTEXT_LIMIT", "Retained scheduler context bound exceeded");
    auto task = std::make_unique<Impl::Task>();task->owner=&p;task->callback=std::move(callback);
    task->priority = inherited_priority?*inherited_priority:(p.running ? p.running->priority : p.root_priority);
    task->id=identity();
    task->fiber=CreateFiberEx(p.limits.stack_commit,p.limits.stack_reserve,FIBER_FLAG_FLOAT_SWITCH,&Impl::entry,task.get());
    if (!task->fiber) bad("AETHER_SCHEDULER_STACK", "Cannot allocate bounded scheduler fiber stack");
    const auto id=task->id;*slot=std::move(task);return id;
}
bool Scheduler::run_one() {
    auto &p=*impl_;p.external();
    if (p.closed) return false;
    const auto now=Impl::Clock::now();
    for (auto &task:p.tasks) if(task && (task->state==State::sleeping ||
        (task->state==State::parked && task->park_timed)) && task->deadline<=now) task->state=State::runnable;
    for (std::size_t n=0;n<p.tasks.size();++n) {
        const auto index=(p.cursor+n)%p.tasks.size();auto &task=p.tasks[index];
        if (!task || task->state!=State::runnable) continue;
        p.cursor=(index+1)%p.tasks.size();p.resume(*task);return true;
    }
    return false;
}
void Scheduler::yield() {
    auto &p=*impl_;p.checkpoint();p.running->state=State::runnable;SwitchToFiber(p.root);p.checkpoint();
}
void Scheduler::sleep_for(std::chrono::milliseconds duration) {
    auto &p=*impl_;p.checkpoint();
    const auto now=Impl::Clock::now();
    if (duration.count()<0 || duration>std::chrono::duration_cast<std::chrono::milliseconds>(Impl::Clock::time_point::max()-now))
        bad("AETHER_SCHEDULER_TIME", "Sleep duration is negative or exceeds the monotonic deadline range");
    if (!duration.count()) {yield();return;}
    p.running->deadline=now+duration;p.running->state=State::sleeping;SwitchToFiber(p.root);p.checkpoint();
}
void Scheduler::park() { impl_->park({}); }
void Scheduler::park_until(std::chrono::steady_clock::time_point deadline) { impl_->park(deadline); }
void Scheduler::unpark(TaskId id) {
    auto &p=*impl_;p.check();auto &task=p.find(id);
    if (terminal(task.state)) return;
    task.park_permit = true;
    if (task.state==State::parked) task.state=State::runnable;
}
void Scheduler::cancel(TaskId id) {
    auto &p=*impl_;p.check();auto &task=p.find(id);
    if (terminal(task.state)) return;
    task.cancelled=true;
    if(task.state==State::sleeping || task.state==State::parked) task.state=State::runnable;
}
void Scheduler::wake(TaskId id) {
    auto &p=*impl_;p.check();auto &task=p.find(id);
    if(task.state==State::sleeping || task.state==State::parked) task.state=State::runnable;
}
std::optional<std::chrono::steady_clock::time_point> Scheduler::next_deadline() const {
    auto &p=*impl_;p.check();std::optional<Impl::Clock::time_point> next;
    for(const auto &task:p.tasks)
        if(task && (task->state==State::sleeping || (task->state==State::parked && task->park_timed)) &&
            (!next || task->deadline<*next)) next=task->deadline;
    return next;
}
void Scheduler::release(TaskId id) {
    auto &p=*impl_;p.external();auto &task=p.find(id);
    if(!terminal(task.state)) bad("AETHER_SCHEDULER_STATE", "Only terminal contexts may be released");
    for(auto &slot:p.tasks) if(slot.get()==&task) {DeleteFiber(task.fiber);slot.reset();return;}
}
void Scheduler::close() {
    auto &p=*impl_;p.external();if(p.close_complete)return;p.closed=true;
    for(auto &task:p.tasks) if(task && !terminal(task->state)) task->cancelled=true;
    // At most one resume per retained context. Cooperative cancellation must unwind
    // directly to entry; a callback that never checkpoints requires the process watchdog.
    for(auto &task:p.tasks) if(task && !terminal(task->state)) {
        p.resume(*task);
        if(!terminal(task->state)) std::terminate();
    }
    if(p.priority_changed && !SetThreadPriority(GetCurrentThread(),p.initial_priority))
        bad("AETHER_SCHEDULER_PRIORITY", "Cannot restore original owner priority while closing scheduler");
    p.root_priority=0;
    p.close_complete=true;
}
void Scheduler::set_current_priority(std::int32_t nice) {
    auto &p=*impl_;p.check();
    if(p.closed)bad("AETHER_SCHEDULER_CLOSED", "Priority changes are closed");
    if(!host::priority_profile_supported(nice))bad("AETHER_SCHEDULER_PRIORITY_UNSUPPORTED", "Only normal and background Android priority profiles are implemented");
    const auto target=*host::priority_profile_target(p.initial_priority,nice);
    if(!SetThreadPriority(GetCurrentThread(),target))
        bad("AETHER_SCHEDULER_PRIORITY", "Cannot apply Android priority profile to the calling Win32 thread");
    (p.running?p.running->priority:p.root_priority)=nice;
    p.priority_changed=true;
}
int Scheduler::priority_baseline() const {impl_->check();return impl_->initial_priority;}
void Scheduler::bind_process_state(std::shared_ptr<ProcessState> state) {
    auto &p=*impl_;p.check();
    if(!state)bad("AETHER_SCHEDULER_PROCESS_STATE","Missing process state");
    if(p.process)p.process->checkpoint();
    p.process=std::move(state);
}
std::int32_t Scheduler::current_priority() const {
    const auto &p=*impl_;p.check();return p.running?p.running->priority:p.root_priority;
}
Scheduler::TaskId Scheduler::execution_token() noexcept { return active_task; }
Scheduler::TaskId Scheduler::current() const {impl_->check();return impl_->running?impl_->running->id:0;}
bool Scheduler::contains(TaskId id) const {impl_->check();for(const auto &task:impl_->tasks)if(task&&task->id==id)return true;return false;}
Scheduler::State Scheduler::state(TaskId id) const {impl_->check();return impl_->find(id).state;}
std::exception_ptr Scheduler::exception(TaskId id) const {impl_->check();return impl_->find(id).failure;}
std::size_t Scheduler::size() const {impl_->check();std::size_t count=0;for(const auto &task:impl_->tasks)if(task)++count;return count;}
} // namespace aether::dex
