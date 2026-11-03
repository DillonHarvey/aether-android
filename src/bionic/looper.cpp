#include "looper.hpp"
#include "descriptors.hpp"
#include "signals.hpp"
#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <bit>
#include <chrono>
#include <deque>
#include <limits>
#include <map>
#include <thread>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
using Clock = std::chrono::steady_clock;
constexpr std::int32_t wake_result = -1, callback_result = -2, timeout_result = -3, error_result = -4;
constexpr std::uint64_t callback_limit = 1'000'000, first_handle = 0xa10f00000001ULL;
std::uint64_t signed_result(std::int32_t value) { return static_cast<std::uint64_t>(static_cast<std::int64_t>(value)); }
std::int32_t integer(std::uint64_t value) { return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)); }
template<std::size_t N> std::array<std::uint8_t, N> encoded(std::uint64_t value) {
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i) bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
    return bytes;
}
struct Failure { Fault fault; std::string_view reason; };
[[noreturn]] void fail(Fault fault, std::string_view reason) { throw Failure{fault, reason}; }
} // namespace

struct NativeLooper::Attachment::State {
    NativeLooper::Impl *owner = nullptr;
    std::uint64_t loop = 0, sequence = 0;
    int fd = -1;
    bool active = false;
    ~State();
};
struct NativeLooper::Impl {
    struct Watch {
        int fd = -1;
        std::int32_t ident = 0;
        std::uint32_t events = 0;
        Address callback = 0, data = 0;
        std::uint64_t sequence = 0;
        std::weak_ptr<const void> description;
        bool source = false;
        std::weak_ptr<Attachment::State> attachment;
    };
    struct Response {
        int fd = -1;
        std::int32_t ident = 0;
        std::uint32_t events = 0;
        Address callback = 0, data = 0;
        std::uint64_t sequence = 0;
        bool source = false;
        std::weak_ptr<Attachment::State> attachment;
    };
    struct Loop {
        std::weak_ptr<a64::ThreadRegisterState> owner;
        bool implicit = true, allow_non_callbacks = false, wake = false;
        std::uint32_t references = 0, polling = 0, source_references = 0;
        std::map<int, Watch> watches;
        std::deque<Response> responses;
    };
    struct Outputs { Address fd = 0, events = 0, data = 0; };
    struct DeferredPoll final : a64::DeferredService {
        Impl &p;
        std::shared_ptr<a64::ThreadRegisterState> owner;
        Address tls,stack_top;std::uint32_t tid;
        std::uint64_t invocation,handle,budget;
        std::int32_t timeout;Outputs out;Clock::time_point until;
        bool all,reserved=false;
        DeferredPoll(Impl &,std::string_view,const a64::ServiceState &,std::uint64_t,
                     std::shared_ptr<a64::ThreadRegisterState>);
        ~DeferredPoll() override;
        bool ready() const noexcept override;
        std::optional<Clock::time_point> deadline() const noexcept override;
        a64::DeferredServiceResult resume(a64::ServiceState &) noexcept override;
    };
    a64::GuestMemory &memory;
    NativeThreads &threads;
    NativeDescriptors &descriptors;
    NativeSignals &signals;
    const a64::AppContext &app;
    const std::thread::id host_owner = std::this_thread::get_id();
    GuestPosixServices::PhdrRunner run;
    std::map<std::uint64_t, Loop> loops;
    std::uint64_t next_handle = first_handle, next_sequence = 1;
    std::uint64_t *active_budget = nullptr;
    unsigned depth = 0;
    std::string_view error;
    Impl(a64::GuestMemory &space, NativeThreads &owners, NativeDescriptors &files,
         NativeSignals &pending, const a64::AppContext &context)
        : memory(space), threads(owners), descriptors(files), signals(pending), app(context) {}

    void terminal() const {
        if (!app.process_state) fail(Fault::invalid_call, "ALooper: process state is unavailable");
        if (app.process_state->exit_status()) fail(Fault::process_exit, "ALooper: process has terminated");
        if (threads.exit_value(threads.tls())) fail(Fault::thread_exit, "ALooper: logical thread has terminated");
    }
    void prune() {
        for (auto it = loops.begin(); it != loops.end();) {
            if (it->second.implicit) {
                const auto owner = it->second.owner.lock();
                if (!owner || !threads.register_owner_live(owner)) it->second.implicit = false;
            }
            if (!it->second.implicit && !it->second.references && !it->second.polling && !it->second.source_references) it = loops.erase(it);
            else ++it;
        }
    }
    std::shared_ptr<a64::ThreadRegisterState> current_owner() const {
        const auto owner = threads.thread_register_state(threads.tls());
        if (!owner || !threads.register_owner_live(owner))
            fail(Fault::invalid_call, "ALooper: current trusted thread incarnation is unavailable");
        return owner;
    }
    std::uint64_t current(const std::shared_ptr<a64::ThreadRegisterState> &owner) const {
        for (const auto &[handle, loop] : loops)
            if (loop.implicit && loop.owner.lock() == owner) return handle;
        return 0;
    }
    Loop &loop(std::uint64_t handle) {
        const auto found = loops.find(handle);
        if (found == loops.end() || (!found->second.implicit && !found->second.references && !found->second.source_references))
            fail(Fault::invalid_call, "ALooper: stale or foreign native looper handle");
        return found->second;
    }
    void binding(const std::shared_ptr<a64::ThreadRegisterState> &owner, Address tls, std::uint32_t tid) const {
        terminal();
        if (threads.tid() != tid || threads.tls() != tls || threads.thread_register_state(tls) != owner ||
            !threads.register_owner_live(owner))
            fail(Fault::invalid_call, "ALooper: guest reentry changed the trusted thread incarnation");
    }
    void outputs(const Outputs &out) const {
        if ((out.fd && !memory.accessible(out.fd, 4, a64::Permission::write)) ||
            (out.events && !memory.accessible(out.events, 4, a64::Permission::write)) ||
            (out.data && !memory.accessible(out.data, 8, a64::Permission::write)))
            fail(Fault::write, "ALooper: poll output is outside writable guest memory");
    }
    void publish(a64::ServiceState &state, const Outputs &out, std::int32_t result,
                 const Response *response = nullptr) {
        outputs(out); // Reentry can free a formerly valid destination.
        const auto fd = response ? static_cast<std::uint32_t>(response->fd) : 0U;
        const auto events = response ? response->events : 0U;
        const auto data = response ? response->data : Address{0};
        if ((out.fd && !memory.write(out.fd, encoded<4>(fd))) ||
            (out.events && !memory.write(out.events, encoded<4>(events))) ||
            (out.data && !memory.write(out.data, encoded<8>(data))))
            fail(Fault::write, "ALooper: poll output publication failed");
        state.registers[0] = signed_result(result);
    }
    void remove_sequence(std::uint64_t handle, int fd, std::uint64_t sequence) {
        const auto found = loops.find(handle);
        if (found == loops.end()) return;
        const auto watch = found->second.watches.find(fd);
        if (watch != found->second.watches.end() && watch->second.sequence == sequence)
            found->second.watches.erase(watch);
    }
    bool source_live(const std::weak_ptr<Attachment::State> &token, int fd, std::uint64_t sequence) const noexcept {
        const auto source = token.lock();
        if (!source || !source->active || source->owner != this || source->fd != fd || source->sequence != sequence) return false;
        const auto found = loops.find(source->loop);
        if (found == loops.end()) return false;
        const auto watch = found->second.watches.find(fd);
        return watch != found->second.watches.end() && watch->second.sequence == sequence &&
               watch->second.source && watch->second.attachment.lock() == source;
    }
    bool source_response(Response &response) const noexcept {
        if (!response.source) return true;
        // Detach/replacement retires an epoch. Closing/reusing its descriptor
        // instead produces one real INVALID response for the still-live epoch.
        if (!source_live(response.attachment, response.fd, response.sequence)) return false;
        const auto source = response.attachment.lock();
        const auto &watch = loops.find(source->loop)->second.watches.find(response.fd)->second;
        const auto original = watch.description.lock();
        const auto current = descriptors.poll_identity(response.fd);
        if (!original || !current || original != current) response.events = 16;
        return true;
    }
    void detach(Attachment::State &source) noexcept {
        if (!source.active) return;
        if (host_owner != std::this_thread::get_id() || source.owner != this) std::terminate();
        source.active = false;
        const auto found = loops.find(source.loop);
        if (found == loops.end() || !found->second.source_references) std::terminate();
        remove_sequence(source.loop, source.fd, source.sequence);
        auto &responses = found->second.responses;
        std::erase_if(responses, [&](const Response &response) {
            return response.source && response.fd == source.fd && response.sequence == source.sequence;
        });
        --found->second.source_references;
    }
    std::uint32_t ready(const Watch &watch) const {
        if (watch.source && !source_live(watch.attachment, watch.fd, watch.sequence)) return 0;
        const auto original = watch.description.lock();
        const auto current_description = descriptors.poll_identity(watch.fd);
        if (!original || !current_description || original != current_description) return 16;
        const auto wanted = static_cast<std::uint16_t>(((watch.events & 1) ? 1 : 0) |
            ((watch.events & 2) ? 4 : 0) | 8 | 16 | 32);
        const auto actual = descriptors.readiness(watch.fd, wanted);
        return ((actual & 1) ? 1U : 0U) | ((actual & 4) ? 2U : 0U) |
               ((actual & 8) ? 4U : 0U) | ((actual & 16) ? 8U : 0U) | ((actual & 32) ? 16U : 0U);
    }
    void debit(std::uint64_t before, std::uint64_t ticks) {
        if (!active_budget || ticks > before)
            fail(Fault::budget, "ALooper: callback or peer exceeded the shared guest budget");
        // A nested native poll has already charged its portion. Inclusive CPU
        // ticks cover that portion too; debit only the remainder once.
        const auto nested = before - *active_budget;
        const auto extra = ticks > nested ? ticks - nested : 0;
        if (extra > *active_budget) fail(Fault::budget, "ALooper: shared guest budget exhausted");
        *active_budget -= extra;
    }
    bool callback(Response response, std::uint64_t handle, a64::ServiceState &state,
                  const std::shared_ptr<a64::ThreadRegisterState> &owner, Address tls, std::uint32_t tid) {
        if (!source_response(response)) return false;
        binding(owner, tls, tid);
        if (!run) fail(Fault::unsupported_service, "ALooper: owned callback runner is unavailable");
        if (!*active_budget) fail(Fault::budget, "ALooper: shared callback budget exhausted");
        if (response.callback % 4 || !memory.accessible(response.callback, 4, a64::Permission::execute))
            fail(Fault::execute, "ALooper: callback is not aligned executable guest code");
        const auto stack = state.stack_pointer;
        if (stack < 16 || stack % 16 || !state.stack_top || stack > state.stack_top ||
            !memory.accessible(stack - 16, 16, a64::Permission::write))
            fail(Fault::write, "ALooper: callback requires the current aligned writable guest stack");
        const auto runner = run; // Reentrant setup cannot replace this call's function.
        const auto before = *active_budget;
        const auto result = runner(response.callback,
            {static_cast<std::uint64_t>(response.fd), response.events, response.data}, stack, tls, before);
        binding(owner, tls, tid); // Terminal precedence wins over returned values.
        if (result.result.fault != Fault::none) fail(result.result.fault, "ALooper: guest callback failed");
        if (!result.result.returned) fail(Fault::invalid_call, "ALooper: guest callback did not return");
        debit(before, result.ticks);
        if (integer(result.result.registers[0]) == 0 || (response.source && (response.events & 16)))
            remove_sequence(handle, response.fd, response.sequence);
        return true;
    }
    bool poll_step(std::string_view name, a64::ServiceState &state, bool full_frame,
                   std::uint64_t handle, std::int32_t timeout, Clock::time_point deadline, const Outputs &out,
                   const std::shared_ptr<a64::ThreadRegisterState> &owner, Address tls, std::uint32_t tid, bool cooperative=false) {
        outputs(out);
        for (;;) {
            binding(owner, tls, tid);
            // Pending responses came from a completed earlier readiness batch.
            // Return one without consuming a wake belonging to the next batch.
            if (!loops.at(handle).responses.empty()) {
                auto response = loops.at(handle).responses.front();
                if (!source_response(response)) {
                    loops.at(handle).responses.pop_front();
                    continue;
                }
                publish(state, out, response.ident, &response);
                loops.at(handle).responses.pop_front();
                if (response.source && (response.events & 16)) remove_sequence(handle, response.fd, response.sequence);
                return true;
            }
            std::array<Response, 256> batch{};
            std::size_t count = 0;
            bool callbacks = false;
            for (const auto &[fd, watch] : loops.at(handle).watches) {
                (void)fd;
                const auto events = ready(watch);
                if (!events) continue;
                batch[count++] = {watch.fd, watch.ident, events, watch.callback, watch.data, watch.sequence,
                                  watch.source, watch.attachment};
                callbacks |= watch.callback != 0;
            }
            if (callbacks && !full_frame)
                fail(Fault::unsupported_service, "ALooper: callbacks require a trusted full service frame");
            const bool woke = loops.at(handle).wake;
            if (count || woke) {
                // Consume exactly the wake observed before callback reentry.
                // A callback can publish a fresh wake for a later poll.
                loops.at(handle).wake = false;
                for (std::size_t i = 0; i < count; ++i)
                    if ((batch[i].events & 16) && !batch[i].source) remove_sequence(handle, batch[i].fd, batch[i].sequence);
                bool delivered_callbacks = false;
                for (std::size_t i = 0; i < count; ++i)
                    if (batch[i].callback) delivered_callbacks |= callback(batch[i], handle, state, owner, tls, tid);
                // No borrowed watch/map references survive guest execution. A
                // replacement made during a callback does not rewrite this batch.
                for (std::size_t i = 0; i < count; ++i)
                    if (!batch[i].callback && source_response(batch[i])) loops.at(handle).responses.push_back(batch[i]);
                if (!loops.at(handle).responses.empty()) continue;
                if (delivered_callbacks) {
                    if (name == "ALooper_pollAll") {
                        if (timeout > 0 && Clock::now() >= deadline) {
                            publish(state, out, timeout_result);
                            return true;
                        }
                        // A child batch is a completed effect. Account and
                        // offer its CPU boundary before processing another batch.
                        if(cooperative)return false;
                        continue;
                    }
                    publish(state, out, callback_result);
                    return true;
                }
                if (!woke) continue; // A retired source did not produce a callback or a wake.
                publish(state, out, wake_result);
                return true;
            }
            if (timeout == 0 || (timeout > 0 && Clock::now() >= deadline)) {
                publish(state, out, timeout_result); return true;
            }
            if (!full_frame)
                fail(Fault::unsupported_service, "ALooper: blocking requires a trusted full service frame");
            if (signals.ready()) {
                const auto deliveries = signals.delivery_serial();
                const auto signal = signals.io_interruption();
                const bool framed = signal && signals.io_frame_ready(*signal,state);
                if (framed) publish(state, out, wake_result);
                const auto fault = (signal?signals.deliver_pending(state,true,std::uint64_t{1}<<(signal->signal-1)):Fault::none);
                if (fault != Fault::none) fail(fault, "ALooper: signal delivery failed");
                if (state.resume) return true;
                binding(owner, tls, tid);
                if (signals.delivery_serial() != deliveries) {
                    if (!framed) publish(state, out, wake_result);
                    return true;
                }
            }
            return false;
        }
    }
    Fault poll(std::string_view name, a64::ServiceState &state, bool full_frame, bool allow_deferred) {
        const auto timeout = integer(state.registers[0]);
        const Outputs out{state.registers[1], state.registers[2], state.registers[3]};
        outputs(out);
        const auto owner = current_owner();
        const auto tls = threads.tls();
        const auto tid = threads.tid();
        const auto handle = current(owner);
        if (!handle) { publish(state, out, error_result); return Fault::none; }
        if (loops.at(handle).polling)
            fail(Fault::unsupported_service, "ALooper: recursive polling of the same looper is unsupported");
        if (depth >= 8) fail(Fault::nesting_limit, "ALooper: nested polling exceeds eight logical loopers");
        if (full_frame && state.trusted_tls != tls)
            fail(Fault::invalid_call, "ALooper: poll frame has a different trusted TLS binding");
        if(threads.factory_execution_active()) {
            if(!full_frame || !allow_deferred || !state.invocation)
                fail(Fault::unsupported_service,"ALooper: child wait requires an admitted deferred service");
            state.deferred=std::make_shared<DeferredPoll>(*this,name,state,handle,owner);
            return Fault::none;
        }
        const auto started = Clock::now();
        const auto deadline = started + std::chrono::milliseconds(timeout > 0 ? timeout : 0);
        std::uint64_t own_budget = full_frame ? state.operation_allowance(callback_limit) : 0;
        const auto previous_budget = active_budget;
        if (!active_budget) active_budget = &own_budget;
        else if (full_frame) *active_budget = state.operation_allowance(*active_budget);
        ++depth;
        ++loops.at(handle).polling;
        struct Scope {
            Impl &p; std::uint64_t handle; std::uint64_t *previous;
            ~Scope() {
                const auto found = p.loops.find(handle);
                if (found != p.loops.end()) --found->second.polling;
                --p.depth; p.active_budget = previous; p.prune();
            }
        } scope{*this, handle, previous_budget};
        for (;;) {
            if (poll_step(name,state,full_frame,handle,timeout,deadline,out,owner,tls,tid)) return Fault::none;
            if (threads.has_runnable()) {
                if (!*active_budget) fail(Fault::budget, "ALooper: peer progress budget exhausted");
                const auto before = *active_budget;
                std::uint64_t spent = 0;
                const auto fault = threads.run_next(before, spent);
                binding(owner, tls, tid);
                if (fault != Fault::none) return fault;
                debit(before, spent);
                continue;
            }
            const auto alarm = signals.alarm_deadline();
            if (timeout < 0 && !alarm)
                fail(Fault::unsupported_service,
                     "ALooper: indefinite wait has no runnable producer or alarm in the cooperative profile");
            std::this_thread::sleep_until(timeout < 0 ? *alarm : (alarm ? (std::min)(deadline, *alarm) : deadline));
        }
    }
};

NativeLooper::Impl::DeferredPoll::DeferredPoll(Impl &p,std::string_view name,const a64::ServiceState &state,
    std::uint64_t handle,std::shared_ptr<a64::ThreadRegisterState> owner):
    p(p),owner(std::move(owner)),tls(state.trusted_tls),stack_top(state.stack_top),tid(p.threads.tid()),
    invocation(state.invocation),handle(handle),budget(state.operation_allowance(callback_limit)),
    timeout(integer(state.registers[0])),out{state.registers[1],state.registers[2],state.registers[3]},
    until(Clock::now()+std::chrono::milliseconds(timeout>0?timeout:0)),all(name=="ALooper_pollAll") {}
NativeLooper::Impl::DeferredPoll::~DeferredPoll() {
    if(reserved) {
        const auto found=p.loops.find(handle);
        if(found!=p.loops.end() && found->second.polling)--found->second.polling;
        p.prune();
    }
}
bool NativeLooper::Impl::DeferredPoll::ready() const noexcept {
    if(!p.app.process_state || p.app.process_state->exit_status() || !p.threads.signal_snapshot(tid,owner))return true;
    const auto found=p.loops.find(handle);
    if(found==p.loops.end() || !found->second.implicit || found->second.owner.lock()!=owner)return true;
    if(!reserved || found->second.wake || !found->second.responses.empty())return true;
    if(timeout==0 || (timeout>0 && Clock::now()>=until) || p.signals.wait_ready(tid,owner))return true;
    try {
        for(const auto &[fd,watch]:found->second.watches){(void)fd;if(p.ready(watch))return true;}
    } catch(...) {return true;} // Authoritative resume reports an immediate query error.
    return false;
}
std::optional<Clock::time_point> NativeLooper::Impl::DeferredPoll::deadline() const noexcept {
    if(!p.threads.signal_snapshot(tid,owner))return {};
    auto next=timeout>=0?std::optional<Clock::time_point>{until}:std::nullopt;
    const auto alarm=p.signals.wait_deadline(tid,owner);
    if(alarm && (!next || *alarm<*next))next=alarm;
    return next;
}
a64::DeferredServiceResult NativeLooper::Impl::DeferredPoll::resume(a64::ServiceState &state) noexcept {
    try {
        p.binding(owner,tls,tid);
        if(state.trusted_tls!=tls || state.invocation!=invocation || state.stack_top!=stack_top ||
           p.current(owner)!=handle)
            fail(Fault::invalid_call,"ALooper: deferred poll frame or association changed");
        if(p.depth || p.active_budget)
            fail(Fault::unsupported_service,"ALooper: deferred poll resumed inside an active callback scope");
        p.outputs(out);
        if(!reserved){
            auto &loop=p.loops.at(handle);
            if(loop.polling)fail(Fault::unsupported_service,"ALooper: recursive deferred polling is unsupported");
            ++loop.polling;reserved=true;
        }
        budget=state.operation_allowance(budget);
        // Only the reservation survives an incomplete step. No global callback
        // depth or pointer into this operation remains installed while parked.
        p.active_budget=&budget;++p.depth;
        struct Scope {
            Impl &p;
            ~Scope(){--p.depth;p.active_budget=nullptr;}
        } scope{p};
        const bool complete=p.poll_step(all?"ALooper_pollAll":"ALooper_pollOnce",state,true,
                                        handle,timeout,until,out,owner,tls,tid,true);
        return {Fault::none,complete};
    } catch(const Failure &failure){p.error=failure.reason;return {failure.fault,true};}
    catch(const ThreadExit &exit){p.threads.request_exit(exit.value);return {Fault::thread_exit,true};}
    catch(const ProcessExit &exit){
        if(exit.signal)p.app.process_state->request_signal(exit.signal);else p.app.process_state->request_exit(exit.status);
        return {Fault::process_exit,true};
    } catch(...) {
        if(p.app.process_state && p.app.process_state->exit_status())return {Fault::process_exit,true};
        if(p.threads.exit_value(tls))return {Fault::thread_exit,true};
        p.error="ALooper: deferred poll host operation failed";return {Fault::unsupported_service,true};
    }
}

NativeLooper::NativeLooper(a64::GuestMemory &memory, NativeThreads &threads, NativeDescriptors &descriptors,
                           NativeSignals &signals, const a64::AppContext &app)
    : impl_(std::make_unique<Impl>(memory, threads, descriptors, signals, app)) {}
NativeLooper::~NativeLooper() = default;
NativeLooper::Attachment::State::~State() { if (active) owner->detach(*this); }
NativeLooper::Attachment::~Attachment() = default;
NativeLooper::Attachment::Attachment(Attachment &&) noexcept = default;
NativeLooper::Attachment &NativeLooper::Attachment::operator=(Attachment &&) noexcept = default;
NativeLooper::Attachment NativeLooper::attach_source(std::uint64_t handle, int fd, std::int32_t ident,
                                                    Address callback, Address data) {
    auto &p = *impl_;
    if (p.host_owner != std::this_thread::get_id())
        throw a64::GuestError("AETHER_INPUT_LOOPER", "Input attachment requires the owning host thread");
    try {
        p.terminal();
        p.prune();
        auto &loop = p.loop(handle);
        if ((!callback && (ident < 0 || !loop.allow_non_callbacks)) ||
            (callback && (callback % 4 || !p.memory.accessible(callback, 4, a64::Permission::execute))))
            fail(Fault::invalid_call, "input queue: invalid Looper ident, options or callback");
        const auto description = p.descriptors.poll_identity(fd);
        if (!description) fail(Fault::invalid_call, "input queue: its readiness descriptor is stale");
        if (loop.source_references >= 4096 || (!loop.watches.contains(fd) && loop.watches.size() >= 256) ||
            p.next_sequence == (std::numeric_limits<std::uint64_t>::max)())
            fail(Fault::unsupported_service, "input queue: Looper attachment capacity exhausted");
        auto source = std::make_shared<Attachment::State>();
        source->owner = &p; source->loop = handle; source->fd = fd; source->sequence = p.next_sequence++;
        Impl::Watch watch{fd, callback ? callback_result : ident, 1, callback, data, source->sequence,
                          description, true, source};
        loop.watches.insert_or_assign(fd, std::move(watch));
        ++loop.source_references;
        source->active = true;
        Attachment result; result.state_ = std::move(source);
        return result;
    } catch (const Failure &failure) {
        p.error = failure.reason;
        throw a64::GuestError("AETHER_INPUT_LOOPER", std::string(failure.reason));
    }
}
void NativeLooper::detach_source(Attachment &source) noexcept {
    if (source.state_) {
        impl_->detach(*source.state_);
        source.state_.reset();
    }
}
void NativeLooper::runner(GuestPosixServices::PhdrRunner run) { impl_->run = std::move(run); }
std::string_view NativeLooper::rejection() const noexcept { return impl_->error; }
Fault NativeLooper::invoke(std::string_view name, a64::ServiceState &state, bool full_frame, bool allow_deferred) noexcept {
    auto &p = *impl_;
    if (p.host_owner != std::this_thread::get_id()) return Fault::invalid_call;
    p.error = {};
    try {
        p.terminal();
        p.prune();
        auto &r = state.registers;
        if (name == "ALooper_prepare" || name == "ALooper_forThread") {
            const auto owner = p.current_owner();
            const auto existing = p.current(owner);
            if (existing || name == "ALooper_forThread") { r[0] = existing; return Fault::none; }
            const auto options = static_cast<std::uint32_t>(r[0]);
            if (options & ~1U) fail(Fault::unsupported_service, "ALooper: unsupported prepare options");
            if (p.loops.size() >= 64 || p.next_handle == (std::numeric_limits<std::uint64_t>::max)())
                fail(Fault::unsupported_service, "ALooper: finite looper identity capacity exhausted");
            Impl::Loop loop;
            loop.owner = owner;
            loop.allow_non_callbacks = (options & 1U) != 0;
            const auto handle = p.next_handle++;
            p.loops.emplace(handle, std::move(loop));
            r[0] = handle;
            return Fault::none;
        }
        if (name == "ALooper_pollOnce" || name == "ALooper_pollAll") return p.poll(name, state, full_frame,allow_deferred);
        const auto handle = r[0];
        if (name == "ALooper_acquire") {
            auto &loop = p.loop(handle);
            if (loop.references >= 4096) fail(Fault::unsupported_service, "ALooper: external reference bound exceeded");
            ++loop.references; return Fault::none;
        }
        if (name == "ALooper_release") {
            auto &loop = p.loop(handle);
            if (!loop.references) fail(Fault::invalid_call, "ALooper: release has no matching acquired reference");
            --loop.references; p.prune(); return Fault::none;
        }
        if (name == "ALooper_wake") { p.loop(handle).wake = true; return Fault::none; }
        if (name == "ALooper_removeFd") {
            r[0] = p.loop(handle).watches.erase(integer(r[1])) ? 1 : 0;
            return Fault::none;
        }
        if (name == "ALooper_addFd") {
            const auto fd = integer(r[1]);
            auto ident = integer(r[2]);
            const auto events = static_cast<std::uint32_t>(r[3]);
            const auto callback = r[4], data = r[5];
            auto &loop = p.loop(handle);
            if ((events & ~31U) || (!callback && (ident < 0 || !loop.allow_non_callbacks))) {
                r[0] = signed_result(-1); return Fault::none;
            }
            const auto description = p.descriptors.poll_identity(fd);
            if (!description) { r[0] = signed_result(-1); return Fault::none; }
            if (callback) ident = callback_result;
            if ((!loop.watches.contains(fd) && loop.watches.size() >= 256) ||
                p.next_sequence == (std::numeric_limits<std::uint64_t>::max)())
                fail(Fault::unsupported_service, "ALooper: watch or registration sequence capacity exhausted");
            Impl::Watch watch{fd, ident, events, callback, data, p.next_sequence++, description, false, {}};
            loop.watches.insert_or_assign(fd, std::move(watch));
            r[0] = 1;
            return Fault::none;
        }
        fail(Fault::unsupported_service, "ALooper: unregistered operation");
    } catch (const Failure &failure) {
        p.error = failure.reason; return failure.fault;
    } catch (const ThreadExit &exit) {
        p.threads.request_exit(exit.value);
        p.error = "ALooper: guest exited its logical thread"; return Fault::thread_exit;
    } catch (const ProcessExit &exit) {
        if (p.app.process_state) {
            if (exit.signal) p.app.process_state->request_signal(exit.signal);
            else p.app.process_state->request_exit(exit.status);
        }
        p.error = "ALooper: guest exited the process"; return Fault::process_exit;
    } catch (...) {
        if (p.app.process_state && p.app.process_state->exit_status()) return Fault::process_exit;
        if (p.threads.exit_value(p.threads.tls())) return Fault::thread_exit;
        p.error = "ALooper: host allocation or internal operation failed"; return Fault::unsupported_service;
    }
}
bool NativeLooper::switch_safe() const noexcept { return impl_->depth==0 && !impl_->active_budget; }
} // namespace aether::bionic
