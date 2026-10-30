#include "aether/security/activity_dispatcher.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/host/windows/clipboard_service.hpp"
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ACTIVITY_DISPATCH: ") + message);
}
struct Request {
    std::uint64_t ticket;
    ActivityCommand command;
    std::optional<host::PreparedDocumentSource> document;
    std::optional<std::u16string> text;
};
} // namespace
struct ActivityDispatcher::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    const std::shared_ptr<host::ClipboardWindowContext> clipboard_window =
        std::make_shared<host::ClipboardWindowContext>();
    host::UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::deque<Request> requests;
    std::vector<ActivityCompletion> completions;
    std::shared_ptr<const android::TextEditObservation> text_edit_observation;
    std::uint64_t text_edit_receipt = 0;
    std::uint64_t active_request_ticket = 0, text_edit_ticket = 0;
    bool text_edit_claimed = false;
    std::shared_ptr<const android::SoftInputObservation> soft_input_observation;
    std::uint64_t soft_input_receipt = 0, soft_input_ticket = 0, last_soft_input_revision = 0;
    std::uint64_t active_soft_input_revision = 0;
    dex::ObjectId active_soft_input_view = 0;
    ActivityCommandKind active_request_kind = ActivityCommandKind::refresh;
    bool soft_input_claimed = false, soft_input_accepted = false;
    std::shared_ptr<const ActivityTerminalActivationCustody> terminal_activations;
    std::uint64_t terminal_activation_receipt = 0;
    bool terminal_activation_claimed = false, terminal_activation_received = false, terminal_activation_receipted = false;
    ActivityPublication pending, visible;
    ActivityDispatchMetrics metrics;
    std::map<dex::ObjectId, std::uint64_t> text_edit_cursors;
    std::uint64_t last_text_edit_sequence = 0;
    std::uint64_t last_streamed_text_edit_revision = 0;
    std::uint64_t last_view_activation_revision = 0;
    std::size_t pending_view_activation_count = 0; // Protected by mailbox mutex.
    struct TextMutationCursor {
        std::uint64_t buffer_revision = 0, revision = 0;
    };
    std::map<dex::ObjectId, TextMutationCursor> text_mutation_cursors;
    std::exception_ptr failure;
    IsolatedActivity *active = nullptr; // Protected by mutex; only cancel crosses threads.
    std::uint64_t next = 1, outstanding = 0, read_ticket = 0;
    bool stopping = false, closing = false, read_failed = false;
    HWND notification_window = nullptr;
    UINT notification_message = 0;
    bool notification_posted = false;
    std::jthread io;
    Impl() { require(static_cast<bool>(event), "Cannot create completion event"); }
    void check_owner() const { require(std::this_thread::get_id() == owner, "Wrong UI owner thread"); }
    void notify() {
        require(SetEvent(event.get()) != FALSE, "Cannot signal completion event");
        if (notification_window && !notification_posted) {
            require(PostMessageW(notification_window, notification_message, 0, 0) != FALSE,
                    "Cannot post completion notification");
            notification_posted = true;
        }
    }
    void abort() noexcept {
        std::lock_guard lock(mutex);
        stopping = true;
        clipboard_window->close();
        active_request_ticket = 0;
        requests.clear();
        if (active)
            active->cancel();
        wake.notify_all();
    }
    ~Impl() {
        abort();
        if (io.joinable())
            io.join();
    }
    void collect_view_activations(const ActivityState &snapshot, ActivityCompletion &completion) {
        require(snapshot.view_activation_revision >= last_view_activation_revision,
                "View activation revision regressed");
        auto cursor = last_view_activation_revision;
        for (const auto &activation : snapshot.view_activations) {
            if (activation.revision <= cursor) continue; // Repeated immutable snapshot.
            require(cursor != UINT64_MAX && activation.revision == cursor + 1,
                    "View activation history is incomplete");
            completion.view_activations.push_back(activation);
            cursor = activation.revision;
        }
        require(cursor == snapshot.view_activation_revision, "View activation history is incomplete");
        last_view_activation_revision = cursor;
    }
    void collect_text_edits(const ActivityState &snapshot, ActivityCompletion &completion) {
        std::erase_if(text_edit_cursors, [&](const auto &entry) { return !snapshot.views.contains(entry.first); });
        auto highest = last_text_edit_sequence;
        for (const auto &[id, node] : snapshot.views) {
            if (node.kind != android::ViewKind::edit_text) continue;
            auto &seen = text_edit_cursors[id];
            require(node.text_edit_event_revision >= seen, "TextEdit event revision regressed");
            if (seen < node.text_edit_dropped_revision)
                completion.text_edit_gaps.push_back({id, node.text_buffer_revision, node.text_edit_dropped_revision});
            for (const auto &edit_record : node.text_edit_events)
                if (edit_record.revision > seen)
                    completion.text_edit_events.push_back({id, edit_record.buffer_revision, edit_record});
            seen = node.text_edit_event_revision;
            highest = std::max(highest, seen);
        }
        std::sort(completion.text_edit_events.begin(), completion.text_edit_events.end(),
                  [](const auto &left, const auto &right) { return left.event.revision < right.event.revision; });
        auto previous = last_text_edit_sequence;
        for (const auto &edit_record : completion.text_edit_events) {
            require(edit_record.event.revision > previous, "Global TextEdit event order regressed");
            previous = edit_record.event.revision;
        }
        last_text_edit_sequence = highest;
    }
    void collect_text_mutations(const ActivityState &snapshot, ActivityCompletion &completion) {
        std::deque<ActivityTextMutation> mutations;
        std::map<dex::ObjectId, ActivityTextMutationGap> gaps;
        const auto add_gap = [&](dex::ObjectId id, std::uint64_t buffer_revision, std::uint64_t revision) {
            auto &gap = gaps[id];
            gap.view = id;
            gap.buffer_revision = buffer_revision;
            gap.through_revision = std::max(gap.through_revision, revision);
        };
        std::erase_if(text_mutation_cursors, [&](const auto &entry) {
            const auto found = snapshot.views.find(entry.first);
            return found == snapshot.views.end() || found->second.kind != android::ViewKind::edit_text;
        });
        for (const auto &[id, node] : snapshot.views) {
            if (node.kind != android::ViewKind::edit_text) continue;
            auto &cursor = text_mutation_cursors[id];
            require(node.text_buffer_revision && node.text_buffer_revision >= cursor.buffer_revision &&
                        node.text_event_revision >= cursor.revision,
                    "Text mutation identity or revision regressed");
            const auto seen = cursor.buffer_revision == node.text_buffer_revision ? cursor.revision : 0;
            if (seen < node.text_mutation_base_revision)
                add_gap(id, node.text_buffer_revision, node.text_mutation_base_revision);
            for (const auto &mutation : node.text_mutations)
                if (mutation.revision > seen) {
                    if (mutations.size() == 256) {
                        const auto &retired = mutations.front();
                        add_gap(retired.view, retired.buffer_revision, retired.mutation.revision);
                        mutations.pop_front();
                    }
                    mutations.push_back({id, node.text_buffer_revision, mutation});
                }
            cursor = {node.text_buffer_revision, node.text_event_revision};
        }
        completion.text_mutations.reserve(mutations.size());
        for (auto &record : mutations) completion.text_mutations.push_back(std::move(record));
        for (const auto &[id, gap] : gaps) {
            (void)id;
            completion.text_mutation_gaps.push_back(gap);
        }
    }
    // The acknowledgement queue still carries every ticket. Only historical
    // text notifications use bounded retention; gaps never reject guest edits.
    void merge_text_edits(const ActivityState &snapshot, ActivityCompletion &completion) {
        std::vector<ActivityTextEditEvent> events;
        std::map<dex::ObjectId, ActivityTextEditGap> gaps;
        const auto add_gap = [&](ActivityTextEditGap gap) {
            const auto current = snapshot.views.find(gap.view);
            if (current == snapshot.views.end() || current->second.kind != android::ViewKind::edit_text) return;
            gap.buffer_revision = current->second.text_buffer_revision;
            auto &stored = gaps[gap.view];
            stored.view = gap.view;
            stored.buffer_revision = gap.buffer_revision;
            stored.dropped_revision = std::max(stored.dropped_revision, gap.dropped_revision);
        };
        const auto append = [&](ActivityCompletion &batch) {
            for (auto &edit_record : batch.text_edit_events) events.push_back(std::move(edit_record));
            for (const auto &gap : batch.text_edit_gaps) add_gap(gap);
            batch.text_edit_events.clear();
            batch.text_edit_gaps.clear();
        };
        for (auto &pending_completion : completions) append(pending_completion);
        append(completion);
        std::sort(events.begin(), events.end(), [](const auto &left, const auto &right) {
            return left.event.revision < right.event.revision;
        });
        std::erase_if(events, [&](const auto &edit_record) {
            const auto current = snapshot.views.find(edit_record.view);
            // Historical payloads belong to this logical View, not its latest
            // backing Editable. Positional mutation records remain separate.
            return current == snapshot.views.end() || current->second.kind != android::ViewKind::edit_text;
        });
        std::size_t units = 0;
        for (const auto &edit_record : events) units += edit_record.event.text.size();
        std::size_t removed = 0;
        while (events.size() - removed > 256 || units > 65536) {
            const auto &edit_record = events[removed++];
            units -= edit_record.event.text.size();
            add_gap({edit_record.view, edit_record.buffer_revision, edit_record.event.revision});
        }
        events.erase(events.begin(), events.begin() + static_cast<std::ptrdiff_t>(removed));
        completion.text_edit_events = std::move(events);
        for (const auto &[id, gap] : gaps) {
            (void)id;
            completion.text_edit_gaps.push_back(gap);
        }
    }
    void merge_text_mutations(const ActivityState &snapshot, ActivityCompletion &completion) {
        std::deque<ActivityTextMutation> mutations;
        std::map<dex::ObjectId, ActivityTextMutationGap> gaps;
        const auto current_buffer = [&](dex::ObjectId id, std::uint64_t buffer_revision) {
            const auto found = snapshot.views.find(id);
            return found != snapshot.views.end() && found->second.kind == android::ViewKind::edit_text &&
                found->second.text_buffer_revision == buffer_revision;
        };
        const auto add_gap = [&](ActivityTextMutationGap gap) {
            if (!current_buffer(gap.view, gap.buffer_revision)) return;
            require(gap.through_revision && gap.through_revision <= snapshot.views.at(gap.view).text_event_revision,
                    "Invalid text mutation delivery gap");
            auto &stored = gaps[gap.view]; // At most the current 256 View identities.
            stored.view = gap.view;
            stored.buffer_revision = gap.buffer_revision;
            stored.through_revision = std::max(stored.through_revision, gap.through_revision);
        };
        const auto append = [&](ActivityCompletion &batch) {
            for (const auto &gap : batch.text_mutation_gaps) add_gap(gap);
            for (auto &record : batch.text_mutations) {
                // A retired View/backing buffer cannot be retargeted to the
                // current document, even when its text happens to be equal.
                if (!current_buffer(record.view, record.buffer_revision)) continue;
                if (mutations.size() == 256) {
                    const auto &retired = mutations.front();
                    add_gap({retired.view, retired.buffer_revision, retired.mutation.revision});
                    mutations.pop_front();
                }
                mutations.push_back(std::move(record));
            }
            batch.text_mutations.clear();
            batch.text_mutation_gaps.clear();
        };
        // Preserve observation order across responses. Per-View revisions are
        // consecutive; they are not a session-global ordering key.
        for (auto &pending_completion : completions) append(pending_completion);
        append(completion);
        completion.text_mutations.reserve(mutations.size());
        for (auto &record : mutations) completion.text_mutations.push_back(std::move(record));
        for (const auto &[id, gap] : gaps) {
            (void)id;
            completion.text_mutation_gaps.push_back(gap);
        }
    }
    void publish(IsolatedActivity &session, ActivityCompletion completion) {
        // Copy outside the mailbox lock. Only the I/O thread touches the connection.
        ActivityPublication update;
        update.state = std::make_shared<const ActivityState>(session.snapshot());
        update.text_edit_observation_revision = completion.read_unavailable
            ? pending.text_edit_observation_revision : last_streamed_text_edit_revision;
        update.process_id = session.process_id();
        update.commands = session.command_count();
        update.broker_calls = session.broker_calls();
        update.exited = session.exited();
        update.audit = session.audit_json();
        update.durable_audit = session.durable_audit_json();
        if (!completion.read_unavailable) {
            if (completion.kind == ActivityCommandKind::prepare_accessibility_metadata ||
                completion.kind == ActivityCommandKind::collection_selection) {
                completion.accessibility_metadata_attempt = update.state->accessibility_metadata_attempt;
                completion.accessibility_invalidation_revision = update.state->accessibility_invalidation_revision;
                completion.accessibility_metadata_status = update.state->accessibility_metadata_status;
            }
            collect_view_activations(*update.state, completion);
            collect_text_edits(*update.state, completion);
            collect_text_mutations(*update.state, completion);
        }
        std::lock_guard lock(mutex);
        require(completion.view_activations.size() <= android::view_activation_limit - pending_view_activation_count,
                "AETHER_VIEW_ACTIVATION_QUOTA: pending completion history exhausted");
        merge_text_edits(*update.state, completion);
        merge_text_mutations(*update.state, completion);
        update.last_live = update.state->content ? update.state : pending.last_live;
        pending = std::move(update);
        if (completion.ticket) {
            ++metrics.completed;
            if (completion.read_unavailable) {
                ++metrics.read_failures;
                read_failed = true;
            } else if (completion.kind == ActivityCommandKind::refresh && read_failed) {
                ++metrics.recovered_reads;
                read_failed = false;
            }
        }
        const auto activation_count = completion.view_activations.size();
        completions.push_back(std::move(completion));
        pending_view_activation_count += activation_count;
        notify();
    }
    void observe_text_edit(const android::TextEditObservation &observation, std::uint64_t context,
                           AwakeDeadlineClock::time_point deadline) {
        auto owned = std::make_shared<const android::TextEditObservation>(observation);
        std::unique_lock lock(mutex);
        require(!stopping && !text_edit_observation &&
                    observation.event.revision > last_text_edit_sequence,
                "Invalid TextEdit observation handoff");
        require(!context || active_request_ticket, "TextEdit command context has no active request");
        if (!pending.state) {
            // No HWND/provider exists during constructor startup. Consume
            // without waking the startup waiter or replaying private history.
            text_edit_cursors[observation.document.object] = observation.event.revision;
            last_text_edit_sequence = observation.event.revision;
            last_streamed_text_edit_revision = observation.event.revision;
            return;
        }
        text_edit_observation = std::move(owned);
        text_edit_ticket = context ? active_request_ticket : 0;
        text_edit_receipt = 0;
        text_edit_claimed = false;
        notify();
        while (!stopping && text_edit_observation) {
            const auto now = AwakeDeadlineClock::now();
            require(now < deadline, "TextEdit consumption exceeded the worker exchange deadline");
            wake.wait_for(lock, deadline - now);
        }
        require(!stopping && AwakeDeadlineClock::now() < deadline &&
                    text_edit_receipt == observation.event.revision,
                "TextEdit consumption was cancelled or expired");
        // Final snapshots share these cursors. Streamed records cannot replay
        // through the ordinary bounded historical completion path.
        text_edit_cursors[observation.document.object] = observation.event.revision;
        last_text_edit_sequence = observation.event.revision;
        last_streamed_text_edit_revision = observation.event.revision;
    }
    bool observe_soft_input(const android::SoftInputObservation &observation, std::uint64_t context,
                            AwakeDeadlineClock::time_point deadline) {
        auto owned = std::make_shared<const android::SoftInputObservation>(observation);
        std::unique_lock lock(mutex);
        require(!stopping && !soft_input_observation && observation.request.revision > last_soft_input_revision,
                "Invalid soft input observation handoff");
        if (!pending.state || !context) {
            last_soft_input_revision = observation.request.revision;
            return false; // Startup/idle records cannot create a native keyboard action.
        }
        require(active_request_ticket && active_request_kind == ActivityCommandKind::claim_soft_input &&
                    active_soft_input_revision == observation.request.revision &&
                    active_soft_input_view == observation.request.view,
                "Soft input observation has no matching explicit host claim");
        soft_input_observation = std::move(owned);
        soft_input_ticket = active_request_ticket;
        soft_input_receipt = 0; soft_input_accepted = false; soft_input_claimed = false;
        notify();
        while (!stopping && soft_input_observation) {
            const auto now = AwakeDeadlineClock::now();
            require(now < deadline, "Soft input consumption exceeded the worker exchange deadline");
            wake.wait_for(lock, deadline - now);
        }
        require(!stopping && AwakeDeadlineClock::now() < deadline &&
                    soft_input_receipt == observation.request.revision,
                "Soft input consumption was cancelled or expired");
        last_soft_input_revision = observation.request.revision;
        return soft_input_accepted;
    }
    void observe_terminal_activations(const ActivityTerminalActivations &batch, std::uint64_t context,
                                      AwakeDeadlineClock::time_point deadline) {
        auto custody = std::make_shared<ActivityTerminalActivationCustody>();
        custody->through_revision = batch.through_revision;
        std::unique_lock lock(mutex);
        require(!stopping && !terminal_activation_received && !terminal_activations &&
                    (!context || active_request_ticket),
                "Invalid terminal activation handoff");
        require(batch.records.size() <= android::view_activation_limit - pending_view_activation_count,
                "Terminal activation custody quota exhausted");
        auto cursor = last_view_activation_revision;
        for (const auto &record : batch.records) {
            require(cursor != UINT64_MAX && record.revision == cursor + 1,
                    "Terminal activation history is incomplete");
            cursor = record.revision;
        }
        require(cursor == batch.through_revision, "Terminal activation cursor mismatch");
        // Allocate/copy the complete ordered custody before consuming any older
        // mailbox facts. Other completion histories and tickets stay untouched.
        custody->records.reserve(pending_view_activation_count + batch.records.size());
        for (const auto &completion : completions)
            for (const auto &record : completion.view_activations)
                custody->records.push_back({record, completion.ticket});
        for (const auto &record : batch.records)
            custody->records.push_back({record, context ? active_request_ticket : 0});
        require(custody->records.size() == pending_view_activation_count + batch.records.size(),
                "Terminal activation custody count mismatch");
        for (auto &completion : completions) completion.view_activations.clear();
        pending_view_activation_count = 0;
        last_view_activation_revision = cursor;
        terminal_activation_received = true;
        if (!pending.state) return; // Startup has no exposed HWND/provider identity.
        terminal_activations = std::move(custody);
        terminal_activation_claimed = false;
        terminal_activation_receipt = 0;
        terminal_activation_receipted = false;
        notify();
        while (!stopping && terminal_activations) {
            const auto now = AwakeDeadlineClock::now();
            require(now < deadline, "Terminal activation custody exceeded the worker exchange deadline");
            wake.wait_for(lock, deadline - now);
        }
        require(!stopping && AwakeDeadlineClock::now() < deadline &&
                    terminal_activation_receipted && terminal_activation_receipt == batch.through_revision,
                "Terminal activation custody was cancelled or expired");
    }
    void run(std::filesystem::path apk, ActivityMode mode,
             const InstalledActivity *application = nullptr,
             const std::filesystem::path &developer_output_root = {}) noexcept {
        try {
            const ActivityTextEditSink sink = [this](const android::TextEditObservation &observation, std::uint64_t context,
                                                     AwakeDeadlineClock::time_point deadline) {
                observe_text_edit(observation, context, deadline);
            };
            const ActivitySoftInputSink soft_sink = [this](const android::SoftInputObservation &observation,
                                                          std::uint64_t context, AwakeDeadlineClock::time_point deadline) {
                return observe_soft_input(observation, context, deadline);
            };
            const ActivityTerminalActivationSink terminal_sink =
                [this](const ActivityTerminalActivations &batch, std::uint64_t context,
                       AwakeDeadlineClock::time_point deadline) { observe_terminal_activations(batch, context, deadline); };
            auto owned = application ? std::make_unique<IsolatedActivity>(*application, sink, soft_sink, clipboard_window, terminal_sink)
                                     : std::make_unique<IsolatedActivity>(apk, mode, developer_output_root, sink, soft_sink,
                                                                          clipboard_window, terminal_sink);
            auto &session = *owned;
            {
                std::lock_guard lock(mutex);
                if (stopping)
                    return;
                active = &session;
                metrics.io_thread = GetCurrentThreadId();
            }
            // Always detach the cross-thread cancellation pointer before destruction.
            struct Detach {
                Impl &self;
                ~Detach() {
                    std::lock_guard lock(self.mutex);
                    self.active = nullptr;
                }
            } detach{*this};
            publish(session, {});
            for (;;) {
                Request request;
                {
                    std::unique_lock lock(mutex);
                    wake.wait_for(lock, std::chrono::milliseconds(10), [&] { return stopping || !requests.empty(); });
                    if (stopping)
                        break;
                    if (requests.empty()) {
                        lock.unlock();
                        (void)session.service_background();
                        continue;
                    }
                    request = std::move(requests.front());
                    requests.pop_front();
                    active_request_ticket = request.ticket;
                    active_request_kind = request.command.kind;
                    active_soft_input_revision = request.command.soft_input_revision;
                    active_soft_input_view = request.command.view;
                }
                ActivityCompletion completion{request.ticket, request.command.kind};
                try {
                    if (request.text) session.drop_text(std::move(*request.text), request.command);
                    else if (request.document) session.drop_document(std::move(*request.document), request.command);
                    else session.dispatch(request.command);
                    completion.handled = session.snapshot().handled;
                } catch (const ActivityReadUnavailable &) {
                    require(request.command.kind == ActivityCommandKind::refresh,
                            "A mutation cannot be retried as a state read");
                    completion.read_unavailable = true;
                }
                publish(session, completion);
                {
                    std::lock_guard lock(mutex);
                    active_request_ticket = 0;
                }
                if (request.command.kind == ActivityCommandKind::close)
                    break;
            }
        } catch (...) {
            std::lock_guard lock(mutex);
            if (!stopping)
                failure = std::current_exception();
            stopping = true;
            active_request_ticket = 0;
            requests.clear();
            SetEvent(event.get());
            if (notification_window)
                PostMessageW(notification_window, notification_message, 0, 0);
        }
    }
};
ActivityDispatcher::ActivityDispatcher(const std::filesystem::path &apk, ActivityMode mode,
                                       const std::filesystem::path &developer_output_root)
    : impl_(std::make_unique<Impl>()) {
    impl_->io = std::jthread([self = impl_.get(), apk, mode, developer_output_root] {
        self->run(apk, mode, nullptr, developer_output_root);
    });
}
ActivityDispatcher::~ActivityDispatcher() = default;
ActivityDispatcher::ActivityDispatcher(InstalledActivity application) : impl_(std::make_unique<Impl>()) {
    impl_->io = std::jthread(
        [self = impl_.get(), app = std::move(application)] { self->run({}, ActivityMode::normal, &app); });
}
std::uint64_t ActivityDispatcher::submit(ActivityCommand command) {
    auto &p = *impl_;
    p.check_owner();
    require(command.kind != ActivityCommandKind::drag || command.drag.action != android::DragAction::drop,
            "DROP requires separately reviewed host document admission");
    (void)command.encode(); // Bound copied command storage before adding it to the queue.
    std::lock_guard lock(p.mutex);
    require(!p.stopping && !p.closing && p.next != UINT64_MAX, "Closed command queue");
    if (command.kind == ActivityCommandKind::refresh) {
        ++p.metrics.read_requests;
        if (p.read_ticket) {
            ++p.metrics.coalesced_reads;
            return p.read_ticket;
        }
    }
    // Reserve a final slot for ordered close. Completed but unconsumed replies also count.
    require(p.outstanding < (command.kind == ActivityCommandKind::close ? 257u : 256u),
            "Pending command quota exceeded");
    const auto ticket = p.next++;
    p.requests.push_back({ticket, std::move(command), {}, {}});
    const auto kind = p.requests.back().command.kind;
    if (kind == ActivityCommandKind::refresh)
        p.read_ticket = ticket;
    if (kind == ActivityCommandKind::close) {
        p.closing = true;
        p.clipboard_window->close();
    }
    ++p.outstanding;
    ++p.metrics.submitted;
    p.metrics.peak_outstanding = std::max(p.metrics.peak_outstanding, p.outstanding);
    p.wake.notify_one();
    return ticket;
}
std::uint64_t ActivityDispatcher::drop_document(host::PreparedDocumentSource source, ActivityCommand command) {
    auto &p = *impl_;
    p.check_owner();
    require(command.kind == ActivityCommandKind::drag && command.drag.action == android::DragAction::drop &&
                command.drag.kind == host::DropPayloadKind::file &&
                command.drag.document && source.service && source.info == *command.drag.document,
            "Reviewed document does not match the captured DROP");
    (void)command.encode();
    std::lock_guard lock(p.mutex);
    require(!p.stopping && !p.closing && p.next != UINT64_MAX && p.outstanding < 256,
            "Closed or full document command queue");
    const auto ticket = p.next++;
    p.requests.push_back({ticket, std::move(command), std::move(source), {}});
    ++p.outstanding; ++p.metrics.submitted;
    p.metrics.peak_outstanding = std::max(p.metrics.peak_outstanding, p.outstanding);
    p.wake.notify_one();
    return ticket;
}
std::uint64_t ActivityDispatcher::drop_text(std::u16string text, ActivityCommand command) {
    auto &p = *impl_;
    p.check_owner();
    require(command.kind == ActivityCommandKind::drag && command.drag.action == android::DragAction::drop &&
                command.drag.kind == host::DropPayloadKind::plain_text && command.drag.text_info &&
                host::matches_drop_text(*command.drag.text_info, text),
            "Reviewed text does not match the captured DROP descriptor");
    (void)command.encode();
    std::lock_guard lock(p.mutex);
    require(!p.stopping && !p.closing && p.next != UINT64_MAX && p.outstanding < 256,
            "Closed or full text command queue");
    const auto ticket = p.next++;
    p.requests.push_back({ticket, std::move(command), {}, std::move(text)});
    ++p.outstanding; ++p.metrics.submitted;
    p.metrics.peak_outstanding = std::max(p.metrics.peak_outstanding, p.outstanding);
    p.wake.notify_one();
    return ticket;
}
void ActivityDispatcher::signal(android::WindowSignal value) {
    ActivityCommand command;
    command.kind =
        value == android::WindowSignal::close ? ActivityCommandKind::close : ActivityCommandKind::signal;
    command.signal = value;
    (void)submit(std::move(command));
}
std::uint64_t ActivityDispatcher::configure(const android::DisplayConfiguration &configuration) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::configure;
    command.configuration = configuration;
    return submit(std::move(command));
}
void ActivityDispatcher::place_views(std::span<const android::ViewPlacement> placements) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::place;
    command.placements.assign(placements.begin(), placements.end());
    (void)submit(std::move(command));
}
void ActivityDispatcher::pointer(const android::PointerInput &input) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::pointer;
    command.pointer = input;
    (void)submit(std::move(command));
}
std::uint64_t ActivityDispatcher::key(const android::KeyInput &input) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::key;
    command.key = input;
    return submit(std::move(command));
}
std::uint64_t ActivityDispatcher::refresh() { return submit({}); }
void ActivityDispatcher::close() {
    ActivityCommand command;
    command.kind = ActivityCommandKind::close;
    (void)submit(std::move(command));
}
void ActivityDispatcher::abort() noexcept { impl_->abort(); }
HANDLE ActivityDispatcher::completion_event() const noexcept { return impl_->event.get(); }
void ActivityDispatcher::set_notification(HWND window, UINT message) {
    auto &p = *impl_;
    p.check_owner();
    require(!window || message >= WM_APP, "Invalid host notification message");
    std::lock_guard lock(p.mutex);
    p.notification_window = window;
    p.notification_message = message;
    p.notification_posted = false;
    if (window && (!p.completions.empty() || p.text_edit_observation || p.soft_input_observation || p.failure))
        p.notify();
}
void ActivityDispatcher::bind_clipboard_window(HWND window) {
    auto &p = *impl_;
    p.check_owner();
    {
        std::lock_guard lock(p.mutex);
        if (p.stopping || p.closing)
            return;
    }
    // Permanent context closure fences a concurrent abort without holding the
    // dispatcher lock across native HWND ownership checks.
    p.clipboard_window->bind(window);
}
void ActivityDispatcher::retire_clipboard_window() noexcept { impl_->clipboard_window->retire(); }
std::vector<ActivityCompletion> ActivityDispatcher::consume() {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    if (p.failure)
        std::rethrow_exception(p.failure);
    if (p.pending.state)
        p.visible = p.pending;
    auto result = std::move(p.completions);
    p.completions.clear();
    p.pending_view_activation_count = 0;
    p.notification_posted = false;
    for (const auto &completion : result) {
        if (completion.ticket)
            --p.outstanding;
        if (completion.ticket == p.read_ticket)
            p.read_ticket = 0;
    }
    if (p.text_edit_observation || p.soft_input_observation || p.terminal_activations)
        p.notify();
    else
        require(ResetEvent(p.event.get()) != FALSE, "Cannot reset completion event");
    return result;
}
std::shared_ptr<const android::TextEditObservation> ActivityDispatcher::take_text_edit_observation() {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    if (p.failure) std::rethrow_exception(p.failure);
    if (p.text_edit_claimed) return {};
    p.text_edit_claimed = p.text_edit_observation != nullptr;
    return p.text_edit_observation;
}
std::uint64_t ActivityDispatcher::text_edit_observation_ticket() const {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    return !p.stopping && p.text_edit_claimed && p.text_edit_observation ? p.text_edit_ticket : 0;
}
void ActivityDispatcher::complete_text_edit_observation(std::uint64_t event_revision) {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    require(p.text_edit_observation && p.text_edit_claimed && p.text_edit_observation->event.revision == event_revision &&
                !p.text_edit_receipt && !p.stopping, "Invalid TextEdit consumption receipt");
    p.text_edit_observation.reset();
    p.text_edit_ticket = 0;
    p.text_edit_claimed = false;
    p.text_edit_receipt = event_revision;
    p.notification_posted = false;
    if (p.completions.empty() && !p.failure && !p.soft_input_observation && !p.terminal_activations)
        require(ResetEvent(p.event.get()) != FALSE, "Cannot reset TextEdit completion event");
    else
        p.notify();
    p.wake.notify_all();
}
std::shared_ptr<const android::SoftInputObservation> ActivityDispatcher::take_soft_input_observation() {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    if (p.failure) std::rethrow_exception(p.failure);
    if (p.soft_input_claimed) return {};
    p.soft_input_claimed = p.soft_input_observation != nullptr;
    return p.soft_input_observation;
}
std::uint64_t ActivityDispatcher::soft_input_observation_ticket() const {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    return !p.stopping && p.soft_input_claimed && p.soft_input_observation ? p.soft_input_ticket : 0;
}
void ActivityDispatcher::complete_soft_input_observation(std::uint64_t revision, bool accepted) {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    require(p.soft_input_observation && p.soft_input_claimed &&
                p.soft_input_observation->request.revision == revision && !p.soft_input_receipt && !p.stopping,
            "Invalid soft input consumption receipt");
    p.soft_input_observation.reset();
    p.soft_input_ticket = 0; p.soft_input_claimed = false;
    p.soft_input_receipt = revision; p.soft_input_accepted = accepted;
    p.notification_posted = false;
    if (p.completions.empty() && !p.failure && !p.text_edit_observation && !p.terminal_activations)
        require(ResetEvent(p.event.get()) != FALSE, "Cannot reset soft input completion event");
    else p.notify();
    p.wake.notify_all();
}
std::shared_ptr<const ActivityTerminalActivationCustody> ActivityDispatcher::take_terminal_activations() {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    // This historical custody precedes any stored terminal failure. Never wait
    // for a final worker snapshot: its sender is paused on this very receipt.
    if (p.terminal_activation_claimed) return {};
    p.terminal_activation_claimed = p.terminal_activations != nullptr;
    return p.terminal_activations;
}
void ActivityDispatcher::complete_terminal_activations(std::uint64_t through_revision) {
    auto &p = *impl_;
    p.check_owner();
    std::lock_guard lock(p.mutex);
    require(p.terminal_activations && p.terminal_activation_claimed &&
                p.terminal_activations->through_revision == through_revision && !p.terminal_activation_receipted,
            "Invalid terminal activation custody receipt");
    p.terminal_activations.reset();
    p.terminal_activation_claimed = false;
    p.terminal_activation_receipt = through_revision;
    p.terminal_activation_receipted = true;
    p.notification_posted = false;
    if (p.completions.empty() && !p.failure && !p.text_edit_observation && !p.soft_input_observation)
        require(ResetEvent(p.event.get()) != FALSE, "Cannot reset terminal activation completion event");
    else p.notify();
    p.wake.notify_all();
}
bool ActivityDispatcher::idle() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->pending.state && impl_->outstanding == 0 && !impl_->text_edit_observation && !impl_->soft_input_observation && !impl_->terminal_activations && !impl_->stopping;
}
bool ActivityDispatcher::read_pending() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->read_ticket != 0;
}
ActivityDispatchMetrics ActivityDispatcher::dispatch_metrics() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->metrics;
}
const ActivityPublication &ActivityDispatcher::publication() const noexcept { return impl_->visible; }
const ActivityState &ActivityDispatcher::snapshot() const {
    impl_->check_owner();
    require(impl_->visible.state != nullptr, "Activity has not published startup state");
    return *impl_->visible.state;
}
std::uint32_t ActivityDispatcher::probe(std::string_view name) const {
    for (std::size_t i = 0; i < activity_probes.size(); ++i)
        if (activity_probes[i] == name)
            return snapshot().probes[i];
    throw ProtocolError("AETHER_ACTIVITY_PROBE: unknown first-party input probe");
}
} // namespace aether::security
