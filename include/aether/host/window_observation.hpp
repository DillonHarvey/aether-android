#pragma once
#include <cstdint>
#include <functional>
#include <limits>
#include <type_traits>

namespace aether::host {
// Host-only sampled facts. HWND is diagnostic identity, never guest authority;
// graphics binding pointers and application text are deliberately absent.
struct WindowObservationFacts {
    std::uint64_t hwnd = 0, transport_session = 0, activity = 0, content = 0;
    std::uint64_t window_generation = 0, input_generation = 0, source_view_revision = 0;
    std::uint64_t attachment_incarnation = 0, visual_epoch = 0, render_revision = 0;
    std::uint64_t read_failures = 0, read_recoveries = 0;
    std::uint32_t host_pid = 0, worker_pid = 0, lifecycle = 0;
    std::int64_t awake_100ns = 0;
    bool visible = false, iconic = false, worker_exited = false;
    bool last_refresh_unavailable = false, finishing = false, terminal = false;
};

enum class WindowObservationKind { visible, buffer_copied, genuine_present, ordinary_message, retired, loss };
struct WindowObservation {
    WindowObservationKind kind = WindowObservationKind::loss;
    WindowObservationFacts facts;
};
using WindowObservationSink = std::function<void(const WindowObservation &)>;

struct WindowObservationSample {
    bool recorded = false;
    WindowObservationFacts facts;
};
struct WindowObservationEpoch {
    bool recorded = false, has_visible_sample = false, has_present = false;
    bool has_visible_present = false, has_postpresent_message = false;
    bool visibility_interrupted = false, retired = false, replacement_observed = false;
    bool terminal_observed = false;
    WindowObservationFacts first, last;
    std::int64_t first_visible_at = 0, first_present_at = 0, first_visible_present_at = 0;
    std::int64_t last_present_at = 0, last_ordinary_message_at = 0, retired_at = 0;
    std::uint64_t observations = 0, buffer_copies = 0, genuine_presents = 0, ordinary_messages = 0;
};
struct WindowObservationSummary {
    // Independent actual host samples survive without renderer tokens. They
    // are never combined into a visual epoch, duration or acceptance claim.
    WindowObservationSample first_visible, last_ordinary_message, retirement;
    WindowObservationEpoch current, first_presented;
    std::uint64_t observations_seen = 0, epochs_seen = 0, epochs_with_detail_omitted = 0;
    std::uint64_t unbound_events = 0, stale_events = 0, capture_losses = 0, observation_failures = 0;
    bool counters_saturated = false;
};

// One UI owner supplies ordered facts. visual_epoch must strictly increase
// within its bound transport session when visual custody changes. Zero visual
// tokens are truthful unbound observations, never proof of presentation.
// Host transport session/process identities bind once; a replacement HWND
// may belong to the same session, but another launch cannot relabel samples.
// genuine_present requires an actual renderer/content completion witness;
// copying a host buffer alone is the distinct buffer_copied event.
// ordinary_message means natural queued dispatch after showing the window,
// excluding preparation pumping and synchronous UpdateWindow dispatch.
// All timestamps describe samples, never continuous visibility or a pass gate.
class WindowObservationReducer final {
    WindowObservationSummary summary_{};
    bool has_stamp_ = false;
    std::int64_t last_stamp_ = 0;
    std::uint64_t bound_transport_session_ = 0;
    std::uint32_t bound_host_pid_ = 0, bound_worker_pid_ = 0;

    void bump(std::uint64_t &value) noexcept {
        if (value == std::numeric_limits<std::uint64_t>::max())
            summary_.counters_saturated = true;
        else
            ++value;
    }
    static bool valid_host_key(const WindowObservationFacts &facts) noexcept {
        return facts.hwnd && facts.transport_session && facts.host_pid && facts.worker_pid;
    }
    static bool valid_key(const WindowObservationFacts &facts) noexcept {
        return valid_host_key(facts) && facts.activity && facts.content &&
               facts.attachment_incarnation && facts.visual_epoch;
    }
    static bool same_key(const WindowObservationFacts &left, const WindowObservationFacts &right) noexcept {
        return left.hwnd == right.hwnd && left.transport_session == right.transport_session &&
               left.host_pid == right.host_pid && left.worker_pid == right.worker_pid &&
               left.activity == right.activity && left.content == right.content &&
               left.attachment_incarnation == right.attachment_incarnation && left.visual_epoch == right.visual_epoch;
    }
    static bool visibly_live(const WindowObservationFacts &facts) noexcept {
        return facts.visible && !facts.iconic && !facts.worker_exited && !facts.terminal && !facts.finishing;
    }
    void sync_first() noexcept {
        if (summary_.first_presented.recorded && same_key(summary_.first_presented.first, summary_.current.first))
            summary_.first_presented = summary_.current;
    }
    void begin(const WindowObservationFacts &facts) noexcept {
        summary_.current = {};
        summary_.current.recorded = true;
        summary_.current.first = summary_.current.last = facts;
        bump(summary_.epochs_seen);
    }

  public:
    void observe(const WindowObservation &event) noexcept {
        bump(summary_.observations_seen);
        if (event.kind == WindowObservationKind::loss) {
            bump(summary_.capture_losses);
            return; // A failed capture need not have valid facts or a timestamp.
        }
        switch (event.kind) {
        case WindowObservationKind::visible:
        case WindowObservationKind::buffer_copied:
        case WindowObservationKind::genuine_present:
        case WindowObservationKind::ordinary_message:
        case WindowObservationKind::retired:
            break;
        default:
            bump(summary_.observation_failures);
            return;
        }
        const auto &facts = event.facts;
        if (facts.awake_100ns < 0 || (has_stamp_ && facts.awake_100ns < last_stamp_)) {
            bump(summary_.observation_failures);
            return;
        }
        has_stamp_ = true;
        last_stamp_ = facts.awake_100ns;
        if (valid_host_key(facts)) {
            if (!bound_transport_session_) {
                bound_transport_session_ = facts.transport_session;
                bound_host_pid_ = facts.host_pid;
                bound_worker_pid_ = facts.worker_pid;
            } else if (facts.transport_session != bound_transport_session_ || facts.host_pid != bound_host_pid_ ||
                       facts.worker_pid != bound_worker_pid_) {
                bump(summary_.observation_failures);
                return;
            }
            if (event.kind == WindowObservationKind::visible && facts.visible && !facts.iconic &&
                !summary_.first_visible.recorded)
                summary_.first_visible = {true, facts};
            else if (event.kind == WindowObservationKind::ordinary_message)
                summary_.last_ordinary_message = {true, facts};
            else if (event.kind == WindowObservationKind::retired)
                summary_.retirement = {true, facts};
        }
        if (!valid_key(facts)) {
            bump(summary_.unbound_events);
            return;
        }
        if (!summary_.current.recorded) {
            begin(facts);
        } else if (!same_key(summary_.current.first, facts)) {
            const auto &old = summary_.current.first;
            if (facts.transport_session != old.transport_session || facts.host_pid != old.host_pid ||
                facts.worker_pid != old.worker_pid) {
                bump(summary_.observation_failures);
                return;
            }
            if (facts.visual_epoch <= old.visual_epoch) {
                bump(summary_.stale_events);
                return;
            }
            if (!summary_.current.retired) {
                summary_.current.retired = true;
                summary_.current.replacement_observed = true;
                summary_.current.retired_at = facts.awake_100ns;
            }
            sync_first();
            if (!summary_.first_presented.recorded || !same_key(summary_.first_presented.first, old))
                bump(summary_.epochs_with_detail_omitted);
            begin(facts);
        } else if (summary_.current.retired) {
            if (event.kind != WindowObservationKind::retired)
                bump(summary_.stale_events);
            return; // Repeated retirement is idempotent; a retired epoch cannot revive.
        }

        auto &epoch = summary_.current;
        bump(epoch.observations);
        epoch.last = facts;
        epoch.terminal_observed = epoch.terminal_observed || facts.terminal || facts.worker_exited;
        const bool visible = visibly_live(facts);
        if (visible && !epoch.has_visible_sample) {
            epoch.has_visible_sample = true;
            epoch.first_visible_at = facts.awake_100ns;
        }
        if (epoch.has_visible_sample && (!facts.visible || facts.iconic))
            epoch.visibility_interrupted = true;
        switch (event.kind) {
        case WindowObservationKind::buffer_copied:
            bump(epoch.buffer_copies);
            break;
        case WindowObservationKind::genuine_present:
            if (!facts.render_revision) {
                bump(summary_.observation_failures);
                break;
            }
            bump(epoch.genuine_presents);
            if (!epoch.has_present) {
                epoch.has_present = true;
                epoch.first_present_at = facts.awake_100ns;
            }
            epoch.last_present_at = facts.awake_100ns;
            if (visible && !epoch.has_visible_present) {
                epoch.has_visible_present = true;
                epoch.first_visible_present_at = facts.awake_100ns;
            }
            if (visible && !summary_.first_presented.recorded)
                summary_.first_presented = epoch;
            break;
        case WindowObservationKind::ordinary_message:
            bump(epoch.ordinary_messages);
            if (visible && epoch.has_visible_present && facts.awake_100ns > epoch.first_visible_present_at) {
                epoch.has_postpresent_message = true;
                epoch.last_ordinary_message_at = facts.awake_100ns;
            }
            break;
        case WindowObservationKind::retired:
            epoch.retired = true;
            epoch.retired_at = facts.awake_100ns;
            break;
        default:
            break;
        }
        // A destroyed/failed owner or confirmed worker exit cannot acquire
        // fresh presentation authority under this same visual incarnation.
        if (epoch.terminal_observed && !epoch.retired) {
            epoch.retired = true;
            epoch.retired_at = facts.awake_100ns;
        }
        sync_first();
    }
    const WindowObservationSummary &summary() const noexcept { return summary_; }
};

static_assert(std::is_trivially_copyable_v<WindowObservation>);
static_assert(std::is_trivially_copyable_v<WindowObservationSummary>);
} // namespace aether::host
