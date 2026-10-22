#pragma once
#include <string_view>
namespace aether::host {
struct NativeLogMessage {int priority=4;std::string_view tag,text;bool assertion=false;};
// Message views are valid only during write; a supplied sink outlives its service.
class NativeLogSink {
  public:
    virtual ~NativeLogSink()=default;
    virtual bool write(const NativeLogMessage &) noexcept=0;
};
}
