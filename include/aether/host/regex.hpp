#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
namespace aether::host {
class RegexError final:public std::runtime_error {
  public:
    enum class Kind {syntax,limit,backend};
    RegexError(Kind kind,std::string message,std::int32_t index=-1):std::runtime_error(std::move(message)),kind(kind),index(index){}
    const Kind kind;const std::int32_t index;
};
struct RegexBackendInfo {std::array<std::uint8_t,4> version{};std::size_t live_patterns=0,live_matchers=0;};
RegexBackendInfo regex_backend_info();
class RegexMatcher;
class RegexPattern {
  public:
    static std::unique_ptr<RegexPattern> compile(std::u16string_view,std::uint32_t flags,bool literal=false);
    ~RegexPattern();
    RegexPattern(const RegexPattern&)=delete;
    std::unique_ptr<RegexMatcher> matcher(std::u16string_view) const;
  private:
    struct State;explicit RegexPattern(std::unique_ptr<State>);
    std::unique_ptr<State> state_;
};
class RegexMatcher {
  public:
    ~RegexMatcher();
    RegexMatcher(const RegexMatcher&)=delete;
    bool matches();bool find(std::int32_t start=-1);
    std::int32_t start(std::int32_t group) const;
    std::int32_t end(std::int32_t group) const;
    std::int32_t groups() const;
    void reset(std::u16string_view);
    std::u16string_view input() const noexcept;
    std::size_t storage_bytes() const noexcept;
  private:
    friend class RegexPattern;
    struct State;explicit RegexMatcher(std::unique_ptr<State>);
    std::unique_ptr<State> state_;
};
}
