#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace aether::uri {
inline constexpr std::size_t text_units = 4096;
class Error final : public std::runtime_error {
  public:
    enum class Kind { limit, part };
    Error(Kind kind, const char *message) : std::runtime_error(message), kind(kind) {}
    const Kind kind;
};
enum class Part { scheme, scheme_specific_part, authority, path, query, fragment, user_info };
struct Slice { std::size_t first, last; }; // Half-open UTF-16 offsets into the borrowed input.

// Original Android15-compatible lenient URI value parsing. This is not an
// external-routing allowlist, host/path validator or URI normalizer. Input must
// remain alive and unchanged while this view or its slices are used.
struct Parsed {
    std::u16string_view text;
    std::size_t colon, fragment;
    explicit Parsed(std::u16string_view text);
    std::size_t start() const noexcept;
    bool hierarchical() const noexcept;
    std::optional<Slice> authority() const;
    std::optional<Slice> part(Part part) const;
};
// UriCodec percent/UTF8 replacement semantics; '+' stays '+'. Every entry
// point enforces the same 4096-unit representation bound, using Error::limit.
std::u16string decode(std::u16string_view encoded);
// Authority helpers take a present encoded authority; absence is represented
// by the caller's optional Slice, never conflated with a present empty value.
std::optional<Slice> user_info(std::u16string_view encoded_authority);
std::u16string host(std::u16string_view encoded_authority);
std::int32_t port(std::u16string_view encoded_authority);
} // namespace aether::uri
