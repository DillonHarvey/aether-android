#include "aether/common/prefix_strings.hpp"
#include <algorithm>
#include <iterator>
#include <map>
#include <stdexcept>

namespace aether {
namespace {
void require(bool condition) {
    if (!condition)
        throw std::invalid_argument("Prefix string table exceeds its bounds or has an invalid reference");
}
std::size_t prefix(std::string_view a, std::string_view b) {
    std::size_t count = 0;
    while (count < a.size() && count < b.size() && a[count] == b[count])
        ++count;
    return count;
}
} // namespace
std::vector<std::uint8_t> encode_prefix_strings(std::span<const std::string> values) {
    require(values.size() <= prefix_string_count);
    std::size_t decoded = 0;
    for (const auto &value : values) {
        require(value.size() <= prefix_string_bytes && value.size() <= prefix_decoded_bytes - decoded);
        decoded += value.size();
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(decoded + values.size() * 6);
    const auto word = [&](std::size_t value) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    };
    std::map<std::string, std::uint16_t, std::less<>> previous;
    for (std::size_t index = 0; index < values.size(); ++index) {
        const auto &value = values[index];
        std::size_t shared = 0, reference = 0xffff;
        const auto candidate = [&](const auto &entry) {
            const auto common = prefix(value, entry.first);
            if (common > shared || (common && common == shared && entry.second < reference)) {
                shared = common;
                reference = entry.second;
            }
        };
        // A longest prior prefix occurs at one of the two lexical neighbours.
        // Work is O(total input bytes * log(count)), never an all-pairs search.
        auto at = previous.lower_bound(value);
        if (at != previous.end())
            candidate(*at);
        if (at != previous.begin())
            candidate(*std::prev(at));
        word(reference);
        word(shared);
        word(value.size() - shared);
        bytes.insert(bytes.end(), value.begin() + static_cast<std::ptrdiff_t>(shared), value.end());
        previous.try_emplace(value, static_cast<std::uint16_t>(index));
    }
    return bytes;
}
DecodedPrefixStrings decode_prefix_strings(std::span<const std::uint8_t> bytes, std::size_t count) {
    require(count <= prefix_string_count);
    DecodedPrefixStrings result;
    result.values.reserve(count);
    std::size_t decoded = 0;
    const auto word = [&] {
        require(result.consumed <= bytes.size() && bytes.size() - result.consumed >= 2);
        const auto at = result.consumed;
        result.consumed += 2;
        return std::size_t{bytes[at]} | (std::size_t{bytes[at + 1]} << 8);
    };
    for (std::size_t index = 0; index < count; ++index) {
        const auto reference = word(), shared = word(), literal = word();
        require((reference == 0xffff && !shared) ||
                (reference < index && shared && shared <= result.values[reference].size()));
        require(shared <= prefix_string_bytes && literal <= prefix_string_bytes - shared &&
                literal <= bytes.size() - result.consumed &&
                shared + literal <= prefix_decoded_bytes - decoded);
        std::string value;
        if (shared)
            value = result.values[reference].substr(0, shared);
        value.append(reinterpret_cast<const char *>(bytes.data() + result.consumed), literal);
        result.consumed += literal;
        decoded += value.size();
        result.values.push_back(std::move(value));
    }
    return result;
}
} // namespace aether
