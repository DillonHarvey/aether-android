#include "aether/apk/runtime_path.hpp"
#include "aether/apk/inspect.hpp"
#include <algorithm>
#include <charconv>
#include <cmath>
#include <utility>

namespace aether::apk {
namespace {
[[noreturn]] void fail(const char *kind, const char *message) {
    throw InspectError(std::string("AETHER_PATH_") + kind, "runtime-path", message);
}
bool space(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
bool digit(char c) noexcept { return c >= '0' && c <= '9'; }
bool letter(char c) noexcept { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
char upper(char c) noexcept { return c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c; }
unsigned arity(char c) {
    switch (upper(c)) {
    case 'M': case 'L': case 'T': return 2;
    case 'H': case 'V': return 1;
    case 'C': return 6;
    case 'S': case 'Q': return 4;
    case 'A': return 7;
    case 'Z': return 0;
    default: fail("INVALID", "Unknown path command");
    }
}
struct Parser {
    std::string_view input;
    std::size_t limit, at = 0;
    const std::function<void(std::uint64_t)> &charge;
    RuntimePath result;
    RuntimePathCommand pending;
    double x = 0, y = 0, start_x = 0, start_y = 0;
    bool moved = false;

    void advance(std::size_t count) {
        charge(static_cast<std::uint64_t>(count));
        at += count;
    }
    void whitespace() {
        while (at < input.size() && space(input[at]))
            advance(1);
    }
    double number(bool comma_allowed) {
        whitespace();
        if (at < input.size() && input[at] == ',') {
            if (!comma_allowed)
                fail("INVALID", "Unexpected comma before path coordinate");
            advance(1);
            whitespace();
        }
        const auto begin = at;
        if (at < input.size() && (input[at] == '+' || input[at] == '-'))
            advance(1);
        bool digits = false;
        while (at < input.size() && digit(input[at])) {
            digits = true;
            advance(1);
        }
        if (at < input.size() && input[at] == '.') {
            advance(1);
            while (at < input.size() && digit(input[at])) {
                digits = true;
                advance(1);
            }
        }
        if (!digits)
            fail("INVALID", "Missing path coordinate");
        if (at < input.size() && (input[at] == 'e' || input[at] == 'E')) {
            advance(1);
            if (at < input.size() && (input[at] == '+' || input[at] == '-'))
                advance(1);
            const auto exponent = at;
            while (at < input.size() && digit(input[at]))
                advance(1);
            if (at == exponent)
                fail("INVALID", "Missing path exponent digits");
        }
        const auto numeric_begin = begin + (input[begin] == '+' ? 1 : 0);
        double value = 0;
        // Numeric conversion visits the token again after the grammar scan.
        charge(static_cast<std::uint64_t>(at - numeric_begin));
        const auto parsed = std::from_chars(input.data() + numeric_begin, input.data() + at, value,
                                            std::chars_format::general);
        if (parsed.ec != std::errc{} || parsed.ptr != input.data() + at || !std::isfinite(value))
            fail("INVALID", "Path coordinate is not a finite representable number");
        return value;
    }
    double flag() {
        whitespace();
        if (at < input.size() && input[at] == ',') {
            advance(1);
            whitespace();
        }
        if (at == input.size() || (input[at] != '0' && input[at] != '1'))
            fail("INVALID", "Path arc flag must be the digit zero or one");
        const auto value = input[at] - '0';
        advance(1);
        return value;
    }
    void append(const RuntimePathCommand &command) {
        auto &commands = result.commands;
        if (commands.size() == commands.capacity()) {
            const auto old_capacity = commands.capacity();
            const auto max_capacity = std::min(commands.max_size(),
                (limit - sizeof(Parser)) / sizeof(RuntimePathCommand));
            if (old_capacity >= max_capacity || max_capacity - old_capacity <= commands.size())
                fail("LIMIT", "Path command growth exceeds admitted working bytes");
            const auto available = max_capacity - old_capacity;
            const auto desired = old_capacity > available / 2 ? available : std::max<std::size_t>(1, old_capacity * 2);
            // MSVC's C++20 std::vector::reserve allocates the requested capacity.
            // Include the old allocation until reserve completes its relocation.
            if (!commands.empty())
                charge(static_cast<std::uint64_t>(commands.size()));
            commands.reserve(desired);
            if (commands.capacity() > available)
                fail("LIMIT", "Path command allocator exceeded admitted capacity");
        }
        charge(1);
        commands.push_back(command);
    }
    void validate(const RuntimePathCommand &command) {
        const auto verb = upper(command.verb);
        const bool relative = command.verb >= 'a' && command.verb <= 'z';
        const auto &a = command.arguments;
        if (!moved && verb != 'M')
            fail("INVALID", "Path must begin with moveto");
        if (verb == 'Z') {
            x = start_x;
            y = start_y;
            return;
        }
        const auto coordinate = [](double value, double origin) {
            const auto resolved = value + origin;
            if (!std::isfinite(resolved))
                fail("INVALID", "Relative path coordinate overflows");
            return resolved;
        };
        const auto ox = relative ? x : 0, oy = relative ? y : 0;
        if (verb == 'A') {
            if (a[0] < 0 || a[1] < 0)
                fail("INVALID", "Path arc radii must be nonnegative");
            if ((a[3] != 0 && a[3] != 1) || (a[4] != 0 && a[4] != 1))
                fail("INVALID", "Path arc flags must be zero or one");
            x = coordinate(a[5], ox);
            y = coordinate(a[6], oy);
        } else if (verb == 'H')
            x = coordinate(a[0], ox);
        else if (verb == 'V')
            y = coordinate(a[0], oy);
        else {
            for (unsigned i = 0; i < command.count; i += 2) {
                const auto px = coordinate(a[i], ox), py = coordinate(a[i + 1], oy);
                if (i + 2 == command.count) {
                    x = px;
                    y = py;
                }
            }
        }
        if (verb == 'M') {
            moved = true;
            start_x = x;
            start_y = y;
        }
    }
    RuntimePath run() {
        if (limit < sizeof(Parser))
            fail("LIMIT", "Path parser storage exceeds admitted working bytes");
        char active = 0;
        while (true) {
            whitespace();
            if (at == input.size())
                break;
            bool explicit_command = false;
            if (letter(input[at])) {
                active = input[at];
                advance(1);
                explicit_command = true;
            } else if (!active)
                fail("INVALID", "Missing path command");
            pending = {};
            auto &command = pending;
            command.verb = active;
            command.count = static_cast<std::uint8_t>(arity(active));
            for (unsigned i = 0; i < command.count; ++i)
                command.arguments[i] = upper(active) == 'A' && (i == 3 || i == 4)
                                           ? flag()
                                           : number(i != 0 || !explicit_command);
            validate(command);
            append(command);
            if (upper(active) == 'M')
                active = active == 'm' ? 'l' : 'L';
            else if (upper(active) == 'Z')
                active = 0;
        }
        return std::move(result);
    }
};
} // namespace
std::size_t RuntimePath::storage_bytes() const noexcept {
    return commands.capacity() * sizeof(RuntimePathCommand);
}
RuntimePath parse_runtime_path(std::string_view input, std::size_t working_bytes,
                               const std::function<void(std::uint64_t)> &charge_work) {
    if (!charge_work)
        fail("INVALID", "Path parsing requires host work accounting");
    return Parser{input, working_bytes, 0, charge_work}.run();
}
} // namespace aether::apk
