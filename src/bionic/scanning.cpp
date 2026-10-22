#include "scanning.hpp"
#include <algorithm>
#include <bitset>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint64_t input_limit = 1024 * 1024;
constexpr std::size_t format_limit = 4096, conversion_limit = 64, numeric_limit = 512;
struct Failure { Fault fault; };
[[noreturn]] void unsupported() { throw Failure{Fault::unsupported_service}; }
bool whitespace(unsigned byte) { return byte == ' ' || (byte >= 9 && byte <= 13); }
unsigned digit(unsigned byte) {
    if (byte >= '0' && byte <= '9') return byte - '0';
    if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
    return 255;
}
unsigned read_byte(a64::GuestMemory &memory, Address address, std::uint64_t offset) {
    std::array<std::uint8_t, 1> byte{};
    if (address >= a64::GuestMemory::address_limit || offset >= a64::GuestMemory::address_limit - address ||
        !memory.read(address + offset, byte)) throw Failure{Fault::read};
    return byte[0];
}
void store(a64::GuestMemory &memory, Address destination, std::uint64_t value, unsigned width) {
    std::array<std::uint8_t, 8> bytes{};
    for (unsigned i = 0; i < width; ++i) bytes[i] = static_cast<std::uint8_t>(value >> (i * 8));
    if (!memory.write(destination, std::span{bytes}.first(width))) throw Failure{Fault::write};
}
struct Arguments {
    a64::GuestMemory &memory;
    a64::ServiceState &state;
    bool full;
    unsigned gp = 2;
    Address stack;
    Address next() {
        if (gp < 8) return state.registers[gp++];
        if (!full) unsupported();
        std::array<std::uint8_t, 8> bytes{};
        if (!memory.read(stack, bytes)) throw Failure{Fault::read};
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i) value |= std::uint64_t{bytes[i]} << (i * 8);
        // A successful eight-byte read is already inside the bounded guest address space.
        stack += 8;
        return value;
    }
};
struct Input {
    a64::GuestMemory &memory;
    Address source;
    std::uint64_t position = 0;
    unsigned peek() {
        if (position >= input_limit) unsupported();
        return read_byte(memory, source, position);
    }
    void skip_space() { while (whitespace(peek())) ++position; }
};
enum class Kind { literal, space, conversion };
struct Instruction {
    Kind kind = Kind::literal;
    unsigned code = 0, bytes = 4;
    std::uint64_t width = 0;
    bool suppress = false;
    std::bitset<256> set;
};
std::vector<Instruction> format(a64::GuestMemory &memory, Address source) {
    std::string text;
    bool terminated = false;
    for (std::size_t i = 0; i < format_limit; ++i) {
        const auto byte = read_byte(memory, source, i);
        if (!byte) { terminated = true; break; }
        text.push_back(static_cast<char>(byte));
    }
    if (!terminated) unsupported();
    std::vector<Instruction> result;
    std::size_t conversions = 0;
    for (std::size_t at = 0; at < text.size();) {
        Instruction item;
        const auto byte = static_cast<unsigned char>(text[at++]);
        if (whitespace(byte)) {
            item.kind = Kind::space;
            while (at < text.size() && whitespace(static_cast<unsigned char>(text[at]))) ++at;
        } else if (byte != '%') item.code = byte;
        else if (at < text.size() && text[at] == '%') { item.code = '%'; ++at; }
        else {
            if (++conversions > conversion_limit) unsupported();
            item.kind = Kind::conversion;
            if (at < text.size() && text[at] == '*') { item.suppress = true; ++at; }
            while (at < text.size() && text[at] >= '0' && text[at] <= '9') {
                const auto number = static_cast<unsigned>(text[at++] - '0');
                if (item.width > (std::numeric_limits<std::uint64_t>::max() - number) / 10) unsupported();
                item.width = item.width * 10 + number;
            }
            bool length = false;
            if (at < text.size() && text[at] == 'h') {
                length = true; ++at; item.bytes = 2;
                if (at < text.size() && text[at] == 'h') { ++at; item.bytes = 1; }
            } else if (at < text.size() && text[at] == 'l') {
                length = true; ++at; item.bytes = 8;
                if (at < text.size() && text[at] == 'l') ++at;
            } else if (at < text.size() && std::string_view("jzt").find(text[at]) != std::string_view::npos) {
                length = true; ++at; item.bytes = 8;
            }
            if (at == text.size()) unsupported();
            item.code = static_cast<unsigned char>(text[at++]);
            if (std::string_view("diuoxXpcsn[").find(static_cast<char>(item.code)) == std::string_view::npos)
                unsupported();
            if (length && (item.code == 'p' || item.code == 'c' || item.code == 's' || item.code == '['))
                unsupported();
            if (item.code == 'p') item.bytes = 8;
            if (item.code == '[') {
                bool negate = false, first = true, closed = false;
                if (at < text.size() && text[at] == '^') { negate = true; ++at; }
                unsigned previous = 0;
                bool previous_valid = false;
                while (at < text.size()) {
                    const auto member = static_cast<unsigned char>(text[at++]);
                    if (member == ']' && !first) { closed = true; break; }
                    first = false;
                    if (member == '-' && previous_valid && at < text.size() && text[at] != ']' &&
                        static_cast<unsigned char>(text[at]) > previous) {
                        const auto last = static_cast<unsigned char>(text[at++]);
                        for (unsigned value = previous; value <= last; ++value) item.set.set(value);
                        previous = last;
                    } else {
                        item.set.set(member); previous = member; previous_valid = true;
                    }
                }
                if (!closed) unsupported();
                if (negate) item.set.flip();
            }
        }
        result.push_back(item);
    }
    return result;
}
struct Number {
    std::uint64_t value = 0;
    bool matched = false, range_error = false;
};
Number integer(Input &input, const Instruction &item) {
    const auto start = input.position;
    const auto width = item.width ? std::min<std::uint64_t>(item.width, numeric_limit) : numeric_limit;
    unsigned base = item.code == 'i' ? 0 : item.code == 'o' ? 8 :
        (item.code == 'x' || item.code == 'X' || item.code == 'p') ? 16 : 10;
    const bool signed_value = item.code == 'd' || item.code == 'i';
    bool negative = false, any = false, prefix = false, first_zero = false;
    std::uint64_t used = 0, magnitude = 0;
    bool overflow = false;
    auto byte = input.peek();
    if (byte == '+' || byte == '-') {
        negative = byte == '-'; ++used; ++input.position;
    }
    const auto digits_start = used;
    const auto maximum = signed_value ? (negative ? (std::uint64_t{1} << 63) :
        (std::uint64_t{1} << 63) - 1) : std::numeric_limits<std::uint64_t>::max();
    while (used < width) {
        byte = input.peek();
        if (!byte) break;
        if (used == digits_start + 1 && first_zero &&
            (((byte == 'x' || byte == 'X') && (item.code == 'i' || base == 16)) ||
             ((byte == 'b' || byte == 'B') && item.code == 'i'))) {
            base = (byte == 'x' || byte == 'X') ? 16 : 2;
            prefix = true; ++used; ++input.position; continue;
        }
        if (!base) base = byte == '0' ? 8 : 10;
        const auto number = digit(byte);
        if (number >= base) break;
        if (!any) first_zero = number == 0;
        any = true; prefix = false;
        if (!item.suppress && !overflow) {
            if (magnitude > maximum / base ||
                (magnitude == maximum / base && number > maximum % base)) overflow = true;
            else magnitude = magnitude * base + number;
        }
        ++used; ++input.position;
    }
    if (!any) { input.position = start; return {}; }
    // Android scanf returns the prefix letter to the input if no digit follows it.
    if (prefix) --input.position;
    if (overflow) magnitude = maximum;
    if (negative && (!overflow || signed_value)) magnitude = 0 - magnitude;
    return {magnitude, true, overflow};
}
} // namespace

a64::Fault scan_text(a64::GuestMemory &memory, a64::ServiceState &state, bool full_frame,
                     a64::Address error_address) {
    try {
        const auto instructions = format(memory, state.registers[1]);
        Input input{memory, state.registers[0]};
        Arguments arguments{memory, state, full_frame, 2, state.stack_pointer};
        std::uint64_t assigned = 0;
        const auto finish = [&](bool input_failure) {
            // Bionic counts assignments here: suppression and %n do not prevent EOF.
            state.registers[0] = input_failure && !assigned ? std::numeric_limits<std::uint64_t>::max() : assigned;
            return Fault::none;
        };
        for (const auto &item : instructions) {
            if (item.kind == Kind::space) { input.skip_space(); continue; }
            if (item.kind == Kind::literal) {
                const auto byte = input.peek();
                if (!byte) return finish(true);
                if (byte != item.code) return finish(false);
                ++input.position; continue;
            }
            if (item.code == 'n') {
                if (!item.suppress) store(memory, arguments.next(), input.position, item.bytes);
                continue;
            }
            if (item.code != 'c' && item.code != '[') input.skip_space();
            if (!input.peek()) return finish(true);
            if (item.code == 'c' || item.code == 's' || item.code == '[') {
                const auto width = item.width ? item.width : item.code == 'c' ? 1 :
                    std::numeric_limits<std::uint64_t>::max();
                std::vector<std::uint8_t> bytes;
                std::uint64_t consumed = 0;
                while (consumed < width) {
                    const auto byte = input.peek();
                    if (!byte || (item.code == 's' && whitespace(byte)) ||
                        (item.code == '[' && !item.set.test(byte))) break;
                    if (!item.suppress) bytes.push_back(static_cast<std::uint8_t>(byte));
                    ++consumed; ++input.position;
                }
                if (!consumed) return finish(false);
                if (!item.suppress) {
                    if (item.code != 'c') bytes.push_back(0);
                    if (!memory.write(arguments.next(), bytes)) throw Failure{Fault::write};
                    ++assigned;
                }
                continue;
            }
            const auto number = integer(input, item);
            if (!number.matched) return finish(false);
            if (!item.suppress) {
                const auto destination = arguments.next();
                if (!memory.accessible(destination, item.bytes, a64::Permission::write)) throw Failure{Fault::write};
                if (number.range_error) store(memory, error_address, 34, 4);
                store(memory, destination, number.value, item.bytes);
                ++assigned;
            }
        }
        return finish(false);
    } catch (const Failure &failure) {
        return failure.fault;
    }
}
} // namespace aether::bionic
